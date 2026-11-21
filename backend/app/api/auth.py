"""Authentication API: register, login, logout, session introspection (/me)."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.config import get_settings
from app.core.accounts_db import restore_user_from_sql_db, sql_upsert_account
from app.core.auth import (
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_user_session,
    hash_password,
    hash_token,
    login_limiter,
    register_limiter,
    resolve_session_from_token,
    set_session_cookie,
    verify_password,
)
from app.core.crypto import is_production_env
from app.core.db import get_session
from app.core.models import User, UserSession
from app.core.user_store import restore_user_into_session, upsert_user_record

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthCredentials(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


def _norm_email(email: str) -> str:
    norm = email.strip().lower()
    if not _EMAIL_RE.match(norm):
        raise HTTPException(400, "Укажите корректный email")
    return norm


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.post("/register")
def register(
    body: AuthCredentials,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    ip = _client_ip(request)
    if not register_limiter.allow(f"reg:{ip}"):
        raise HTTPException(429, "Слишком много попыток регистрации. Повторите позже.")

    email = _norm_email(body.email)
    existing = (
        session.exec(select(User).where(User.email == email)).first()
        or restore_user_from_sql_db(session, email)
        or restore_user_into_session(session, email)
    )
    if existing:
        raise HTTPException(409, "Пользователь с таким email уже зарегистрирован")

    user = User(email=email, password_hash=hash_password(body.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    sql_db_path = sql_upsert_account(user)
    users_file = upsert_user_record(user)
    logger.info("Registered user %s (saved to SQL %s, app DB, and %s)", email, sql_db_path.name, users_file.name)

    raw_token, sess_row = create_user_session(session, user)
    set_session_cookie(response, request, raw_token)
    return {
        "authenticated": True,
        "user": _user_dict(user),
        "csrf_token": sess_row.csrf_token,
    }


@router.post("/login")
def login(
    body: AuthCredentials,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    email = _norm_email(body.email)
    ip = _client_ip(request)
    rate_key = f"login:{ip}:{email}"

    # Check dedicated SQL accounts database (`database.db`) and main DB / users file
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        user = restore_user_from_sql_db(session, email) or restore_user_into_session(session, email)
    if not user:
        logger.warning("Login failed for %s: user not found in DB or users file", email)
        if not login_limiter.allow(rate_key):
            raise HTTPException(
                429,
                "Превышено число неудачных попыток входа. Повторите через 5 минут или восстановите пароль.",
            )
        raise HTTPException(401, "Неверный email или пароль")
    if not verify_password(body.password, user.password_hash):
        logger.warning("Login failed for %s: password hash mismatch", email)
        if not login_limiter.allow(rate_key):
            raise HTTPException(
                429,
                "Превышено число неудачных попыток входа. Повторите через 5 минут или восстановите пароль.",
            )
        raise HTTPException(401, "Неверный email или пароль")

    # Even if user knows password, block if currently locked out
    if login_limiter.is_limited(rate_key):
        raise HTTPException(
            429,
            "Аккаунт временно заблокирован из-за частых неудачных попыток входа. Попробуйте через 5 минут.",
        )
    login_limiter.clear(rate_key)

    if not user.is_active:
        raise HTTPException(403, "Учётная запись отключена")

    raw_token, sess_row = create_user_session(session, user)
    set_session_cookie(response, request, raw_token)
    return {
        "authenticated": True,
        "user": _user_dict(user),
        "csrf_token": sess_row.csrf_token,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
    if raw_cookie:
        th = hash_token(raw_cookie)
        sess_row = session.exec(select(UserSession).where(UserSession.token_hash == th)).first()
        if sess_row:
            sess_row.revoked = True
            session.add(sess_row)
            session.commit()
    clear_session_cookie(response, request)
    return {"ok": True, "authenticated": False}


@router.get("/me")
def me(request: Request, session: Session = Depends(get_session)):
    db_url = get_settings().database_url.lower()
    persistent_storage = not (is_production_env() and "sqlite" in db_url)
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
    resolved = resolve_session_from_token(session, raw_cookie)
    if not resolved:
        return {
            "authenticated": False,
            "user": None,
            "csrf_token": "",
            "persistent_storage": persistent_storage,
        }
    sess_row, user = resolved
    return {
        "authenticated": True,
        "user": _user_dict(user),
        "csrf_token": sess_row.csrf_token,
        "persistent_storage": persistent_storage,
    }
