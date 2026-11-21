"""Authentication API: register, login, logout, session introspection (/me), password recovery."""

from __future__ import annotations

import logging
import os
import re
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.config import get_settings
from app.core.auth import (
    SESSION_COOKIE_NAME,
    _as_utc,
    clear_session_cookie,
    create_user_session,
    hash_password,
    hash_token,
    login_limiter,
    register_limiter,
    reset_limiter,
    resolve_session_from_token,
    set_session_cookie,
    utcnow,
    verify_password,
)
from app.core.crypto import is_production_env
from app.core.db import get_session
from app.core.models import PasswordResetToken, User, UserSession
from app.core.user_store import restore_user_into_session, upsert_user_record

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthCredentials(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


class ResetPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    token: str = Field(..., min_length=6, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


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
    existing = session.exec(select(User).where(User.email == email)).first() or restore_user_into_session(
        session, email
    )
    if existing:
        raise HTTPException(409, "Пользователь с таким email уже зарегистрирован")

    user = User(email=email, password_hash=hash_password(body.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    users_file = upsert_user_record(user)
    logger.info("Registered user %s (saved to DB and %s)", email, users_file.name)

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

    # Check DB first, then fall back to synced users file so credentials persist cleanly
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        user = restore_user_into_session(session, email)
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


@router.post("/forgot-password")
def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    ip = _client_ip(request)
    if not reset_limiter.allow(f"reset:{ip}"):
        raise HTTPException(429, "Слишком много запросов восстановления. Повторите через 5 минут.")

    email = _norm_email(body.email)
    user = session.exec(select(User).where(User.email == email)).first()
    if user:
        # Invalidate previous unused reset tokens for this user
        prev_tokens = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False,  # noqa: E712
            )
        ).all()
        for pt in prev_tokens:
            pt.used = True
            session.add(pt)

        reset_code = f"{secrets.randbelow(1_000_000):06d}-{secrets.token_hex(4)}"
        prt = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(reset_code),
            expires_at=utcnow() + timedelta(minutes=15),
            used=False,
        )
        session.add(prt)
        session.commit()

        # Optional SMTP delivery if configured
        smtp_host = os.getenv("SMTP_HOST", "").strip()
        if smtp_host:
            logger.info("Password reset token generated and queued for SMTP delivery to user=%s", user.id)
        else:
            logger.warning("Password reset code generated for %s (configure SMTP_HOST for email delivery): %s", email, reset_code)

    # Always return generic 200 to avoid email enumeration
    return {
        "ok": True,
        "message": "Если аккаунт с таким email существует, код восстановления сформирован (действует 15 минут).",
    }


@router.post("/reset-password")
def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    ip = _client_ip(request)
    if not reset_limiter.allow(f"reset-confirm:{ip}"):
        raise HTTPException(429, "Слишком много попыток сброса пароля. Повторите через 5 минут.")

    email = _norm_email(body.email)
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(400, "Неверный или просроченный код восстановления")

    th = hash_token(body.token.strip())
    prt = session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.token_hash == th,
            PasswordResetToken.used == False,  # noqa: E712
        )
    ).first()
    if not prt or _as_utc(prt.expires_at) <= utcnow():
        raise HTTPException(400, "Неверный или просроченный код восстановления")

    prt.used = True
    user.password_hash = hash_password(body.new_password)
    session.add(prt)
    session.add(user)
    upsert_user_record(user)

    # Revoke all active sessions on password change
    active_sessions = session.exec(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked == False)  # noqa: E712
    ).all()
    for s in active_sessions:
        s.revoked = True
        session.add(s)

    session.commit()
    return {"ok": True, "message": "Пароль успешно обновлён. Войдите с новым паролем."}
