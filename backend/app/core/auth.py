"""Authentication helpers: PBKDF2 password hashing, HttpOnly cookie sessions, CSRF, ownership checks."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, Response
from sqlmodel import Session, select

from app.config import get_settings
from app.core.db import get_session
from app.core.models import User, UserSession
from app.core.rate_limit import SlidingWindowLimiter

SESSION_COOKIE_NAME = "florabyte_session"
_PBKDF2_ITERS = 310_000

# Brute-force protection: max 5 failed logins per 5 minutes per IP / email
login_limiter = SlidingWindowLimiter(max_requests=5, window_seconds=300)
register_limiter = SlidingWindowLimiter(max_requests=10, window_seconds=300)
reset_limiter = SlidingWindowLimiter(max_requests=5, window_seconds=300)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERS).hex()
    return f"pbkdf2_sha256${_PBKDF2_ITERS}${salt}${dk}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        alg, iters_s, salt_hex, expected_hex = encoded.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters_s)
        ).hex()
        return hmac.compare_digest(dk, expected_hex)
    except Exception:
        return False


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_https_request(request: Request) -> bool:
    mode = (get_settings().cookie_secure or "auto").strip().lower()
    if mode == "true":
        return True
    if mode == "false":
        return False
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").split(",")[0].strip().lower()
    return proto == "https"


def create_user_session(session: Session, user: User) -> tuple[str, UserSession]:
    settings = get_settings()
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    ttl = timedelta(days=max(1, int(settings.session_ttl_days)))
    row = UserSession(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        csrf_token=csrf_token,
        expires_at=utcnow() + ttl,
        revoked=False,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return raw_token, row


def set_session_cookie(response: Response, request: Request, raw_token: str) -> None:
    settings = get_settings()
    secure = is_https_request(request)
    # Cross-origin Render (frontend.onrender.com -> backend.onrender.com) requires SameSite=None + Secure over HTTPS.
    samesite = "none" if secure else "lax"
    max_age = max(1, int(settings.session_ttl_days)) * 86400
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=max_age,
        path="/",
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    secure = is_https_request(request)
    samesite = "none" if secure else "lax"
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=secure,
        samesite=samesite,
        httponly=True,
    )


def resolve_session_from_token(session: Session, raw_token: str) -> tuple[UserSession, User] | None:
    if not raw_token:
        return None
    th = hash_token(raw_token)
    sess_row = session.exec(
        select(UserSession).where(UserSession.token_hash == th, UserSession.revoked == False)  # noqa: E712
    ).first()
    if not sess_row:
        return None
    if _as_utc(sess_row.expires_at) <= utcnow():
        return None
    user = session.get(User, sess_row.user_id)
    if not user or not user.is_active:
        return None
    return sess_row, user


def get_optional_user(
    request: Request,
    session: Session = Depends(get_session),
) -> Optional[User]:
    user = getattr(request.state, "user", None)
    if isinstance(user, User):
        return user
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
    resolved = resolve_session_from_token(session, raw_cookie)
    if resolved:
        sess_row, user_obj = resolved
        request.state.user = user_obj
        request.state.user_session = sess_row
        return user_obj
    return None


def get_current_user(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
) -> Optional[User]:
    """Return authenticated User; returns None ONLY if server-to-server token or AUTH_REQUIRED=0 is active."""
    if user is not None:
        return user
    if getattr(request.state, "service_auth", False) or not get_settings().auth_required:
        return None
    raise HTTPException(401, "Требуется авторизация")


def check_owner(owner_id: str | None, user: Optional[User]) -> None:
    """Enforce per-user ownership on workflows, runs, and credentials."""
    if user is None:
        return
    if owner_id is not None and owner_id != user.id:
        raise HTTPException(403, "Нет доступа к ресурсу другого пользователя")
