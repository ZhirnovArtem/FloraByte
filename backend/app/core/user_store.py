"""File-backed user credential store synced with the SQL User table (email + PBKDF2 password hash)."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.core.models import User

logger = logging.getLogger("app.auth")
_LOCK = threading.Lock()


def get_users_file_path() -> Path:
    env_path = os.environ.get("AUTH_USERS_FILE", "").strip()
    if env_path:
        path = Path(env_path)
    else:
        settings = get_settings()
        db_url = os.environ.get("DATABASE_URL", "").strip() or settings.database_url
        if db_url.startswith("sqlite:///") and db_url != "sqlite:///./ai_security_workflow.db":
            raw_db = db_url[len("sqlite:///") :]
            if raw_db and raw_db != ":memory:":
                db_p = Path(raw_db)
                path = db_p.parent / f"{db_p.stem}_users.json"
            else:
                path = Path(settings.auth_users_file)
        else:
            path = Path(settings.auth_users_file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "florabyte_data" / "users.json"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def _read_store(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Could not parse auth users file %s; starting empty map", path)
        return {}
    if isinstance(raw, dict) and isinstance(raw.get("users"), dict):
        return {str(k).strip().lower(): v for k, v in raw["users"].items() if isinstance(v, dict)}
    if isinstance(raw, list):
        out: dict[str, dict] = {}
        for item in raw:
            if isinstance(item, dict) and item.get("email"):
                out[str(item["email"]).strip().lower()] = item
        return out
    return {}


def _write_store(path: Path, users_map: dict[str, dict]) -> None:
    payload = json.dumps({"users": users_map}, ensure_ascii=False, indent=2)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(payload, encoding="utf-8")
    try:
        tmp_path.chmod(0o600)
    except OSError:
        pass
    tmp_path.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def upsert_user_record(user: User) -> Path:
    email = user.email.strip().lower()
    record = {
        "id": user.id,
        "email": email,
        "password_hash": user.password_hash,
        "is_active": bool(user.is_active),
        "created_at": user.created_at.isoformat() if user.created_at else datetime.now(timezone.utc).isoformat(),
    }
    with _LOCK:
        path = get_users_file_path()
        users_map = _read_store(path)
        users_map[email] = record
        _write_store(path, users_map)
        return path


def find_user_record(email: str) -> dict | None:
    norm = email.strip().lower()
    with _LOCK:
        path = get_users_file_path()
        users_map = _read_store(path)
        rec = users_map.get(norm)
        return dict(rec) if isinstance(rec, dict) else None


def restore_user_into_session(session: Session, email: str) -> User | None:
    rec = find_user_record(email)
    if not rec or not rec.get("password_hash"):
        return None
    norm = str(rec.get("email", email)).strip().lower()
    existing = session.exec(select(User).where(User.email == norm)).first()
    if existing:
        return existing
    user = User(
        id=str(rec.get("id") or "") or None,
        email=norm,
        password_hash=str(rec["password_hash"]),
        is_active=bool(rec.get("is_active", True)),
    )
    if user.id is None:
        user = User(
            email=norm,
            password_hash=str(rec["password_hash"]),
            is_active=bool(rec.get("is_active", True)),
        )
    session.add(user)
    session.commit()
    session.refresh(user)
    logger.info("Restored user %s from users file into database", norm)
    return user


def sync_users_with_db(session: Session) -> None:
    with _LOCK:
        path = get_users_file_path()
        file_map = _read_store(path)
        db_users = session.exec(select(User)).all()
        db_by_email = {u.email.strip().lower(): u for u in db_users}

        changed_file = False
        for email, u in db_by_email.items():
            rec = file_map.get(email)
            if not rec or rec.get("password_hash") != u.password_hash:
                file_map[email] = {
                    "id": u.id,
                    "email": email,
                    "password_hash": u.password_hash,
                    "is_active": bool(u.is_active),
                    "created_at": u.created_at.isoformat() if u.created_at else datetime.now(timezone.utc).isoformat(),
                }
                changed_file = True

        restored = 0
        for email, rec in file_map.items():
            if email not in db_by_email and rec.get("password_hash"):
                u_kwargs = {
                    "email": email,
                    "password_hash": str(rec["password_hash"]),
                    "is_active": bool(rec.get("is_active", True)),
                }
                if rec.get("id"):
                    u_kwargs["id"] = str(rec["id"])
                session.add(User(**u_kwargs))
                restored += 1
        if restored:
            session.commit()
            logger.info("Synchronized %d user(s) from %s into database", restored, path)
        if changed_file:
            _write_store(path, file_map)
