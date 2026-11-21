"""Dedicated SQLite accounts database (`database.db`) managed with explicit SQL queries."""

from __future__ import annotations

import logging
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.core.models import User

logger = logging.getLogger("app.auth.sql")
_SQL_LOCK = threading.Lock()

_CREATE_ACCOUNTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_CREATE_ACCOUNTS_EMAIL_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts (email);
"""

_SELECT_ACCOUNT_BY_EMAIL_SQL = """
SELECT id, email, password_hash, is_active, created_at, updated_at
FROM accounts
WHERE email = ?
LIMIT 1;
"""

_SELECT_ALL_ACCOUNTS_SQL = """
SELECT id, email, password_hash, is_active, created_at, updated_at
FROM accounts;
"""

_UPSERT_ACCOUNT_SQL = """
INSERT INTO accounts (id, email, password_hash, is_active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(email) DO UPDATE SET
    id = excluded.id,
    password_hash = excluded.password_hash,
    is_active = excluded.is_active,
    updated_at = excluded.updated_at;
"""

_UPDATE_ACCOUNT_PASSWORD_SQL = """
UPDATE accounts
SET password_hash = ?, updated_at = ?
WHERE email = ?;
"""


def get_accounts_db_path() -> Path:
    env_path = os.environ.get("AUTH_SQL_DB_PATH", "").strip()
    if env_path:
        path = Path(env_path)
    else:
        settings = get_settings()
        db_url = os.environ.get("DATABASE_URL", "").strip() or settings.database_url
        if db_url.startswith("sqlite:///") and db_url != "sqlite:///./ai_security_workflow.db":
            raw_db = db_url[len("sqlite:///") :]
            if raw_db and raw_db != ":memory:":
                db_p = Path(raw_db)
                path = db_p.parent / f"{db_p.stem}_database.db"
            else:
                path = Path(settings.auth_sql_db_path)
        else:
            path = Path(settings.auth_sql_db_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "florabyte_data" / "database.db"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def _connect() -> sqlite3.Connection:
    path = get_accounts_db_path()
    conn = sqlite3.connect(str(path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_accounts_sql_db() -> Path:
    with _SQL_LOCK:
        path = get_accounts_db_path()
        with _connect() as conn:
            conn.execute(_CREATE_ACCOUNTS_TABLE_SQL)
            conn.execute(_CREATE_ACCOUNTS_EMAIL_INDEX_SQL)
            conn.commit()
        return path


def sql_get_account_by_email(email: str) -> dict | None:
    norm = email.strip().lower()
    with _SQL_LOCK:
        with _connect() as conn:
            conn.execute(_CREATE_ACCOUNTS_TABLE_SQL)
            row = conn.execute(_SELECT_ACCOUNT_BY_EMAIL_SQL, (norm,)).fetchone()
            return dict(row) if row is not None else None


def sql_upsert_account(user: User) -> Path:
    norm = user.email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    created_iso = user.created_at.isoformat() if user.created_at else now_iso
    with _SQL_LOCK:
        path = get_accounts_db_path()
        with _connect() as conn:
            conn.execute(_CREATE_ACCOUNTS_TABLE_SQL)
            conn.execute(_CREATE_ACCOUNTS_EMAIL_INDEX_SQL)
            conn.execute(
                _UPSERT_ACCOUNT_SQL,
                (user.id, norm, user.password_hash, 1 if user.is_active else 0, created_iso, now_iso),
            )
            conn.commit()
        return path


def sql_update_password_hash(email: str, password_hash: str) -> None:
    norm = email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _SQL_LOCK:
        with _connect() as conn:
            conn.execute(_CREATE_ACCOUNTS_TABLE_SQL)
            conn.execute(_UPDATE_ACCOUNT_PASSWORD_SQL, (password_hash, now_iso, norm))
            conn.commit()


def restore_user_from_sql_db(session: Session, email: str) -> User | None:
    rec = sql_get_account_by_email(email)
    if not rec or not rec.get("password_hash"):
        return None
    norm = str(rec["email"]).strip().lower()
    existing = session.exec(select(User).where(User.email == norm)).first()
    if existing:
        if existing.password_hash != rec["password_hash"]:
            existing.password_hash = str(rec["password_hash"])
            session.add(existing)
            session.commit()
            session.refresh(existing)
        return existing

    user = User(
        id=str(rec["id"]),
        email=norm,
        password_hash=str(rec["password_hash"]),
        is_active=bool(rec["is_active"]),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    logger.info("Restored account %s from database.db (SQL) into app session DB", norm)
    return user


def sync_accounts_sql_with_db(session: Session) -> None:
    init_accounts_sql_db()
    with _SQL_LOCK:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(_SELECT_ALL_ACCOUNTS_SQL).fetchall()]
    sql_by_email = {str(r["email"]).strip().lower(): r for r in rows}

    db_users = session.exec(select(User)).all()
    db_by_email = {u.email.strip().lower(): u for u in db_users}

    for email, u in db_by_email.items():
        rec = sql_by_email.get(email)
        if not rec or rec.get("password_hash") != u.password_hash:
            sql_upsert_account(u)

    restored = 0
    for email, rec in sql_by_email.items():
        if email not in db_by_email and rec.get("password_hash"):
            session.add(
                User(
                    id=str(rec["id"]),
                    email=email,
                    password_hash=str(rec["password_hash"]),
                    is_active=bool(rec["is_active"]),
                )
            )
            restored += 1
    if restored:
        session.commit()
        logger.info("Synchronized %d account(s) from database.db into app DB", restored)
