"""Database engine, cross-dialect lightweight column migration, and session helpers."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings

_engine = None
_BACKEND_DIR = Path(__file__).resolve().parents[2]


def _normalized_db_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if url == "sqlite:///./ai_security_workflow.db":
        return f"sqlite:///{(_BACKEND_DIR / 'ai_security_workflow.db').as_posix()}"
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    if url.startswith("postgresql://") and "+" not in url.split("://", 1)[0]:
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        db_url = _normalized_db_url(settings.database_url)
        connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
        _engine = create_engine(db_url, echo=settings.debug, connect_args=connect_args)
    return _engine


def _ensure_columns(engine) -> None:
    """Safely add new nullable columns to existing SQLite/PostgreSQL databases without losing data."""
    migrations = [
        ("workflows", "owner_id", "TEXT"),
        ("runs", "owner_id", "TEXT"),
        ("credentials", "owner_id", "TEXT"),
    ]
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, col, col_type in migrations:
            if table not in existing_tables:
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            if col not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))


def init_db() -> None:
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    _ensure_columns(engine)
    from app.core.user_store import sync_users_with_db

    with Session(engine) as session:
        sync_users_with_db(session)


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
