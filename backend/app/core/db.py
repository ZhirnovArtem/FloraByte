"""Database engine, lightweight column migration, and session helpers."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
        _engine = create_engine(settings.database_url, echo=settings.debug, connect_args=connect_args)
    return _engine


def _ensure_sqlite_columns(engine) -> None:
    """Safely add new nullable columns to existing SQLite databases without losing data."""
    if not str(engine.url).startswith("sqlite"):
        return
    migrations = [
        ("workflows", "owner_id", "TEXT"),
        ("runs", "owner_id", "TEXT"),
        ("credentials", "owner_id", "TEXT"),
    ]
    with engine.begin() as conn:
        for table, col, col_type in migrations:
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            existing = {r[1] for r in rows}
            if existing and col not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))


def init_db() -> None:
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    _ensure_sqlite_columns(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
