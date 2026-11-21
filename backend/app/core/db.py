"""Database engine, PostgreSQL/SQLite support, tracked schema migrations, and session helpers."""

from __future__ import annotations

import logging
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings

logger = logging.getLogger(__name__)

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


def is_postgres_url(raw_url: str | None = None) -> bool:
    url = _normalized_db_url(raw_url if raw_url is not None else get_settings().database_url).lower()
    return url.startswith("postgresql")


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        db_url = _normalized_db_url(settings.database_url)
        if db_url.startswith("sqlite"):
            _engine = create_engine(
                db_url,
                echo=settings.debug,
                connect_args={"check_same_thread": False},
            )
        else:
            _engine = create_engine(
                db_url,
                echo=settings.debug,
                pool_pre_ping=True,
                pool_recycle=300,
                pool_size=5,
                max_overflow=10,
            )
    return _engine


def check_db_connection() -> tuple[bool, str]:
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:
        logger.error("Database connectivity check failed: %s", exc)
        return False, str(exc)


def _ensure_schema_migrations_table(conn) -> None:
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
    )


def _ensure_columns(engine) -> None:
    """Safely add missing nullable columns & track idempotent schema migrations."""
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())

    with engine.begin() as conn:
        _ensure_schema_migrations_table(conn)
        applied = {
            int(r[0])
            for r in conn.execute(text("SELECT version FROM schema_migrations")).fetchall()
        }

        if 1 not in applied:
            column_migrations = [
                ("workflows", "owner_id", "TEXT"),
                ("runs", "owner_id", "TEXT"),
                ("credentials", "owner_id", "TEXT"),
            ]
            for table, col, col_type in column_migrations:
                if table not in existing_tables:
                    continue
                existing = {c["name"] for c in insp.get_columns(table)}
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
            conn.execute(
                text(
                    "INSERT INTO schema_migrations (version, name, applied_at) "
                    "VALUES (:v, :n, :t)"
                ),
                {
                    "v": 1,
                    "n": "ensure_owner_id_columns",
                    "t": datetime.now(timezone.utc).isoformat(),
                },
            )

        if 2 not in applied:
            index_ddls = [
                ("users", "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_unique ON users (email)"),
                ("workflows", "CREATE INDEX IF NOT EXISTS ix_workflows_owner_id_idx ON workflows (owner_id)"),
                ("runs", "CREATE INDEX IF NOT EXISTS ix_runs_owner_id_idx ON runs (owner_id)"),
                ("custom_nodes", "CREATE INDEX IF NOT EXISTS ix_custom_nodes_owner_id_idx ON custom_nodes (owner_id)"),
            ]
            for table, ddl in index_ddls:
                if table in existing_tables:
                    conn.execute(text(ddl))
            conn.execute(
                text(
                    "INSERT INTO schema_migrations (version, name, applied_at) "
                    "VALUES (:v, :n, :t)"
                ),
                {
                    "v": 2,
                    "n": "ensure_core_indexes",
                    "t": datetime.now(timezone.utc).isoformat(),
                },
            )


def init_db() -> None:
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    _ensure_columns(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
