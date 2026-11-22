"""Tests for 4-stage PostgreSQL single-source-of-truth migration, health checks, and backup/restore."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import text

import app.core.db as db_mod
from app.config import get_settings
from app.core.auth import hash_password, login_limiter, register_limiter
from app.main import app

_TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from backup_db import dump_database, restore_database  # noqa: E402
from migrate_accounts_to_postgres import migrate_sources  # noqa: E402


def test_postgres_url_normalization_and_health_flags(tmp_path, monkeypatch):
    assert db_mod._normalized_db_url("postgres://user:pass@db.internal:5432/florabyte") == (
        "postgresql+psycopg://user:pass@db.internal:5432/florabyte"
    )
    assert db_mod._normalized_db_url("postgresql://user:pass@db.internal:5432/florabyte") == (
        "postgresql+psycopg://user:pass@db.internal:5432/florabyte"
    )
    assert db_mod.is_postgres_url("postgres://u:p@h:5432/db") is True
    assert db_mod.is_postgres_url("sqlite:///./ai_security_workflow.db") is False

    db_file = tmp_path / "health.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.delenv("RENDER", raising=False)
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["storage_backend"] == "sqlite"
        assert body["database_connected"] is True
        assert body["persistent_storage"] is True

        # In production (RENDER=true) with SQLite, persistent_storage warns False
        monkeypatch.setenv("RENDER", "true")
        r_render = client.get("/health")
        assert r_render.json()["persistent_storage"] is False

    db_mod._engine = None
    get_settings.cache_clear()


def test_schema_migrations_recorded_idempotently(tmp_path, monkeypatch):
    db_file = tmp_path / "schema_mig.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    get_settings.cache_clear()
    db_mod._engine = None

    db_mod.init_db()
    db_mod.init_db()  # second run must be idempotent

    with db_mod.get_engine().connect() as conn:
        rows = conn.execute(text("SELECT version, name FROM schema_migrations ORDER BY version")).fetchall()
        assert rows == [
            (1, "ensure_owner_id_columns"),
            (2, "ensure_core_indexes"),
            (3, "ensure_template_visibility_columns"),
        ]

    db_mod._engine = None
    get_settings.cache_clear()


def test_migrate_legacy_sqlite_and_json_preserving_ids_and_hashes(tmp_path, monkeypatch):
    # Legacy SQLite DB (users + workflows)
    legacy_db = tmp_path / "legacy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{legacy_db}")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    db_mod._engine = None
    login_limiter._hits.clear()
    register_limiter._hits.clear()

    with TestClient(app) as legacy_client:
        reg = legacy_client.post(
            "/api/auth/register",
            json={"email": "legacy.user@example.com", "password": "LegacyPassword123!"},
        )
        assert reg.status_code == 200
        legacy_user_id = reg.json()["user"]["id"]
        csrf = reg.json()["csrf_token"]
        wf = legacy_client.post(
            "/api/workflows",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "Migrated Flow",
                "graph_json": {"nodes": [{"id": "t1", "type": "trigger.manual", "params": {}}], "edges": []},
            },
        )
        assert wf.status_code == 200
        legacy_wf_id = wf.json()["id"]

    # Legacy accounts SQLite (`database.db` style) + legacy `users.json`
    accounts_db = tmp_path / "database.db"
    with sqlite3.connect(str(accounts_db)) as conn:
        conn.execute(
            "CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, is_active INTEGER, created_at TEXT)"
        )
        conn.execute(
            "INSERT INTO accounts VALUES (?, ?, ?, ?, ?)",
            ("acc-uuid-2", "sql.legacy@example.com", hash_password("SqlLegacyPass1!"), 1, "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()

    users_json = tmp_path / "users.json"
    users_json.write_text(
        json.dumps(
            {
                "users": {
                    "json.legacy@example.com": {
                        "id": "json-uuid-3",
                        "email": "json.legacy@example.com",
                        "password_hash": hash_password("JsonLegacyPass1!"),
                        "is_active": True,
                        "created_at": "2026-01-02T00:00:00+00:00",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    # Run migration tool into a fresh target DB
    target_db = tmp_path / "target_pg_sim.db"
    target_url = f"sqlite:///{target_db}"
    stats = migrate_sources(
        target_url=target_url,
        sources=[legacy_db, accounts_db, users_json],
        dry_run=False,
    )
    assert stats["accounts_discovered"] == 3
    assert stats["accounts_inserted"] == 3
    assert stats["workflows_inserted"] >= 1

    # Re-running migration is idempotent (0 new inserts)
    stats_again = migrate_sources(
        target_url=target_url,
        sources=[legacy_db, accounts_db, users_json],
        dry_run=False,
    )
    assert stats_again["accounts_inserted"] == 0
    assert stats_again["accounts_skipped"] == 3

    # Point app to target DB -> all migrated accounts can log in and see preserved IDs & workflows
    monkeypatch.setenv("DATABASE_URL", target_url)
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client:
        for email, pw in (
            ("legacy.user@example.com", "LegacyPassword123!"),
            ("sql.legacy@example.com", "SqlLegacyPass1!"),
            ("json.legacy@example.com", "JsonLegacyPass1!"),
        ):
            r = client.post("/api/auth/login", json={"email": email, "password": pw})
            assert r.status_code == 200, r.text
            if email == "legacy.user@example.com":
                assert r.json()["user"]["id"] == legacy_user_id
                wfs = client.get("/api/workflows").json()["workflows"]
                assert any(w["id"] == legacy_wf_id and w["name"] == "Migrated Flow" for w in wfs)
            client.post("/api/auth/logout")

    db_mod._engine = None
    get_settings.cache_clear()


def test_backup_dump_and_restore_roundtrip(tmp_path, monkeypatch):
    src_db = tmp_path / "src.db"
    dst_db = tmp_path / "dst.db"
    backup_file = tmp_path / "backup.json"

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{src_db}")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    db_mod._engine = None
    login_limiter._hits.clear()
    register_limiter._hits.clear()

    with TestClient(app) as client:
        reg = client.post(
            "/api/auth/register",
            json={"email": "backup@example.com", "password": "BackupPassword1!"},
        )
        assert reg.status_code == 200
        uid = reg.json()["user"]["id"]
        csrf = reg.json()["csrf_token"]
        wf = client.post(
            "/api/workflows",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "Backed Up Workflow",
                "graph_json": {"nodes": [{"id": "t1", "type": "trigger.manual", "params": {}}], "edges": []},
            },
        )
        assert wf.status_code == 200

    dumped = dump_database(f"sqlite:///{src_db}", backup_file)
    assert dumped["users"] == 1
    assert dumped["workflows"] >= 1
    assert backup_file.exists()

    restored = restore_database(f"sqlite:///{dst_db}", backup_file)
    assert restored["users"] == 1
    assert restored["workflows"] >= 1

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{dst_db}")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client_dst:
        login = client_dst.post(
            "/api/auth/login",
            json={"email": "backup@example.com", "password": "BackupPassword1!"},
        )
        assert login.status_code == 200
        assert login.json()["user"]["id"] == uid
        wfs = client_dst.get("/api/workflows").json()["workflows"]
        assert any(w["name"] == "Backed Up Workflow" for w in wfs)

    db_mod._engine = None
    get_settings.cache_clear()
