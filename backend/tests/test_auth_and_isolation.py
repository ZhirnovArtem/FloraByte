"""Auth modernization tests: registration, HttpOnly cookies, CSRF/Origin, rate limiting, reset, and owner isolation."""

from __future__ import annotations

import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, select

import app.core.db as db_mod
from app.config import get_settings
from app.core.auth import (
    SESSION_COOKIE_NAME,
    hash_token,
    login_limiter,
    register_limiter,
    reset_limiter,
    utcnow,
)
from app.core.models import PasswordResetToken, User
from app.main import app


@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    db_file = tmp_path / "auth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    monkeypatch.setenv("COOKIE_SECURE", "auto")
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    login_limiter._hits.clear()
    register_limiter._hits.clear()
    reset_limiter._hits.clear()
    db_mod._engine = None
    SQLModel.metadata.drop_all(db_mod.get_engine())
    db_mod.init_db()
    with TestClient(app) as client:
        yield client
    db_mod._engine = None
    get_settings.cache_clear()


def test_unauthenticated_api_blocked_and_me_unauthenticated(auth_client: TestClient):
    for ep in ("/api/workflows", "/api/runs", "/api/integrations", "/api/credentials", "/api/templates"):
        assert auth_client.get(ep).status_code == 401
    me = auth_client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["authenticated"] is False


def test_register_httponly_cookie_persistence_and_logout(auth_client: TestClient):
    r = auth_client.post(
        "/api/auth/register",
        json={"email": "Alice@Example.com", "password": "StrongPassword123!"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authenticated"] is True
    assert body["user"]["email"] == "alice@example.com"
    csrf = body["csrf_token"]
    assert csrf

    # Set-Cookie must carry HttpOnly and not be stored in JSON
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert f"{SESSION_COOKIE_NAME}=" in set_cookie
    assert "httponly" in set_cookie

    # Duplicate email rejected
    dup = auth_client.post(
        "/api/auth/register",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    )
    assert dup.status_code == 409

    # Password is hashed in DB
    with Session(db_mod.get_engine()) as session:
        user = session.exec(select(User).where(User.email == "alice@example.com")).first()
        assert user is not None
        assert user.password_hash.startswith("pbkdf2_sha256$")
        assert "StrongPassword123!" not in user.password_hash

    # Simulate browser reload with persisted cookie
    saved_cookie = auth_client.cookies.get(SESSION_COOKIE_NAME)
    assert saved_cookie
    with TestClient(app) as reloaded:
        reloaded.cookies.set(SESSION_COOKIE_NAME, saved_cookie)
        me = reloaded.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["authenticated"] is True
        assert me.json()["user"]["email"] == "alice@example.com"
        assert me.json()["csrf_token"] == csrf
        assert reloaded.get("/api/workflows").status_code == 200

    # Logout revokes session server-side
    out = auth_client.post("/api/auth/logout")
    assert out.status_code == 200
    assert out.json()["authenticated"] is False
    assert auth_client.get("/api/auth/me").json()["authenticated"] is False
    assert auth_client.get("/api/workflows").status_code == 401

    # Replaying old cookie after logout fails
    with TestClient(app) as replay:
        replay.cookies.set(SESSION_COOKIE_NAME, saved_cookie)
        assert replay.get("/api/workflows").status_code == 401


def test_https_cookie_flags_samesite_none_secure(auth_client: TestClient):
    r = auth_client.post(
        "/api/auth/register",
        headers={"X-Forwarded-Proto": "https"},
        json={"email": "httpsuser@example.com", "password": "StrongPassword123!"},
    )
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=none" in set_cookie


def test_csrf_and_origin_enforcement(auth_client: TestClient):
    r = auth_client.post(
        "/api/auth/register",
        json={"email": "csrf@example.com", "password": "StrongPassword123!"},
    )
    csrf = r.json()["csrf_token"]
    wf_payload = {
        "name": "csrf-wf",
        "graph_json": {"nodes": [{"id": "t1", "type": "trigger.manual", "params": {}}], "edges": []},
    }

    # Missing X-CSRF-Token -> 403
    assert auth_client.post("/api/workflows", json=wf_payload).status_code == 403
    # Wrong X-CSRF-Token -> 403
    assert auth_client.post("/api/workflows", json=wf_payload, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    # Untrusted Origin -> 403
    assert (
        auth_client.post(
            "/api/workflows",
            json=wf_payload,
            headers={"X-CSRF-Token": csrf, "Origin": "https://evil.attacker.example"},
        ).status_code
        == 403
    )
    # Valid CSRF + allowed Origin -> 200
    ok = auth_client.post(
        "/api/workflows",
        json=wf_payload,
        headers={"X-CSRF-Token": csrf, "Origin": "http://localhost:5173"},
    )
    assert ok.status_code == 200


def test_login_bruteforce_rate_limit_and_password_reset(auth_client: TestClient):
    auth_client.post(
        "/api/auth/register",
        json={"email": "brute@example.com", "password": "OldPassword123!"},
    )
    auth_client.post("/api/auth/logout")

    # 5 failed logins -> 401; 6th -> 429
    for _ in range(5):
        res = auth_client.post(
            "/api/auth/login",
            json={"email": "brute@example.com", "password": "WrongPassword!"},
        )
        assert res.status_code == 401

    locked = auth_client.post(
        "/api/auth/login",
        json={"email": "brute@example.com", "password": "OldPassword123!"},
    )
    assert locked.status_code == 429

    # Password reset flow
    forgot = auth_client.post("/api/auth/forgot-password", json={"email": "brute@example.com"})
    assert forgot.status_code == 200

    reset_code = "654321-abcd"
    with Session(db_mod.get_engine()) as session:
        user = session.exec(select(User).where(User.email == "brute@example.com")).first()
        assert user is not None
        prt = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(reset_code),
            expires_at=utcnow() + timedelta(minutes=10),
            used=False,
        )
        session.add(prt)
        session.commit()

    reset = auth_client.post(
        "/api/auth/reset-password",
        json={"email": "brute@example.com", "token": reset_code, "new_password": "NewPassword456!"},
    )
    assert reset.status_code == 200

    # Clear limiter to verify new password works and old fails
    login_limiter.clear("login:testclient:brute@example.com")
    login_limiter._hits.clear()
    assert (
        auth_client.post(
            "/api/auth/login",
            json={"email": "brute@example.com", "password": "OldPassword123!"},
        ).status_code
        == 401
    )
    assert (
        auth_client.post(
            "/api/auth/login",
            json={"email": "brute@example.com", "password": "NewPassword456!"},
        ).status_code
        == 200
    )


def test_per_user_isolation_workflows_runs_credentials_integrations(auth_client: TestClient):
    with TestClient(app) as client_a, TestClient(app) as client_b:
        ra = client_a.post("/api/auth/register", json={"email": "usera@example.com", "password": "PasswordA123!"})
        rb = client_b.post("/api/auth/register", json={"email": "userb@example.com", "password": "PasswordB123!"})
        client_a.headers["X-CSRF-Token"] = ra.json()["csrf_token"]
        client_b.headers["X-CSRF-Token"] = rb.json()["csrf_token"]

        # User A creates workflow, run, credential, and AI integration
        wf_a = client_a.post(
            "/api/workflows",
            json={
                "name": "UserA Secret Flow",
                "graph_json": {
                    "nodes": [
                        {"id": "t1", "type": "trigger.manual", "params": {}},
                        {"id": "e1", "type": "findings.export", "params": {}},
                    ],
                    "edges": [{"id": "ed1", "source": "t1", "target": "e1"}],
                },
            },
        )
        assert wf_a.status_code == 200
        wf_a_id = wf_a.json()["id"]

        run_a = client_a.post(f"/api/workflows/{wf_a_id}/run?wait=true")
        assert run_a.status_code == 200
        run_a_id = run_a.json()["run_id"]

        cred_a = client_a.post(
            "/api/credentials",
            json={"name": "A-key", "kind": "llm", "value": "sk-userA-secret-9999"},
        )
        assert cred_a.status_code == 200
        cred_a_id = cred_a.json()["id"]

        integ_a = client_a.put(
            "/api/integrations/ai",
            json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "AIzaUserASecretKey123456"},
        )
        assert integ_a.status_code == 200

        # User B cannot see or access User A's resources
        assert wf_a_id not in [w["id"] for w in client_b.get("/api/workflows").json()["workflows"]]
        assert run_a_id not in [r["id"] for r in client_b.get("/api/runs").json()["runs"]]
        assert cred_a_id not in [c["id"] for c in client_b.get("/api/credentials").json()["credentials"]]
        assert client_b.get("/api/integrations").json()["ai"]["configured"] is False

        assert client_b.get(f"/api/workflows/{wf_a_id}").status_code == 403
        assert client_b.post(f"/api/workflows/{wf_a_id}/run?wait=true").status_code == 403
        assert client_b.delete(f"/api/workflows/{wf_a_id}").status_code == 403
        assert client_b.get(f"/api/runs/{run_a_id}").status_code == 403
        assert client_b.get(f"/api/runs/{run_a_id}/report.json").status_code == 403
        assert client_b.delete(f"/api/credentials/{cred_a_id}").status_code == 403


def test_users_file_persistence_and_login_recovery(tmp_path: Path, monkeypatch):
    import json

    users_file = tmp_path / "users.json"
    db1 = tmp_path / "first.db"
    db2 = tmp_path / "recreated.db"

    monkeypatch.setenv("AUTH_USERS_FILE", str(users_file))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db1}")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client1:
        reg = client1.post(
            "/api/auth/register",
            json={"email": "art.zhirnov@gmail.com", "password": "MySecretPassword1!"},
        )
        assert reg.status_code == 200

    assert users_file.exists()
    data = json.loads(users_file.read_text(encoding="utf-8"))
    rec = data["users"]["art.zhirnov@gmail.com"]
    assert rec["password_hash"].startswith("pbkdf2_sha256$")
    assert "MySecretPassword1!" not in json.dumps(data)

    # Simulate DB wipe / recreation while users.json survives
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db2}")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client2:
        bad = client2.post(
            "/api/auth/login",
            json={"email": "art.zhirnov@gmail.com", "password": "WrongPassword!"},
        )
        assert bad.status_code == 401

        ok = client2.post(
            "/api/auth/login",
            json={"email": "art.zhirnov@gmail.com", "password": "MySecretPassword1!"},
        )
        assert ok.status_code == 200
        assert ok.json()["authenticated"] is True
        assert ok.json()["user"]["email"] == "art.zhirnov@gmail.com"


def test_accounts_database_db_sql_queries(tmp_path: Path, monkeypatch):
    import sqlite3

    accounts_db = tmp_path / "database.db"
    users_file = tmp_path / "missing_users.json"
    db1 = tmp_path / "main1.db"
    db2 = tmp_path / "main2.db"

    monkeypatch.setenv("AUTH_SQL_DB_PATH", str(accounts_db))
    monkeypatch.setenv("AUTH_USERS_FILE", str(users_file))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db1}")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client1:
        reg = client1.post(
            "/api/auth/register",
            json={"email": "sqluser@example.com", "password": "SqlStrongPassword1!"},
        )
        assert reg.status_code == 200

    assert accounts_db.exists()
    with sqlite3.connect(str(accounts_db)) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "accounts" in tables
        row = conn.execute(
            "SELECT email, password_hash, is_active FROM accounts WHERE email = ?",
            ("sqluser@example.com",),
        ).fetchone()
        assert row is not None
        assert row[0] == "sqluser@example.com"
        assert row[1].startswith("pbkdf2_sha256$")
        assert "SqlStrongPassword1!" not in row[1]
        assert row[2] == 1

    # Remove JSON backup & recreate main app DB: login must succeed directly via SQL from database.db
    if users_file.exists():
        users_file.unlink()
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db2}")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client2:
        bad = client2.post(
            "/api/auth/login",
            json={"email": "sqluser@example.com", "password": "WrongPassword1!"},
        )
        assert bad.status_code == 401

        ok = client2.post(
            "/api/auth/login",
            json={"email": "sqluser@example.com", "password": "SqlStrongPassword1!"},
        )
        assert ok.status_code == 200
        assert ok.json()["user"]["email"] == "sqluser@example.com"

