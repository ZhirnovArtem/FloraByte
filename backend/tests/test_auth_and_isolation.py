"""Auth modernization tests: registration, HttpOnly cookies, CSRF/Origin, rate limiting, and owner isolation."""

from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, select

import app.core.db as db_mod
from app.config import get_settings
from app.core.auth import (
    SESSION_COOKIE_NAME,
    login_limiter,
    register_limiter,
)
from app.core.models import User
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


def test_login_bruteforce_rate_limit_and_no_password_reset(auth_client: TestClient):
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

    # Password reset endpoints have been removed
    assert auth_client.post("/api/auth/forgot-password", json={"email": "brute@example.com"}).status_code == 404
    assert (
        auth_client.post(
            "/api/auth/reset-password",
            json={"email": "brute@example.com", "token": "123456-abcd", "new_password": "NewPassword456!"},
        ).status_code
        == 404
    )

    # Clear limiter to verify existing password still works
    login_limiter.clear("login:testclient:brute@example.com")
    login_limiter._hits.clear()
    assert (
        auth_client.post(
            "/api/auth/login",
            json={"email": "brute@example.com", "password": "OldPassword123!"},
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


def test_single_source_of_truth_no_duplicate_account_files(tmp_path, monkeypatch):
    """Accounts live exclusively in DATABASE_URL (users table); no sidecar JSON/SQLite account stores are created."""
    db_file = tmp_path / "primary.db"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    db_mod._engine = None

    with TestClient(app) as client1:
        reg = client1.post(
            "/api/auth/register",
            json={"email": "art.zhirnov@gmail.com", "password": "MySecretPassword1!"},
        )
        assert reg.status_code == 200
        user_id = reg.json()["user"]["id"]

    # No legacy sidecar stores created
    assert not (tmp_path / "database.db").exists()
    assert not (tmp_path / "users.json").exists()
    assert not (tmp_path / "data" / "users.json").exists()

    # Re-open app pointing at the same DATABASE_URL -> login succeeds with original password & preserves ID
    db_mod._engine = None
    get_settings.cache_clear()
    with TestClient(app) as client2:
        bad = client2.post(
            "/api/auth/login",
            json={"email": "art.zhirnov@gmail.com", "password": "WrongPassword!"},
        )
        assert bad.status_code == 401

        ok = client2.post(
            "/api/auth/login",
            json={"email": "ART.ZHIRNOV@gmail.com", "password": "MySecretPassword1!"},
        )
        assert ok.status_code == 200
        assert ok.json()["authenticated"] is True
        assert ok.json()["user"]["id"] == user_id
        assert ok.json()["user"]["email"] == "art.zhirnov@gmail.com"


