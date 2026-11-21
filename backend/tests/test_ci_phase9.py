"""Phase 9 tests: CI/CD API (/api/ci/run, /runs/{id}, /result, /webhook, severity gates)."""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.config import get_settings
from app.core.db import get_engine, init_db
from app.main import app


@pytest.fixture()
def ci_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/ci9.db")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.setenv("CI_TOKEN", "ci-secret-token-9")
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    SQLModel.metadata.drop_all(get_engine())
    init_db()
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def _zip_bytes(kt_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/build.gradle.kts", 'plugins { kotlin("jvm") }\n')
        zf.writestr("proj/src/main/kotlin/App.kt", kt_code)
    return buf.getvalue()


def test_ci_run_gates_polling_and_webhook(ci_client: TestClient):
    headers = {"X-CI-Token": "ci-secret-token-9"}
    assert ci_client.get("/api/ci/status").status_code == 401
    assert ci_client.get("/api/ci/status", headers=headers).json()["webhook_supported"] is True

    # Create a Secrets + Export workflow
    wf_graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": ""}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
        ],
        "edges": [
            {"id": "e1", "source": "t1", "target": "s1"},
            {"id": "e2", "source": "s1", "target": "sc1"},
            {"id": "e3", "source": "sc1", "target": "e1"},
        ],
    }
    wf_id = ci_client.post("/api/workflows", json={"name": "ci-sec", "graph_json": wf_graph}).json()["id"]

    # 1) Upload project with a HIGH hardcoded password (no CRITICAL)
    up1 = ci_client.post(
        "/api/uploads",
        headers=headers,
        files={"file": ("app.zip", _zip_bytes('val password = "super_secret_pw_123"\n'), "application/zip")},
    ).json()["upload_id"]

    # fail_on=CRITICAL -> PASS (200)
    r_pass = ci_client.post(
        "/api/ci/run",
        headers=headers,
        json={
            "workflow_id": wf_id,
            "repository": "org/repo",
            "commit": "abc123",
            "branch": "main",
            "upload_id": up1,
            "fail_on": "CRITICAL",
            "wait": True,
        },
    )
    assert r_pass.status_code == 200, r_pass.text
    d_pass = r_pass.json()
    assert d_pass["verdict"] == "PASS"
    assert d_pass["severity_counts"]["HIGH"] >= 1
    run_id = d_pass["run_id"]

    # Check status & result endpoints
    st = ci_client.get(f"/api/ci/runs/{run_id}", headers=headers)
    assert st.status_code == 200
    assert st.json()["verdict"] == "PASS"

    res = ci_client.get(f"/api/ci/runs/{run_id}/result", headers=headers)
    assert res.status_code == 200
    assert len(res.json()["findings"]) >= 1
    assert "super_secret_pw_123" not in res.text

    # fail_on=HIGH -> FAIL (409)
    r_fail = ci_client.post(
        "/api/ci/run",
        headers=headers,
        json={"workflow_id": wf_id, "upload_id": up1, "fail_on": "HIGH", "wait": True},
    )
    assert r_fail.status_code == 409
    assert r_fail.json()["verdict"] == "FAIL"
    assert r_fail.json()["exit_code_hint"] == 1

    # 2) Webhook with disallowed git_url rejected (403)
    bad_wh = ci_client.post(
        "/api/ci/webhook",
        headers=headers,
        json={"event": "push", "workflow_id": wf_id, "git_url": "https://evil.invalid/repo.git"},
    )
    assert bad_wh.status_code == 403

    # 3) Webhook with valid upload_id succeeds synchronously when wait=True
    good_wh = ci_client.post(
        "/api/ci/webhook",
        headers=headers,
        json={"event": "pull_request", "workflow_id": wf_id, "upload_id": up1, "fail_on": "CRITICAL", "wait": True},
    )
    assert good_wh.status_code == 200
    assert good_wh.json()["ci"]["event"] == "pull_request"

    # 4) Execution failure (missing upload_id UUID) -> 500 ERROR
    r_err = ci_client.post(
        "/api/ci/run",
        headers=headers,
        json={"workflow_id": wf_id, "wait": True},
    )
    assert r_err.status_code == 500
    assert r_err.json()["verdict"] == "ERROR"
