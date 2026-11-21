"""E2E test for full pipeline with real scanners (USE_STUB_SCANNERS=0), AI_CODE_CHECKER, and Telegram."""

from __future__ import annotations

import io
import os
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.config import get_settings
from app.core.db import get_engine, init_db
from app.main import app
from tests.conftest import authenticate_client


@pytest.fixture(scope="module")
def full_client(tmp_path_factory):
    base = tmp_path_factory.mktemp("e2e_full")
    os.environ["DATABASE_URL"] = f"sqlite:///{base}/full.db"
    os.environ["USE_STUB_SCANNERS"] = "0"
    os.environ["TELEGRAM_BOT_TOKEN"] = "123456:FAKE_TELEGRAM_TOKEN"
    os.environ["TELEGRAM_CHAT_ID"] = "-100999"
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = base / "runs"
    settings.upload_dir = base / "uploads"
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.use_stub_scanners = False

    SQLModel.metadata.drop_all(get_engine())
    init_db()
    with TestClient(app) as c:
        authenticate_client(c)
        yield c


def _sample_gradle_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("my-project/settings.gradle.kts", 'rootProject.name = "demo"\n')
        zf.writestr(
            "my-project/build.gradle.kts",
            'dependencies {\n    implementation("org.apache.logging.log4j:log4j-core:2.14.0")\n}\n',
        )
        zf.writestr(
            "my-project/src/main/kotlin/App.kt",
            'val apiKey = "super_secret_api_key_987654321"\n'
            'fun q(id: String) = jdbcTemplate.query("SELECT * FROM users WHERE id=" + id)\n',
        )
    return buf.getvalue()


def test_full_pipeline_real_scanners_ai_telegram(full_client: TestClient, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    r = full_client.post(
        "/api/uploads",
        files={"file": ("proj.zip", _sample_gradle_zip(), "application/zip")},
    )
    assert r.status_code == 200, r.text
    upload_id = r.json()["upload_id"]

    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}, "position": {"x": 0, "y": 0}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": upload_id}, "position": {"x": 100, "y": 0}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}, "position": {"x": 200, "y": 0}},
            {"id": "sc2", "type": "scanner.sca", "params": {}, "position": {"x": 200, "y": 100}},
            {"id": "sc3", "type": "scanner.sast", "params": {}, "position": {"x": 200, "y": 200}},
            {"id": "m1", "type": "findings.merge", "params": {}, "position": {"x": 300, "y": 100}},
            {"id": "e1", "type": "findings.export", "params": {}, "position": {"x": 400, "y": 100}},
            {"id": "ai1", "type": "ai.explain", "params": {}, "position": {"x": 500, "y": 100}},
            {"id": "tg1", "type": "notify.telegram", "params": {}, "position": {"x": 600, "y": 100}},
        ],
        "edges": [
            {"id": "ed1", "source": "t1", "target": "s1"},
            {"id": "ed2", "source": "s1", "target": "sc1"},
            {"id": "ed3", "source": "s1", "target": "sc2"},
            {"id": "ed4", "source": "s1", "target": "sc3"},
            {"id": "ed5", "source": "sc1", "target": "m1", "targetHandle": "a"},
            {"id": "ed6", "source": "sc2", "target": "m1", "targetHandle": "b"},
            {"id": "ed7", "source": "sc3", "target": "m1", "targetHandle": "c"},
            {"id": "ed8", "source": "m1", "target": "e1"},
            {"id": "ed9", "source": "m1", "target": "ai1"},
            {"id": "ed10", "source": "e1", "target": "tg1"},
        ],
    }

    r = full_client.post("/api/workflows", json={"name": "full-e2e", "graph_json": graph})
    assert r.status_code == 200, r.text
    wf_id = r.json()["id"]

    tg_payloads = []
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"ok": True, "result": {"message_id": 101}}

    async def fake_post(self, url, json=None, **kwargs):
        tg_payloads.append(json)
        return fake_resp

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = full_client.post(f"/api/workflows/{wf_id}/run?wait=true")
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]

    run = full_client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "success"
    assert run["ai_report"] is not None
    assert len(tg_payloads) == 1
    assert "super_secret_api_key_987654321" not in tg_payloads[0]["text"]

    rep = full_client.get(f"/api/runs/{run_id}/report.json").json()
    cats = {f["category"] for f in rep["findings"]}
    assert cats == {"SECRET", "SCA", "SAST"}
    assert "super_secret_api_key_987654321" not in str(rep)
