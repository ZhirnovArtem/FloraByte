"""Phase 10 E2E tests: full pipeline, rerun, partial failure (scanner/LLM/Telegram), WS, and restart persistence."""

from __future__ import annotations

import io
import zipfile
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

import app.core.db as db_mod
from app.config import get_settings
from app.engine.events import event_bus
from app.main import app
from tests.conftest import authenticate_client


@pytest.fixture()
def e2e_env(tmp_path, monkeypatch):
    db_file = tmp_path / "phase10.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    db_mod._engine = None
    SQLModel.metadata.drop_all(db_mod.get_engine())
    db_mod.init_db()
    with TestClient(app) as client:
        authenticate_client(client)
        yield client, db_file, tmp_path
    db_mod._engine = None
    get_settings.cache_clear()


def _make_sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/settings.gradle.kts", 'rootProject.name = "demo"\n')
        zf.writestr(
            "demo/build.gradle.kts",
            'dependencies {\n    implementation("org.apache.logging.log4j:log4j-core:2.14.0")\n}\n',
        )
        zf.writestr(
            "demo/src/main/kotlin/App.kt",
            'val password = "prod_password_phase10_xyz"\n'
            'fun search(q: String) = jdbc.queryForList("SELECT * FROM items WHERE name = \'$q\'")\n',
        )
    return buf.getvalue()


def _build_full_graph(upload_id: str, dry_run_tg: bool = True) -> dict:
    return {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}},
            {"id": "sc2", "type": "scanner.sca", "params": {}},
            {"id": "sc3", "type": "scanner.sast", "params": {}},
            {"id": "m1", "type": "findings.merge", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
            {"id": "ai1", "type": "ai.explain", "params": {}},
            {"id": "tg1", "type": "notify.telegram", "params": {"dry_run": dry_run_tg}},
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
            {"id": "ed10", "source": "ai1", "target": "tg1"},
        ],
    }


def test_e2e_full_rerun_ws_and_restart_persistence(e2e_env):
    client, _db_file, _tmp = e2e_env
    up = client.post("/api/uploads", files={"file": ("demo.zip", _make_sample_zip(), "application/zip")})
    assert up.status_code == 200
    upload_id = up.json()["upload_id"]

    wf_id = client.post(
        "/api/workflows",
        json={"name": "phase10-e2e", "graph_json": _build_full_graph(upload_id, dry_run_tg=True)},
    ).json()["id"]

    # Run 1 (LLM unavailable -> strict AI error, zero fake recommendations, scan findings preserved)
    run1_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    run1 = client.get(f"/api/runs/{run1_id}").json()
    assert run1["status"] == "partial"
    assert run1["ai_report"]["validation"]["mode"] == "error"
    assert run1["ai_report"]["items"] == []

    rep1 = client.get(f"/api/runs/{run1_id}/report.json").json()
    assert {f["category"] for f in rep1["findings"]} == {"SECRET", "SCA", "SAST"}
    assert "prod_password_phase10_xyz" not in str(rep1)

    md1 = client.get(f"/api/runs/{run1_id}/report.md").text
    assert "# Security findings report" in md1

    # WebSocket events verified
    with client.websocket_connect(f"/ws/runs/{run1_id}") as ws:
        evs = []
        for _ in range(30):
            ev = ws.receive_json()
            evs.append(ev)
            if ev.get("event") == "run_finished":
                break
        assert evs[0]["event"] == "run_started"
        assert evs[-1]["event"] == "run_finished"

    # Rerun (Run 2)
    run2_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    assert run2_id != run1_id
    history = client.get("/api/runs").json()["runs"]
    assert len(history) >= 2

    # Simulate backend restart: reset SQLAlchemy engine & clear in-memory event_bus
    event_bus.clear(run1_id)
    db_mod._engine = None
    with TestClient(app) as restarted_client:
        restarted_client.cookies.update(client.cookies)
        restarted_client.headers.update(client.headers)
        hist_after = restarted_client.get("/api/runs").json()["runs"]
        assert any(r["id"] == run1_id for r in hist_after)
        assert len(restarted_client.get(f"/api/runs/{run1_id}/report.json").json()["findings"]) == len(rep1["findings"])
        with restarted_client.websocket_connect(f"/ws/runs/{run1_id}") as ws:
            replayed = []
            for _ in range(30):
                ev = ws.receive_json()
                replayed.append(ev)
                if ev.get("event") == "run_finished":
                    break
            assert replayed[-1]["event"] == "run_finished"


def test_e2e_partial_scanner_and_telegram_failures_preserve_reports(e2e_env, monkeypatch):
    client, _db_file, _tmp = e2e_env
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:AATestFailureTokenPhase10")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "777")
    get_settings.cache_clear()

    up = client.post("/api/uploads", files={"file": ("demo.zip", _make_sample_zip(), "application/zip")})
    upload_id = up.json()["upload_id"]
    wf_id = client.post(
        "/api/workflows",
        json={"name": "phase10-partial", "graph_json": _build_full_graph(upload_id, dry_run_tg=False)},
    ).json()["id"]

    # Force one scanner (SAST) to fail AND Telegram API to return 500
    async def fail_tg(self, url, json=None, **kwargs):
        return httpx.Response(500, request=httpx.Request("POST", url))

    with (
        patch("app.nodes.scanners.sast.scan", side_effect=RuntimeError("SAST crashed")),
        patch.object(httpx.AsyncClient, "post", new=fail_tg),
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "partial"
    by_node = {n["node_id"]: n["status"] for n in run["nodes"]}
    assert by_node["sc1"] == "success"
    assert by_node["sc2"] == "success"
    assert by_node["sc3"] == "failed"
    assert by_node["m1"] == "success"
    assert by_node["e1"] == "success"
    assert by_node["ai1"] == "failed"
    assert by_node["tg1"] == "failed"

    # Report from surviving scanners (SECRET + SCA) still preserved!
    rep = client.get(f"/api/runs/{run_id}/report.json").json()
    assert {f["category"] for f in rep["findings"]} == {"SECRET", "SCA"}
