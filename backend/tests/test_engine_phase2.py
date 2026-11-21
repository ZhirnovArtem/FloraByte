"""Phase 2 verification tests: CRUD, engine isolation, timeouts, and WS history replay."""

from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlmodel import SQLModel

from app.config import get_settings
from app.core.db import get_engine, init_db
from app.engine.events import event_bus
from app.main import app
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import NODE_REGISTRY, register_node
from tests.conftest import authenticate_client


@pytest.fixture()
def client(tmp_path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path}/phase2.db"
    os.environ["USE_STUB_SCANNERS"] = "1"
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    SQLModel.metadata.drop_all(get_engine())
    init_db()
    with TestClient(app) as c:
        authenticate_client(c)
        yield c


def test_workflow_crud_and_node_types(client: TestClient):
    nt = client.get("/api/node-types")
    assert nt.status_code == 200
    types = {n["type"] for n in nt.json()["nodes"]}
    assert {"trigger.manual", "source.upload_zip", "scanner.secrets", "logic.if_else", "ai.explain", "notify.telegram"} <= types

    g = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
        ],
        "edges": [{"id": "edge1", "source": "t1", "target": "e1"}],
    }
    created = client.post("/api/workflows", json={"name": "phase2-wf", "graph_json": g})
    assert created.status_code == 200
    wf_id = created.json()["id"]

    assert any(w["id"] == wf_id for w in client.get("/api/workflows").json()["workflows"])

    updated = client.put(f"/api/workflows/{wf_id}", json={"name": "phase2-wf-v2"})
    assert updated.status_code == 200
    assert updated.json()["name"] == "phase2-wf-v2"

    deleted = client.delete(f"/api/workflows/{wf_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/workflows/{wf_id}").status_code == 404


def test_node_failure_isolates_branch_and_ws_replays_from_db(client: TestClient):
    class _EmptyParams(BaseModel):
        pass

    @register_node
    class _FailingTestNode(BaseNode):
        type = "test.phase2_fail"
        label = "Failing Test Node"
        group = "logic"
        inputs = [Port(name="in", kind="Any")]
        outputs = [Port(name="out", kind="Any")]
        Params = _EmptyParams

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
            raise RuntimeError("boom in branch A")

    try:
        graph = {
            "nodes": [
                {"id": "t1", "type": "trigger.manual", "params": {}},
                {"id": "fail_a", "type": "test.phase2_fail", "params": {}},
                {"id": "skip_a", "type": "findings.export", "params": {}},
                {"id": "ok_b", "type": "findings.export", "params": {}},
            ],
            "edges": [
                {"id": "e1", "source": "t1", "target": "fail_a"},
                {"id": "e2", "source": "fail_a", "target": "skip_a"},
                {"id": "e3", "source": "t1", "target": "ok_b"},
            ],
        }
        wf_id = client.post("/api/workflows", json={"name": "partial-test", "graph_json": graph}).json()["id"]
        run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

        run_data = client.get(f"/api/runs/{run_id}").json()
        assert run_data["status"] == "partial"
        assert run_data["started_at"] is not None
        assert run_data["finished_at"] is not None
        by_id = {n["node_id"]: n["status"] for n in run_data["nodes"]}
        assert by_id["t1"] == "success"
        assert by_id["fail_a"] == "failed"
        assert by_id["skip_a"] == "skipped"
        assert by_id["ok_b"] == "success"

        # Verify in-memory WS replay
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
            events = []
            for _ in range(10):
                ev = ws.receive_json()
                events.append(ev)
                if ev.get("event") == "run_finished":
                    break
            ev_names = [e["event"] for e in events]
            assert "run_started" in ev_names
            assert "node_failed" in ev_names
            assert "node_skipped" in ev_names
            assert "node_finished" in ev_names
            assert "run_finished" in ev_names

        # Clear in-memory event_bus history (simulates backend restart) and verify DB replay
        event_bus.clear(run_id)
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
            replayed = []
            for _ in range(12):
                ev = ws.receive_json()
                replayed.append(ev)
                if ev.get("event") == "run_finished":
                    break
            ev_names = [e["event"] for e in replayed]
            assert ev_names[0] == "run_started"
            assert "node_failed" in ev_names
            assert "node_skipped" in ev_names
            assert ev_names[-1] == "run_finished"
    finally:
        NODE_REGISTRY.pop("test.phase2_fail", None)


def test_node_timeout_marks_node_failed_cleanly(client: TestClient, monkeypatch):
    class _EmptyParams(BaseModel):
        pass

    @register_node
    class _SlowTestNode(BaseNode):
        type = "test.phase2_slow"
        label = "Slow Test Node"
        group = "logic"
        inputs = [Port(name="in", kind="Any")]
        outputs = [Port(name="out", kind="Any")]
        Params = _EmptyParams

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
            await asyncio.sleep(5)
            return {"out": "done"}

    settings = get_settings()
    monkeypatch.setattr(settings, "node_timeout_sec", 0.05)
    try:
        graph = {
            "nodes": [
                {"id": "t1", "type": "trigger.manual", "params": {}},
                {"id": "slow", "type": "test.phase2_slow", "params": {}},
            ],
            "edges": [{"id": "e1", "source": "t1", "target": "slow"}],
        }
        wf_id = client.post("/api/workflows", json={"name": "timeout-test", "graph_json": graph}).json()["id"]
        run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
        run_data = client.get(f"/api/runs/{run_id}").json()
        assert run_data["status"] == "partial"
        by_id = {n["node_id"]: n for n in run_data["nodes"]}
        assert by_id["slow"]["status"] == "failed"
        assert "TimeoutError" in (by_id["slow"]["error"] or "")
    finally:
        NODE_REGISTRY.pop("test.phase2_slow", None)
