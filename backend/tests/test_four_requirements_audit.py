"""Comprehensive verification of the 4 Page-10 enterprise requirements on fix/florabyte-integration."""

from __future__ import annotations

import io
import json
import shutil
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from sqlmodel import SQLModel

import app.core.db as db_mod
from app.config import get_settings
from app.core.crypto import get_fernet, is_production_env, reset_fernet_cache
from app.core.masking import redact_payload
from app.core.models import Finding
from app.engine.events import event_bus
from app.main import app
from app.nodes.ai.explain import AiExplainNode
from app.nodes.ai.explain import Params as AiParams
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import NODE_REGISTRY, register_node
from tests.conftest import authenticate_client


@pytest.fixture()
def audit_client(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("APP_SECRET_KEY_FILE", str(tmp_path / "fernet.key"))
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    reset_fernet_cache()
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
        auth = authenticate_client(client, email="audit1@florabyte.local")
        yield client, auth["user"], tmp_path
    db_mod._engine = None
    get_settings.cache_clear()
    reset_fernet_cache()


def _zip_with_secret(secret_literal: str = "audit_secret_token_42") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/settings.gradle.kts", 'rootProject.name = "audit"\n')
        zf.writestr("proj/src/main/kotlin/Cfg.kt", f'val apiSecret = "{secret_literal}"\n')
    return buf.getvalue()


def _empty_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/settings.gradle.kts", 'rootProject.name = "clean"\n')
        zf.writestr("proj/src/main/kotlin/Clean.kt", 'fun ok() = 1\n')
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Requirement 1: Modularity & unified node contract
# ---------------------------------------------------------------------------


def test_all_registered_nodes_follow_unified_contract():
    assert len(NODE_REGISTRY) >= 12
    for ntype, cls in NODE_REGISTRY.items():
        assert issubclass(cls, BaseNode)
        assert cls.type == ntype and cls.type
        assert isinstance(cls.label, str) and cls.label
        assert isinstance(cls.group, str) and cls.group
        assert issubclass(cls.Params, BaseModel)
        for p in (*cls.inputs, *cls.outputs):
            assert isinstance(p, Port)
            assert p.name and p.kind
        desc = cls.describe()
        json.dumps(desc)  # must be JSON-serializable for /api/node-types


def test_add_custom_scanner_and_messenger_without_core_changes(audit_client):
    client, _, _ = audit_client
    delivered: list[dict[str, Any]] = []

    class CustomScannerParams(BaseModel):
        marker: str = Field("TODO_AUDIT")

    @register_node
    class CustomAuditScannerNode(BaseNode):
        type = "scanner.custom_audit_test"
        label = "Custom Audit Scanner"
        group = "scanner"
        inputs = [Port(name="workspace", kind="Workspace")]
        outputs = [Port(name="findings", kind="Findings")]
        Params = CustomScannerParams

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
            assert isinstance(params, CustomScannerParams)
            return {
                "findings": [
                    Finding(
                        category="SAST",
                        path="src/custom.kt",
                        **{"class": params.marker},
                        line=7,
                        severity="MEDIUM",
                        description="Custom scanner rule matched",
                    )
                ]
            }

    class CustomMessengerParams(BaseModel):
        channel: str = Field("#sec-ops")

    @register_node
    class CustomAuditMessengerNode(BaseNode):
        type = "notify.custom_audit_slack"
        label = "Custom Audit Messenger"
        group = "notify"
        inputs = [Port(name="report", kind="Report")]
        outputs = [Port(name="out", kind="Any")]
        Params = CustomMessengerParams

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
            assert isinstance(params, CustomMessengerParams)
            rep = inputs["report"]
            delivered.append({"channel": params.channel, "count": len(rep.get("findings") or [])})
            return {"out": {"sent": True, "channel": params.channel}}

    try:
        types_catalog = {t["type"] for t in client.get("/api/node-types").json()["nodes"]}
        assert "scanner.custom_audit_test" in types_catalog
        assert "notify.custom_audit_slack" in types_catalog

        up_id = client.post("/api/uploads", files={"file": ("clean.zip", _empty_zip(), "application/zip")}).json()["upload_id"]
        wf_id = client.post(
            "/api/workflows",
            json={
                "name": "custom-scanner-and-messenger",
                "graph_json": {
                    "nodes": [
                        {"id": "t1", "type": "trigger.manual", "params": {}},
                        {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
                        {"id": "sc1", "type": "scanner.custom_audit_test", "params": {"marker": "CUSTOM_RULE_1"}},
                        {"id": "e1", "type": "findings.export", "params": {}},
                        {"id": "n1", "type": "notify.custom_audit_slack", "params": {"channel": "#appsec"}},
                    ],
                    "edges": [
                        {"id": "ed1", "source": "t1", "target": "s1"},
                        {"id": "ed2", "source": "s1", "target": "sc1"},
                        {"id": "ed3", "source": "sc1", "target": "e1", "targetHandle": "findings"},
                        {"id": "ed4", "source": "e1", "sourceHandle": "report", "target": "n1", "targetHandle": "report"},
                    ],
                },
            },
        ).json()["id"]

        run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
        run = client.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "success"
        assert delivered == [{"channel": "#appsec", "count": 1}]
    finally:
        NODE_REGISTRY.pop("scanner.custom_audit_test", None)
        NODE_REGISTRY.pop("notify.custom_audit_slack", None)


# ---------------------------------------------------------------------------
# Requirement 2: Real local LLM server (Ollama / vLLM style) + live switching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_local_http_llm_server_and_zero_restart_switching(audit_client, tmp_path):
    client, user, _ = audit_client

    class LocalLlmHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/v1/models":
                body = json.dumps({"data": [{"id": "llama3.2-local"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path == "/v1/chat/completions":
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                payload = {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "summary": "Локальная модель Ollama успешно проверила находку.",
                                        "items": [
                                            {
                                                "finding_ref": 0,
                                                "explanation": "Пароль в открытом виде в Cfg.kt.",
                                                "risk": "Утечка секрета из репозитория.",
                                                "priority": "HIGH",
                                                "fix_steps": ["Перенести секрет в env"],
                                            }
                                        ],
                                    },
                                    ensure_ascii=False,
                                )
                            }
                        }
                    ]
                }
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalLlmHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    local_url = f"http://127.0.0.1:{port}/v1"

    try:
        # Live model discovery & test against real local HTTP server
        r_models = client.post(
            "/api/integrations/ai/models",
            json={"provider": "ollama", "base_url": local_url, "api_key": ""},
        )
        assert r_models.status_code == 200
        assert r_models.json()["ok"] is True
        assert "llama3.2-local" in r_models.json()["models"]

        r_test = client.post(
            "/api/integrations/ai/test",
            json={"provider": "ollama", "model": "llama3.2-local", "base_url": local_url, "api_key": ""},
        )
        assert r_test.status_code == 200
        assert r_test.json()["ok"] is True

        # Save Ollama, then save Gemini, then switch back to Ollama without restart
        client.put(
            "/api/integrations/ai",
            json={"provider": "ollama", "model": "llama3.2-local", "base_url": local_url, "api_key": ""},
        )
        client.put(
            "/api/integrations/ai",
            json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "AIzaCloudSwitchTest999"},
        )
        client.post("/api/integrations/ai/activate", json={"provider": "ollama"})

        finding = Finding(category="SECRET", path="Cfg.kt", **{"class": "password"}, line=1, severity="HIGH")
        ctx = NodeContext(run_id="r-local-http", node_id="ai1", workspace=str(tmp_path), owner_id=user["id"])
        res = await AiExplainNode().run(ctx, {"findings": [finding]}, AiParams())
        val = res["report"]["validation"]
        assert val["passed"] is True
        assert val["provider"] == "ollama"
        assert "Ollama" in res["report"]["summary"]
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Requirement 3: Production APP_SECRET_KEY requirement + WS/log redaction
# ---------------------------------------------------------------------------


def test_production_requires_app_secret_key_and_ws_redaction(monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("RENDER", "true")
    reset_fernet_cache()
    assert is_production_env() is True

    with pytest.raises(RuntimeError, match="APP_SECRET_KEY"):
        get_fernet()

    # Valid Fernet key succeeds in production
    from cryptography.fernet import Fernet

    monkeypatch.setenv("APP_SECRET_KEY", Fernet.generate_key().decode())
    reset_fernet_cache()
    assert get_fernet() is not None

    # Redact nested WS event payloads
    ev = {
        "event": "node_failed",
        "error": "Auth failed with Authorization: Basic dXNlcjpwYXNzMTIz and AIzaSyFakeKey999999999999 and sk-ant-secret1234567890",
        "nested": ["https://user:supersecret@git.example.com/repo.git", "123456789:AATelegramSecretTokenXYZ999"],
    }
    safe = redact_payload(ev)
    dumped = json.dumps(safe)
    for leak in ("dXNlcjpwYXNzMTIz", "AIzaSyFakeKey999999999999", "sk-ant-secret1234567890", "supersecret", "AATelegramSecretTokenXYZ999"):
        assert leak not in dumped


@pytest.mark.asyncio
async def test_event_bus_redacts_ws_events():
    q = await event_bus.subscribe("r-redact-ws")
    try:
        await event_bus.emit(
            "r-redact-ws",
            {"event": "node_failed", "error": "Failed calling key AIzaWsLeakTestKey123456789"},
        )
        msg = await q.get()
        assert "AIzaWsLeakTestKey123456789" not in msg["error"]
    finally:
        await event_bus.unsubscribe("r-redact-ws", q)
        event_bus.clear("r-redact-ws")


# ---------------------------------------------------------------------------
# Requirement 4: Persistent run history, node error inspection, compare & restart
# ---------------------------------------------------------------------------


def test_run_history_node_errors_comparison_and_restart_persistence(audit_client):
    client, _, tmp_path = audit_client

    up1 = client.post("/api/uploads", files={"file": ("v1.zip", _zip_with_secret("first_secret_111"), "application/zip")}).json()["upload_id"]
    wf_id = client.post(
        "/api/workflows",
        json={
            "name": "history-compare-wf",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.manual", "params": {}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up1}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "m1", "type": "findings.merge", "params": {}},
                    {"id": "ai1", "type": "ai.explain", "params": {}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "target": "m1", "targetHandle": "a"},
                    {"id": "ed4", "source": "m1", "sourceHandle": "findings", "target": "ai1", "targetHandle": "findings"},
                    {"id": "ed5", "source": "ai1", "sourceHandle": "report", "target": "e1", "targetHandle": "report"},
                ],
            },
        },
    ).json()["id"]

    # Run 1: AI not configured -> partial run, findings saved, AI error recorded on ai1 node
    run1_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    # Run 2: configure Gemini, scan clean project -> success
    up2 = client.post("/api/uploads", files={"file": ("v2.zip", _empty_zip(), "application/zip")}).json()["upload_id"]
    client.put(
        f"/api/workflows/{wf_id}",
        json={
            "name": "history-compare-wf",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.manual", "params": {}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up2}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "m1", "type": "findings.merge", "params": {}},
                    {"id": "ai1", "type": "ai.explain", "params": {}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "target": "m1", "targetHandle": "a"},
                    {"id": "ed4", "source": "m1", "sourceHandle": "findings", "target": "ai1", "targetHandle": "findings"},
                    {"id": "ed5", "source": "ai1", "sourceHandle": "report", "target": "e1", "targetHandle": "report"},
                ],
            },
        },
    )
    run2_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    # Wipe /tmp/runs and reset engine to simulate Backend restart
    shutil.rmtree(tmp_path / "runs", ignore_errors=True)
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    db_mod._engine = None

    with TestClient(app) as restarted:
        restarted.cookies.update(client.cookies)
        restarted.headers.update(client.headers)

        # Inspect Run 1 after restart: findings preserved, ai1 node failed with clear error
        r1 = restarted.get(f"/api/runs/{run1_id}").json()
        assert r1["status"] == "partial"
        assert r1["summary"]["report"]["findings_count"] == 1
        assert r1["ai_report"]["validation"]["mode"] == "error"
        ai_node = next(n for n in r1["nodes"] if n["node_id"] == "ai1")
        assert ai_node["status"] == "failed"
        assert ai_node["error"]

        # Compare Run 1 vs Run 2 after restart: 1 finding fixed!
        cmp_res = restarted.get(f"/api/runs/compare?base={run1_id}&target={run2_id}")
        assert cmp_res.status_code == 200
        diff = cmp_res.json()
        assert diff["summary"]["base_total"] == 1
        assert diff["summary"]["target_total"] == 0
        assert diff["summary"]["fixed_count"] == 1
        assert diff["summary"]["new_count"] == 0

        # Report exports still work after /tmp wipe
        assert len(restarted.get(f"/api/runs/{run1_id}/report.json").json()["findings"]) == 1
        assert "Cfg.kt" in restarted.get(f"/api/runs/{run1_id}/report.md").text
        assert restarted.get(f"/api/runs/{run1_id}/report.pdf").content.startswith(b"%PDF-1.4")
