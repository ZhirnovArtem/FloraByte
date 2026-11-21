"""Tests for additional technical requirements: modularity, closed-loop local LLMs, secret protection, and persistent history."""

from __future__ import annotations

import io
import logging
import shutil
import zipfile
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from sqlmodel import SQLModel, Session

import app.core.db as db_mod
from app.config import get_settings
from app.core.crypto import decrypt, reset_fernet_cache
from app.core.logging import RedactingFilter
from app.core.models import Finding, IntegrationSetting
from app.main import app
from app.nodes.ai.explain import AiExplainNode
from app.nodes.ai.explain import Params as AiParams
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import NODE_REGISTRY, register_node
from tests.conftest import authenticate_client


@pytest.fixture()
def ent_client(tmp_path, monkeypatch):
    db_file = tmp_path / "enterprise.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("APP_SECRET_KEY_FILE", str(tmp_path / "fernet.key"))
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
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
        authenticate_client(client)
        yield client, tmp_path
    db_mod._engine = None
    get_settings.cache_clear()
    reset_fernet_cache()


def _sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/settings.gradle.kts", 'rootProject.name = "ent"\n')
        zf.writestr("proj/src/main/kotlin/App.kt", 'val password = "ent_secret_password_99"\n')
    return buf.getvalue()


def test_extensible_node_registration_and_execution(ent_client):
    client, _ = ent_client
    delivered: list[str] = []

    class CustomParams(BaseModel):
        channel: str = Field("sec-ops", description="Target channel")

    @register_node
    class CustomSlackTestNode(BaseNode):
        type = "notify.custom_ext_test"
        label = "Custom Ext Notify"
        group = "notify"
        inputs = [Port(name="report", kind="Report")]
        outputs = [Port(name="out", kind="Any")]
        Params = CustomParams

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
            assert isinstance(params, CustomParams)
            delivered.append(params.channel)
            return {"out": {"sent": True, "channel": params.channel}}

    try:
        nt = client.get("/api/node-types").json()["nodes"]
        match = [n for n in nt if n["type"] == "notify.custom_ext_test"]
        assert len(match) == 1
        assert "channel" in match[0]["params_schema"]["properties"]

        wf_id = client.post(
            "/api/workflows",
            json={
                "name": "ext-node-flow",
                "graph_json": {
                    "nodes": [
                        {"id": "t1", "type": "trigger.manual", "params": {}},
                        {"id": "e1", "type": "findings.export", "params": {}},
                        {"id": "c1", "type": "notify.custom_ext_test", "params": {"channel": "audit-room"}},
                    ],
                    "edges": [
                        {"id": "ed1", "source": "t1", "target": "e1"},
                        {"id": "ed2", "source": "e1", "sourceHandle": "report", "target": "c1", "targetHandle": "report"},
                    ],
                },
            },
        ).json()["id"]

        run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
        run = client.get(f"/api/runs/{run_id}").json()
        assert run["status"] == "success"
        assert delivered == ["audit-room"]
    finally:
        NODE_REGISTRY.pop("notify.custom_ext_test", None)


@pytest.mark.asyncio
async def test_local_ollama_and_vllm_closed_loop_no_key(ent_client, tmp_path):
    client, _ = ent_client

    for provider, url, model in (
        ("ollama", "http://ollama.internal:11434/v1", "llama3.2"),
        ("vllm", "http://10.20.30.40:8000/v1", "Qwen/Qwen2.5-7B-Instruct"),
    ):
        put = client.put(
            "/api/integrations/ai",
            json={"provider": provider, "model": model, "base_url": url, "api_key": ""},
        )
        assert put.status_code == 200, put.text
        assert put.json()["configured"] is True
        assert put.json()["source"] == "local"
        assert put.json()["provider"] == provider

        async def fake_get(self, req_url, **kwargs):
            assert "generativelanguage.googleapis.com" not in str(req_url)
            return httpx.Response(
                200,
                json={"data": [{"id": model}]},
                request=httpx.Request("GET", req_url),
            )

        with patch.object(httpx.AsyncClient, "get", new=fake_get):
            test_res = client.post(
                "/api/integrations/ai/test",
                json={"provider": provider, "model": model, "base_url": url, "api_key": ""},
            )
        assert test_res.status_code == 200
        assert test_res.json()["ok"] is True

        seen_urls: list[str] = []

        async def fake_post(self, req_url, json=None, **kwargs):
            seen_urls.append(str(req_url))
            assert "generativelanguage.googleapis.com" not in str(req_url)
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": '{"summary":"Локальный анализ завершён.","items":[{"finding_ref":0,"explanation":"Пароль в коде Cfg.kt:4.","risk":"HIGH","fix_steps":["Вынести в env"]}]}'
                            }
                        }
                    ]
                },
                request=httpx.Request("POST", req_url),
            )

        node = AiExplainNode()
        ctx = NodeContext(run_id=f"r-{provider}", node_id="ai1", workspace=tmp_path)
        finding = Finding(category="SECRET", path="Cfg.kt", **{"class": "password"}, line=4, severity="HIGH")
        with patch.object(httpx.AsyncClient, "post", new=fake_post):
            out = await node.run(ctx, {"findings": [finding]}, AiParams(provider=provider, base_url=url, model=model))
        rep = out["report"]
        assert rep["validation"]["mode"] == "llm"
        assert rep["validation"]["ai_status"] == "Успешно"
        assert seen_urls == [f"{url}/chat/completions"]


def test_secrets_encryption_redaction_and_deletion(ent_client):
    client, _ = ent_client
    tg_token = "987654321:AATestBotTokenForRedactionCheck999"

    # Credential stored encrypted and deletable
    created = client.post(
        "/api/credentials",
        json={"name": "corp-key", "kind": "llm", "value": "sk-SuperSecretCorpKey1234567890"},
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    assert "sk-SuperSecretCorpKey1234567890" not in created.text
    assert client.delete(f"/api/credentials/{cid}").status_code == 200
    assert cid not in [c["id"] for c in client.get("/api/credentials").json()["credentials"]]

    # Telegram URL token redaction in logger
    rec = logging.LogRecord(
        "httpx",
        logging.INFO,
        __file__,
        1,
        'HTTP Request: POST https://api.telegram.org/bot%s/sendMessage "HTTP/1.1 200 OK"',
        (tg_token,),
        None,
    )
    assert RedactingFilter().filter(rec)
    assert tg_token not in rec.getMessage()

    # Integration secret encrypted in DB and cleanly deletable
    client.put(
        "/api/integrations/ai",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "AIzaStoredSecretKey1234567890"},
    )
    with Session(db_mod.get_engine()) as session:
        rows = session.query(IntegrationSetting).all()
        assert any("AIzaStoredSecretKey1234567890" not in r.encrypted_secret and decrypt(r.encrypted_secret) == "AIzaStoredSecretKey1234567890" for r in rows)
    assert client.delete("/api/integrations/ai").status_code == 200
    assert client.get("/api/integrations").json()["ai"]["configured"] is False


def test_run_history_duration_and_report_recovery_after_tmp_wipe(ent_client):
    client, tmp_path = ent_client

    up_id = client.post("/api/uploads", files={"file": ("app.zip", _sample_zip(), "application/zip")}).json()["upload_id"]
    wf_id = client.post(
        "/api/workflows",
        json={
            "name": "persist-history",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.manual", "params": {}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "m1", "type": "findings.merge", "params": {}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "target": "m1", "targetHandle": "a"},
                    {"id": "ed4", "source": "m1", "sourceHandle": "findings", "target": "e1", "targetHandle": "findings"},
                ],
            },
        },
    ).json()["id"]

    run_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    # Simulate ephemeral Render /tmp wipe + backend restart
    shutil.rmtree(tmp_path / "runs", ignore_errors=True)
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    db_mod._engine = None

    with TestClient(app) as restarted:
        restarted.cookies.update(client.cookies)
        restarted.headers.update(client.headers)

        hist = restarted.get("/api/runs").json()["runs"]
        entry = next(r for r in hist if r["id"] == run_id)
        assert isinstance(entry["duration_ms"], int) and entry["duration_ms"] >= 0

        rep_json = restarted.get(f"/api/runs/{run_id}/report.json").json()
        assert len(rep_json["findings"]) == 1

        rep_md = restarted.get(f"/api/runs/{run_id}/report.md").text
        assert "# Security findings report" in rep_md
        assert "Main.kt" in rep_md or "App.kt" in rep_md

        rep_pdf = restarted.get(f"/api/runs/{run_id}/report.pdf").content
        assert rep_pdf.startswith(b"%PDF-1.4")
