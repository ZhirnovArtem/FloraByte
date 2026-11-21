"""Comprehensive tests for Universal AI Provider architecture, UI endpoints, switching, security, and exports."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, select

import app.core.db as db_mod
from app.config import get_settings
from app.core.crypto import decrypt, reset_fernet_cache
from app.core.models import Finding, IntegrationSetting
from app.core.pdf_export import render_report_pdf
from app.main import app
from app.nodes.ai.explain import AiExplainNode
from app.nodes.ai.explain import Params as AiParams
from app.nodes.ai.providers import AIProviderManager, BaseProviderAdapter, ProviderSpec
from app.nodes.base import NodeContext
from app.nodes.findings.report_export import ReportExportNode
from app.nodes.findings.report_export import Params as ExportParams
from app.nodes.notify.telegram import _format_message
from tests.conftest import authenticate_client

_ORIG_ASYNC_CLIENT = httpx.AsyncClient


def _mock_async_client(transport_fn):
    return lambda **kw: _ORIG_ASYNC_CLIENT(transport=httpx.MockTransport(transport_fn))


@pytest.fixture()
def ai_client(tmp_path, monkeypatch):
    db_file = tmp_path / "universal_ai.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
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
        auth = authenticate_client(client, email="ai_owner_1@florabyte.local")
        yield client, auth["user"], tmp_path
    db_mod._engine = None
    get_settings.cache_clear()
    reset_fernet_cache()


def _sample_finding() -> Finding:
    return Finding(
        category="SAST",
        path="src/auth.py",
        line=42,
        severity="HIGH",
        class_="hardcoded-secret",
        description="Hardcoded password literal detected",
        remediation="Load from environment variable",
    )


def _valid_ai_payload(tag: str) -> dict[str, Any]:
    return {
        "summary": f"Анализ выполнен через {tag}: выявлена критичная проблема.",
        "items": [
            {
                "finding_ref": 0,
                "explanation": f"[{tag}] В файле src/auth.py на строке 42 обнаружен захардкоженный секрет.",
                "risk": "Высокий риск компрометации учётных данных и несанкционированного доступа.",
                "priority": "HIGH",
                "fix_steps": ["Вынесите пароль в переменную окружения и перевыпустите секрет."],
            }
        ],
    }


def test_default_unconfigured_honest_state_and_gemini_env_default(ai_client, monkeypatch):
    client, user, _ = ai_client
    r_none = client.get("/api/integrations")
    assert r_none.status_code == 200
    ai_info = r_none.json()["ai"]
    assert ai_info["configured"] is False
    assert ai_info["provider"] == "gemini"

    # With no default key and no user key, AiExplainNode must return honest error without fallback
    node = AiExplainNode()
    ctx = NodeContext(run_id="r-unconf", node_id="ai1", workspace=str(user["id"]), owner_id=user["id"])
    import asyncio

    out = asyncio.run(node.run(ctx, {"findings": [_sample_finding()]}, AiParams()))
    report = out["report"]
    assert report["items"] == []
    assert report["validation"]["mode"] == "error"
    assert report["validation"]["passed"] is False
    assert "не настроен" in report["validation"]["error"].lower() or "ключ" in report["validation"]["error"].lower()

    # When GEMINI_API_KEY is set on backend, Gemini becomes active default
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDefaultServerKey12345")
    get_settings.cache_clear()
    r_env = client.get("/api/integrations")
    assert r_env.status_code == 200
    assert r_env.json()["ai"]["configured"] is True
    assert r_env.json()["ai"]["provider"] == "gemini"
    assert r_env.json()["ai"]["source"] == "env"


def test_providers_catalog_and_custom_adapter_registration():
    mgr = AIProviderManager()
    ids = {p["id"] for p in mgr.list_specs()}
    for expected in ("gemini", "gigachat", "openai", "anthropic", "deepseek", "openrouter", "ollama", "vllm", "openai_compatible"):
        assert expected in ids

    class DummyCustomAdapter(BaseProviderAdapter):
        async def list_models(self, api_key, base_url):
            return ["custom-v1"]

        async def test_connection(self, api_key, model, base_url):
            return {"ok": True, "models": ["custom-v1"], "detail": "ok"}

        async def explain(self, canonical_findings, *, api_key, model, base_url, timeout=60.0):
            return json.dumps(_valid_ai_payload("custom"))

        async def generate_text(self, *, system_prompt, user_prompt, api_key, model, base_url, timeout=20.0):
            return "{}"

    spec = ProviderSpec(
        id="custom_test",
        label="Custom Test",
        adapter_kind="custom",
        auth_type="api_key",
        default_base_url="https://example.invalid/v1",
        default_model="custom-v1",
    )
    mgr._adapters[spec.id] = DummyCustomAdapter(spec)
    assert isinstance(mgr.get_adapter("custom_test"), DummyCustomAdapter)


@pytest.mark.asyncio
async def test_all_adapters_explain_and_live_model_discovery(ai_client, tmp_path):
    client, user, _ = ai_client
    ctx = NodeContext(run_id="r-adapters", node_id="ai1", workspace=str(tmp_path), owner_id=user["id"])
    node = AiExplainNode()

    # 1. Gemini (via AI_CODE_CHECKER mock)
    client.put(
        "/api/integrations/ai",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "AIzaSyUserGeminiKey999"},
    )
    with patch("app.nodes.ai.explain._call_ai_code_checker", new=AsyncMock(return_value=_valid_ai_payload("Gemini"))):
        res_gem = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_gem["report"]["validation"]["passed"] is True
    assert res_gem["report"]["validation"]["provider"] == "gemini"
    assert "Gemini" in res_gem["report"]["items"][0]["explanation"]

    # 2. GigaChat OAuth2 (Basic -> Bearer -> /models + /chat/completions)
    def gigachat_transport(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/v2/oauth"):
            assert request.headers["Authorization"].startswith("Basic ")
            return httpx.Response(200, json={"access_token": "gc_access_tok_xyz"})
        if request.url.path.endswith("/models"):
            assert request.headers["Authorization"] == "Bearer gc_access_tok_xyz"
            return httpx.Response(200, json={"data": [{"id": "GigaChat"}, {"id": "GigaChat-Pro"}]})
        if request.url.path.endswith("/chat/completions"):
            assert request.headers["Authorization"] == "Bearer gc_access_tok_xyz"
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": json.dumps(_valid_ai_payload("GigaChat"))}}]},
            )
        return httpx.Response(404)

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(gigachat_transport)
        r_models = client.post(
            "/api/integrations/ai/models",
            json={"provider": "gigachat", "base_url": "https://gigachat.devices.sberbank.ru/api/v1", "api_key": "clientid:clientsecret"},
        )
        assert r_models.status_code == 200
        assert r_models.json()["ok"] is True
        assert "GigaChat-Pro" in r_models.json()["models"]

        client.put(
            "/api/integrations/ai",
            json={
                "provider": "gigachat",
                "model": "GigaChat-Pro",
                "base_url": "https://gigachat.devices.sberbank.ru/api/v1",
                "api_key": "clientid:clientsecret",
                "activate": True,
            },
        )
        res_gc = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_gc["report"]["validation"]["passed"] is True
    assert res_gc["report"]["validation"]["provider"] == "gigachat"
    assert res_gc["report"]["validation"]["provider_label"] == "Sber GigaChat"
    assert "GigaChat" in res_gc["report"]["items"][0]["explanation"]

    # 3. Anthropic Claude (/v1/messages)
    def claude_transport(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "sk-ant-test-key-12345"
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "claude-3-5-haiku-latest"}]})
        if request.url.path.endswith("/messages"):
            return httpx.Response(
                200,
                json={"content": [{"type": "text", "text": json.dumps(_valid_ai_payload("Claude"))}]},
            )
        return httpx.Response(404)

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(claude_transport)
        client.put(
            "/api/integrations/ai",
            json={"provider": "anthropic", "model": "claude-3-5-haiku-latest", "api_key": "sk-ant-test-key-12345"},
        )
        res_cl = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_cl["report"]["validation"]["passed"] is True
    assert res_cl["report"]["validation"]["provider"] == "anthropic"
    assert "Claude" in res_cl["report"]["items"][0]["explanation"]

    # 4. OpenAI-compatible (OpenAI) & 5. Ollama (local without key)
    client.put(
        "/api/integrations/ai",
        json={"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-openai-test-987654"},
    )
    with patch("app.nodes.ai.llm_client.chat_completion", new=AsyncMock(return_value=json.dumps(_valid_ai_payload("OpenAI")))):
        res_oai = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_oai["report"]["validation"]["passed"] is True
    assert res_oai["report"]["validation"]["provider"] == "openai"

    client.put(
        "/api/integrations/ai",
        json={"provider": "ollama", "model": "llama3.2", "base_url": "http://localhost:11434/v1", "api_key": ""},
    )
    with patch("app.nodes.ai.llm_client.chat_completion", new=AsyncMock(return_value=json.dumps(_valid_ai_payload("Ollama")))):
        res_oll = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_oll["report"]["validation"]["passed"] is True
    assert res_oll["report"]["validation"]["provider"] == "ollama"

    # Zero-restart quick switching back to gigachat without re-entering secret!
    r_act = client.post("/api/integrations/ai/activate", json={"provider": "gigachat"})
    assert r_act.status_code == 200
    assert r_act.json()["provider"] == "gigachat"
    assert r_act.json()["configured"] is True

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(gigachat_transport)
        res_switched = await node.run(ctx, {"findings": [_sample_finding()]}, AiParams())
    assert res_switched["report"]["validation"]["provider"] == "gigachat"


def test_bad_key_unavailable_model_and_no_fallback_on_error(ai_client, tmp_path):
    client, user, _ = ai_client

    # Bad key -> 401 -> test fails clearly and never echoes plaintext key
    secret = "AIzaSyInvalidSecret99999"

    def bad_gem_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": f"Invalid key {secret}"}})

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(bad_gem_transport)
        r_test = client.post(
            "/api/integrations/ai/test",
            json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": secret},
        )
    assert r_test.status_code == 200
    assert r_test.json()["ok"] is False
    assert secret not in (r_test.json().get("detail") or "")

    # Unavailable model -> key valid, model missing from /models
    def missing_model_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"models": [{"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]}]},
        )

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(missing_model_transport)
        r_m = client.post(
            "/api/integrations/ai/test",
            json={"provider": "gemini", "model": "gemini-nonexistent-99", "api_key": "AIzaSyValidKey12345"},
        )
    assert r_m.status_code == 200
    assert r_m.json()["ok"] is False
    assert "недоступна" in r_m.json()["detail"].lower()

    # Save valid openai profile then simulate LLM runtime 500 -> NO fallback, strict error
    client.put("/api/integrations/ai", json={"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-err-12345678"})
    node = AiExplainNode()
    ctx = NodeContext(run_id="r-err", node_id="ai1", workspace=str(tmp_path), owner_id=user["id"])
    import asyncio

    with patch("app.nodes.ai.llm_client.chat_completion", new=AsyncMock(side_effect=RuntimeError("Upstream 500"))):
        out = asyncio.run(node.run(ctx, {"findings": [_sample_finding()]}, AiParams()))
    assert out["report"]["items"] == []
    assert out["report"]["validation"]["mode"] == "error"
    assert out["report"]["validation"]["passed"] is False


def test_secret_encryption_user_isolation_and_profile_deletion(ai_client):
    client, user, _ = ai_client
    raw_key = "sk-ant-super-secret-xyz-999"
    r_save = client.put(
        "/api/integrations/ai",
        json={"provider": "anthropic", "model": "claude-3-5-haiku-latest", "api_key": raw_key},
    )
    assert r_save.status_code == 200
    assert raw_key not in json.dumps(r_save.json())

    # Check DB stores Fernet-encrypted value, not plaintext
    with Session(db_mod.get_engine()) as session:
        rows = session.exec(select(IntegrationSetting)).all()
        assert rows
        for row in rows:
            if row.encrypted_secret:
                assert raw_key not in row.encrypted_secret
                assert decrypt(row.encrypted_secret) == raw_key

    # Second user must be completely isolated from first user's keys
    with TestClient(app) as client2:
        authenticate_client(client2, email="ai_owner_2@florabyte.local")
        r2 = client2.get("/api/integrations/ai/providers")
        assert r2.status_code == 200
        assert r2.json()["profiles"] == []
        assert r2.json()["active"]["configured"] is False

    # Delete specific provider profile for user 1
    r_del = client.delete("/api/integrations/ai?provider=anthropic")
    assert r_del.status_code == 200
    r_prov = client.get("/api/integrations/ai/providers")
    assert all(p["provider"] != "anthropic" for p in r_prov.json()["profiles"])


@pytest.mark.asyncio
async def test_unified_exports_markdown_pdf_and_telegram(ai_client, tmp_path):
    client, user, _ = ai_client
    client.put(
        "/api/integrations/ai",
        json={"provider": "anthropic", "model": "claude-3-5-haiku-latest", "api_key": "sk-ant-export-test-123"},
    )
    ctx = NodeContext(run_id="r-export", node_id="ai1", workspace=str(tmp_path), owner_id=user["id"])

    def claude_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": json.dumps(_valid_ai_payload("Claude"))}]},
        )

    with patch("app.nodes.ai.providers.httpx.AsyncClient") as mock_http:
        mock_http.side_effect = _mock_async_client(claude_transport)
        ai_out = await AiExplainNode().run(ctx, {"findings": [_sample_finding()]}, AiParams())

    exported = await ReportExportNode().run(
        ctx,
        {"findings": [_sample_finding()], "report": ai_out["report"]},
        ExportParams(),
    )
    rep = exported["report"]

    # Markdown includes provider label, explanation, risk, priority, and fix steps
    md = rep["report_md"]
    assert "Anthropic Claude" in md
    assert "Приоритет исправления" in md
    assert "Возможные последствия" in md

    # PDF includes provider label and priority
    pdf_bytes = render_report_pdf("r-export", "success", rep["findings"], ai_report=rep)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"Anthropic Claude" in pdf_bytes
    assert b"Priority: HIGH" in pdf_bytes

    # Telegram message includes provider label and priority
    tg_text = _format_message(rep, "r-export")
    assert "Anthropic Claude" in tg_text
    assert "Приоритет: HIGH" in tg_text
