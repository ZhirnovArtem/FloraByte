"""Tests for upgraded AI workflow generation, cron/email parsing, conditional wiring, and notify.email."""

from __future__ import annotations

import io
import json
import zipfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

import app.core.db as db_mod
from app.config import get_settings
from app.engine.graph import validate_graph
from app.main import app
from app.nodes.registry import NODE_REGISTRY
from tests.conftest import authenticate_client


@pytest.fixture()
def ai_gen_client(tmp_path, monkeypatch):
    db_file = tmp_path / "ai_gen.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    monkeypatch.setenv("APP_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir(exist_ok=True)
    settings.upload_dir.mkdir(exist_ok=True)

    db_mod._engine = None
    SQLModel.metadata.drop_all(db_mod.get_engine())
    db_mod.init_db()
    with TestClient(app) as client:
        authenticate_client(client, email="aigen@example.com", password="StrongPassword123!")
        yield client
    db_mod._engine = None
    get_settings.cache_clear()


def _sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/app.py", 'API_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n')
    return buf.getvalue()


def test_prompt_daily_14_repo_secrets_email_parses_cron_and_saves_valid_graph(ai_gen_client: TestClient):
    res = ai_gen_client.post(
        "/api/ai/generate-workflow",
        json={
            "prompt": (
                "Каждый день в 14:00 проверяй код из репозитория "
                "https://github.com/TBagirov/training на наличие секретов "
                "и отправляй отчет на почту sec@company.com"
            )
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]
    graph = data["graph"]
    validate_graph(graph, NODE_REGISTRY)

    by_type = {n["type"]: n for n in graph["nodes"]}
    assert "trigger.schedule" in by_type
    assert by_type["trigger.schedule"]["params"]["cron"] == "0 14 * * *"
    assert "source.git_clone" in by_type
    assert by_type["source.git_clone"]["params"]["url"] == "https://github.com/TBagirov/training"
    assert "scanner.secrets" in by_type
    assert "notify.email" in by_type
    assert by_type["notify.email"]["params"]["to_email"] == "sec@company.com"

    # Generated workflow can be saved directly via /api/workflows without manual fixes
    saved = ai_gen_client.post(
        "/api/workflows",
        json={"name": data["name"], "graph_json": graph},
    )
    assert saved.status_code == 200, saved.text


def test_conditional_critical_prompt_places_if_else_before_export_and_executes(ai_gen_client: TestClient):
    res = ai_gen_client.post(
        "/api/ai/generate-workflow",
        json={"prompt": "Проверь архив на секреты и если есть критические уязвимости отправь на почту"},
    )
    assert res.status_code == 200
    graph = res.json()["graph"]
    validate_graph(graph, NODE_REGISTRY)

    by_type = {n["type"]: n for n in graph["nodes"]}
    assert "logic.if_else" in by_type
    assert by_type["logic.if_else"]["params"]["left"] == "findings.by_severity.CRITICAL"
    assert "notify.email" in by_type

    # Swap source to uploaded zip and execute end-to-end
    up_id = ai_gen_client.post("/api/uploads", files={"file": ("app.zip", _sample_zip(), "application/zip")}).json()["upload_id"]
    for n in graph["nodes"]:
        if n["type"] == "source.upload_zip":
            n["params"]["upload_id"] = up_id
        if n["type"] == "notify.email":
            n["params"]["dry_run"] = True

    wf_id = ai_gen_client.post("/api/workflows", json={"name": "ai-cond", "graph_json": graph}).json()["id"]
    run_res = ai_gen_client.post(f"/api/workflows/{wf_id}/run?wait=true")
    assert run_res.status_code == 200, run_res.text
    run_data = ai_gen_client.get(f"/api/runs/{run_res.json()['run_id']}").json()
    assert run_data["status"] == "success"


def test_llm_invalid_cyclic_graph_falls_back_cleanly_while_valid_llm_graph_accepted(ai_gen_client: TestClient):
    class FakeAdapter:
        def validate_config(self, api_key, model, base_url):
            return None

        async def generate_text(self, **kwargs):
            # Return an invalid cyclic graph first -> must be rejected by validate_graph and fall back!
            return json.dumps({
                "name": "Bad Cyclic",
                "nodes": [
                    {"id": "a", "type": "trigger.manual", "params": {}},
                    {"id": "b", "type": "scanner.secrets", "params": {}},
                ],
                "edges": [
                    {"id": "e1", "source": "a", "target": "b"},
                    {"id": "e2", "source": "b", "target": "a"},
                ],
            })

    with patch("app.api.ai_generator.provider_manager.resolve_runtime_config", return_value=("gemini", "k", "m", "u")):
        with patch("app.api.ai_generator.provider_manager.get_adapter", return_value=FakeAdapter()):
            r = ai_gen_client.post("/api/ai/generate-workflow", json={"prompt": "проверь git на секреты и на почту"})
            assert r.status_code == 200
            body = r.json()
            assert body["mode"] == "rule_based"
            validate_graph(body["graph"], NODE_REGISTRY)

    class GoodAdapter:
        def validate_config(self, api_key, model, base_url):
            return None

        async def generate_text(self, **kwargs):
            return json.dumps({
                "name": "LLM Ежедневная проверка",
                "summary": "Создано LLM",
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "0 14 * * *"}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training", "branch": "main"}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "exp1", "type": "findings.export", "params": {}},
                    {"id": "em1", "type": "notify.email", "params": {"to_email": "sec@company.com", "dry_run": True}},
                ],
                "edges": [
                    {"id": "e1", "source": "t1", "target": "s1"},
                    {"id": "e2", "source": "s1", "target": "sc1"},
                    {"id": "e3", "source": "sc1", "target": "exp1"},
                    {"id": "e4", "source": "exp1", "target": "em1"},
                ],
            })

    with patch("app.api.ai_generator.provider_manager.resolve_runtime_config", return_value=("gemini", "k", "m", "u")):
        with patch("app.api.ai_generator.provider_manager.get_adapter", return_value=GoodAdapter()):
            r2 = ai_gen_client.post("/api/ai/generate-workflow", json={"prompt": "Каждый день в 14:00 проверяй репозиторий и шли на почту"})
            assert r2.status_code == 200
            body2 = r2.json()
            assert body2["mode"] == "llm"
            assert body2["provider"] == "gemini"
            assert body2["name"] == "LLM Ежедневная проверка"
            validate_graph(body2["graph"], NODE_REGISTRY)


def test_email_integration_smtp_ssl_and_resend_and_send_run(ai_gen_client: TestClient):
    from unittest.mock import MagicMock

    # 1. Save Resend email integration (encrypted per-user)
    saved = ai_gen_client.put(
        "/api/integrations/email",
        json={
            "transport": "resend",
            "from_email": "onboarding@resend.dev",
            "default_to": "reports@company.com",
            "secret": "re_test_1234567890abcdef",
            "enabled": True,
        },
    )
    assert saved.status_code == 200, saved.text
    st = saved.json()
    assert st["configured"] is True
    assert st["transport"] == "resend"
    assert st["default_to"] == "reports@company.com"
    assert "re_test_1234567890abcdef" not in json.dumps(st)

    # 2. AI generator automatically sets dry_run=False and fills default_to from saved Email integration
    gen = ai_gen_client.post(
        "/api/ai/generate-workflow",
        json={"prompt": "Проверь архив на секреты и отправь отчет на почту"},
    )
    assert gen.status_code == 200
    g = gen.json()["graph"]
    email_node = next(n for n in g["nodes"] if n["type"] == "notify.email")
    assert email_node["params"]["dry_run"] is False
    assert email_node["params"]["to_email"] == "reports@company.com"

    # 3. Execute workflow with mocked Resend HTTPS POST and verify email was actually sent
    up_id = ai_gen_client.post("/api/uploads", files={"file": ("app.zip", _sample_zip(), "application/zip")}).json()["upload_id"]
    for n in g["nodes"]:
        if n["type"] == "source.upload_zip":
            n["params"]["upload_id"] = up_id

    sent_payloads = []

    class FakeResp:
        status_code = 200
        text = '{"id": "email_123"}'

        def json(self):
            return {"id": "email_123"}

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent_payloads.append({"url": url, "headers": headers, "json": json})
            return FakeResp()

    wf_id = ai_gen_client.post("/api/workflows", json={"name": "email-resend", "graph_json": g}).json()["id"]
    with patch("app.nodes.notify.email.httpx.AsyncClient", FakeAsyncClient):
        run_res = ai_gen_client.post(f"/api/workflows/{wf_id}/run?wait=true")
        assert run_res.status_code == 200
        run_id = run_res.json()["run_id"]
        run_data = ai_gen_client.get(f"/api/runs/{run_id}").json()
        assert run_data["status"] == "success"
        assert len(sent_payloads) == 1
        assert sent_payloads[0]["url"] == "https://api.resend.com/emails"
        assert sent_payloads[0]["json"]["to"] == ["reports@company.com"]
        assert "FloraByte Security Report" in sent_payloads[0]["json"]["text"]

        # On-demand send-run endpoint also works
        sr = ai_gen_client.post(f"/api/integrations/email/send-run/{run_id}")
        assert sr.status_code == 200
        assert sr.json()["sent"] is True
        assert len(sent_payloads) == 2

    # 4. SMTP port 465 uses SMTP_SSL cleanly
    smtp_save = ai_gen_client.put(
        "/api/integrations/email",
        json={
            "transport": "smtp",
            "smtp_host": "smtp.yandex.ru",
            "smtp_port": 465,
            "smtp_user": "sec@yandex.ru",
            "from_email": "sec@yandex.ru",
            "default_to": "reports@company.com",
            "secret": "app-pass-465",
            "enabled": True,
        },
    )
    assert smtp_save.status_code == 200
    ssl_mock = MagicMock()
    with patch("app.nodes.notify.email.smtplib.SMTP_SSL", return_value=ssl_mock) as smtp_ssl_cls:
        test_res = ai_gen_client.post(
            "/api/integrations/email/test",
            json={"transport": "smtp", "smtp_host": "smtp.yandex.ru", "smtp_port": 465, "default_to": "reports@company.com"},
        )
        assert test_res.status_code == 200
        assert test_res.json()["ok"] is True
        smtp_ssl_cls.assert_called_once_with("smtp.yandex.ru", 465, timeout=15)

