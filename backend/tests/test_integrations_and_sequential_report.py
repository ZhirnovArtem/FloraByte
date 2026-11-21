"""Tests for sequential AI->Export->Telegram report, Telegram 404 diagnostics, and 1-time integrations."""

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
from app.main import app
from app.nodes.notify.telegram import normalize_bot_token


@pytest.fixture()
def integ_client(tmp_path, monkeypatch):
    db_file = tmp_path / "integ.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
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
        yield client
    db_mod._engine = None
    get_settings.cache_clear()


def _sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/settings.gradle.kts", 'rootProject.name = "proj"\n')
        zf.writestr(
            "proj/src/main/kotlin/Main.kt",
            'val password = "hardcoded_secret_integ_999"\n',
        )
    return buf.getvalue()


def test_telegram_token_normalization_and_404_diagnostics(integ_client):
    assert normalize_bot_token("  bot12345678:AAExampleValidTokenValue12345  ") == "12345678:AAExampleValidTokenValue12345"

    # Malformed token rejected cleanly before hitting Telegram
    bad = integ_client.post(
        "/api/integrations/telegram/test",
        json={"bot_token": "not-a-valid-token", "chat_id": "123"},
    )
    assert bad.status_code == 200
    assert bad.json()["ok"] is False
    assert "Неверный формат токена" in bad.json()["error"]

    # HTTP 404 produces clear Russian diagnostic without leaking token
    fake_token = "999888777:AAFakeSecretTokenValue1234567890"

    async def fake_get(self, url, **kwargs):
        return httpx.Response(404, json={"ok": False, "error_code": 404, "description": "Not Found"}, request=httpx.Request("GET", url))

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        res_404 = integ_client.post(
            "/api/integrations/telegram/test",
            json={"bot_token": fake_token, "chat_id": "555"},
        )
    assert res_404.status_code == 200
    body = res_404.json()
    assert body["ok"] is False
    assert "HTTP 404" in body["error"]
    assert fake_token not in body["error"]


def test_one_time_integrations_and_sequential_ai_export_telegram_pipeline(integ_client):
    fake_ai_key = "AIzaFakeGeminiKeyIntegrationTest12345"
    fake_tg_token = "123456789:AAFakeTelegramTokenIntegration12345"

    # 1. Save AI integration once
    put_ai = integ_client.put(
        "/api/integrations/ai",
        json={
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "base_url": "",
            "api_key": fake_ai_key,
        },
    )
    assert put_ai.status_code == 200
    assert put_ai.json()["configured"] is True
    assert fake_ai_key not in put_ai.text

    # 2. Save Telegram integration once (with mocked getMe + getChat verification, auto_send=False for on-demand test)
    async def fake_tg_get(self, url, **kwargs):
        if "/getMe" in str(url):
            return httpx.Response(200, json={"ok": True, "result": {"username": "florabyte_test_bot"}}, request=httpx.Request("GET", url))
        return httpx.Response(200, json={"ok": True, "result": {"id": 777111, "title": "SecOps"}}, request=httpx.Request("GET", url))

    with patch.object(httpx.AsyncClient, "get", new=fake_tg_get):
        put_tg = integ_client.put(
            "/api/integrations/telegram",
            json={
                "bot_token": f"bot{fake_tg_token}",
                "chat_id": "777111",
                "auto_send": False,
                "verify": True,
            },
        )
    assert put_tg.status_code == 200
    tg_info = put_tg.json()
    assert tg_info["configured"] is True
    assert tg_info["bot_username"] == "florabyte_test_bot"
    assert tg_info["auto_send"] is False
    assert fake_tg_token not in put_tg.text

    # 3. Upload ZIP and run sequential pipeline: Merge -> AI Explain -> Export Report -> Telegram
    up_id = integ_client.post("/api/uploads", files={"file": ("proj.zip", _sample_zip(), "application/zip")}).json()["upload_id"]
    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}},
            {"id": "m1", "type": "findings.merge", "params": {}},
            {"id": "ai1", "type": "ai.explain", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
            {"id": "tg1", "type": "notify.telegram", "params": {}},
        ],
        "edges": [
            {"id": "ed1", "source": "t1", "target": "s1"},
            {"id": "ed2", "source": "s1", "target": "sc1"},
            {"id": "ed3", "source": "sc1", "target": "m1", "targetHandle": "a"},
            {"id": "ed4", "source": "m1", "sourceHandle": "findings", "target": "ai1", "targetHandle": "findings"},
            {"id": "ed5", "source": "ai1", "sourceHandle": "report", "target": "e1", "targetHandle": "report"},
            {"id": "ed6", "source": "e1", "sourceHandle": "report", "target": "tg1", "targetHandle": "report"},
        ],
    }

    wf_id = integ_client.post("/api/workflows", json={"name": "seq-pipeline", "graph_json": graph}).json()["id"]

    sent_payloads: list[dict] = []

    async def fake_tg_post(self, url, json=None, **kwargs):
        sent_payloads.append({"url": str(url), "json": json})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 42}}, request=httpx.Request("POST", url))

    fake_ai_output = {
        "summary": "Обнаружен жёстко зашитый пароль в исходном коде.",
        "items": [
            {
                "finding_ref": 0,
                "explanation": "Пароль хранится открыто в Kotlin-файле.",
                "risk": "Компрометация учётных данных.",
                "fix_steps": ["Перенести секрет в переменные окружения."],
            }
        ],
    }

    with (
        patch("app.nodes.ai.explain._call_ai_code_checker", new=AsyncMock(return_value=fake_ai_output)),
        patch.object(httpx.AsyncClient, "post", new=fake_tg_post),
    ):
        run_id = integ_client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    run = integ_client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "success"
    assert run["ai_report"]["validation"]["ai_status"] == "LLM"

    # Verify report.json still matches organisers' format
    rep_json = integ_client.get(f"/api/runs/{run_id}/report.json").json()
    assert len(rep_json["findings"]) == 1
    assert "hardcoded_secret_integ_999" not in str(rep_json)

    # Verify report.md includes AI explanations, consequences, and fix steps
    rep_md = integ_client.get(f"/api/runs/{run_id}/report.md").text
    assert "**AI-анализ:** LLM" in rep_md
    assert "Пароль хранится открыто в Kotlin-файле." in rep_md
    assert "Компрометация учётных данных." in rep_md
    assert "Перенести секрет в переменные окружения." in rep_md

    # Verify Telegram received unified report + AI recommendations and used normalized token
    assert len(sent_payloads) == 1
    assert sent_payloads[0]["url"] == f"https://api.telegram.org/bot{fake_tg_token}/sendMessage"
    assert "AI-рекомендации:" in sent_payloads[0]["json"]["text"]

    # Verify on-demand send endpoint works as well
    with patch.object(httpx.AsyncClient, "post", new=fake_tg_post):
        ondemand = integ_client.post(f"/api/integrations/telegram/send-run/{run_id}")
    assert ondemand.status_code == 200
    assert ondemand.json()["sent"] is True
    assert len(sent_payloads) == 2


def test_ai_status_error_vs_fallback(integ_client):
    up_id = integ_client.post("/api/uploads", files={"file": ("proj.zip", _sample_zip(), "application/zip")}).json()["upload_id"]
    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
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
    }
    wf_id = integ_client.post("/api/workflows", json={"name": "ai-status", "graph_json": graph}).json()["id"]

    # Case A: No AI key configured -> ai_status == "Fallback"
    r1 = integ_client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    run1 = integ_client.get(f"/api/runs/{r1}").json()
    assert run1["ai_report"]["validation"]["ai_status"] == "Fallback"

    # Case B: AI key configured, but API raises error -> ai_status == "Ошибка"
    integ_client.put(
        "/api/integrations/ai",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "base_url": "", "api_key": "AIzaBadKey1234567890"},
    )
    with patch("app.nodes.ai.explain._call_ai_code_checker", new=AsyncMock(side_effect=RuntimeError("403 API key invalid"))):
        r2 = integ_client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    run2 = integ_client.get(f"/api/runs/{r2}").json()
    assert run2["ai_report"]["validation"]["ai_status"] == "Ошибка"
