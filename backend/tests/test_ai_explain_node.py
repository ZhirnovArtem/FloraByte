from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from app.core.models import Finding
from app.nodes.ai.explain import AiExplainNode, Params
from app.nodes.base import NodeContext


@pytest.mark.asyncio
async def test_ai_explain_empty_findings(tmp_path):
    node = AiExplainNode()
    ctx = NodeContext(run_id="r1", node_id="ai1", workspace=tmp_path)
    out = await node.run(ctx, {"findings": []}, Params())
    rep = out["report"]
    assert rep["items"] == []
    assert rep["validation"]["mode"] == "empty"
    assert rep["validation"]["passed"] is True


@pytest.mark.asyncio
async def test_ai_explain_error_when_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    from app.config import get_settings

    get_settings.cache_clear()
    node = AiExplainNode()
    ctx = NodeContext(run_id="r2", node_id="ai1", workspace=tmp_path)
    finding = Finding(
        category="SECRET",
        path="Cfg.kt",
        **{"class": "password"},
        line=4,
        severity="HIGH",
        evidence='val p = "****"',
    )
    out = await node.run(ctx, {"findings": [finding]}, Params())
    rep = out["report"]
    assert rep["status"] == "error"
    assert rep["summary"] == ""
    assert rep["items"] == []
    assert rep["validation"]["passed"] is False
    assert rep["validation"]["mode"] == "error"
    assert rep["validation"]["ai_status"] == "Ошибка"
    assert rep["validation"]["error"]
    assert len(rep["findings"]) == 1


@pytest.mark.asyncio
async def test_ai_explain_rejects_unavailable_model_and_empty_response(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaFakeTestKey1234567890")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.nodes.ai.explain import _run_checker_batch_without_env_mutation
    import services.ai_service as ai_svc

    # Selected model not available -> explicit error
    with patch("services.ai_service._list_generation_models", new=AsyncMock(return_value={"gemini-3.5-flash-lite"})):
        with pytest.raises(ai_svc.AIServiceError, match="недоступна"):
            await _run_checker_batch_without_env_mutation(
                [{"rule_id": "r", "file": "a.kt", "line": 1, "severity": "HIGH", "message": "msg"}],
                api_key="AIzaFakeTestKey1234567890",
                model="nonexistent-gemini-model",
            )

    # Empty/invalid response from model -> error mode, zero fake items, key redacted
    node = AiExplainNode()
    ctx = NodeContext(run_id="r2b", node_id="ai1", workspace=tmp_path)
    finding = Finding(category="SAST", path="A.kt", **{"class": "sql"}, line=2, severity="HIGH")
    with patch(
        "app.nodes.ai.explain._call_ai_code_checker",
        new=AsyncMock(side_effect=RuntimeError("Gemini failed for AIzaFakeTestKey1234567890")),
    ):
        out = await node.run(ctx, {"findings": [finding]}, Params())
    rep = out["report"]
    assert rep["validation"]["mode"] == "error"
    assert rep["validation"]["ai_status"] == "Ошибка"
    assert rep["items"] == []
    assert rep["summary"] == ""
    assert "AIzaFakeTestKey1234567890" not in rep["validation"]["error"]


@pytest.mark.asyncio
async def test_ai_explain_does_not_mutate_os_environ(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    from app.nodes.ai.explain import _run_checker_batch_without_env_mutation

    # Verify calling internal runner with explicit key leaves os.environ clean
    with patch("services.ai_service._list_generation_models", new=AsyncMock(return_value={"gemini-2.0-flash"})), patch(
        "services.ai_service._generate_with_retry",
        new=AsyncMock(
            return_value={
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [
                                {
                                    "text": '{"status":"ok","summary":"ok","findings":[{"rule_id":"r","file":"a.kt","line":1,"severity":"HIGH","explanation":"exp","risk":"risk","recommendation":"fix"}]}'
                                }
                            ]
                        },
                    }
                ]
            }
        ),
    ):
        res = await _run_checker_batch_without_env_mutation(
            [{"rule_id": "r", "file": "a.kt", "line": 1, "severity": "HIGH", "message": "msg"}],
            api_key="explicit-key-123",
            model="gemini-2.0-flash",
        )
    assert res["status"] == "ok"
    assert "GEMINI_API_KEY" not in os.environ
    assert "GEMINI_MODEL" not in os.environ


@pytest.mark.asyncio
async def test_ai_explain_uses_ai_code_checker_and_validates(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    from app.config import get_settings

    get_settings.cache_clear()

    mock_ai_report = {
        "status": "ok",
        "summary": "Обнаружена 1 проблема SCA.",
        "findings": [
            {
                "rule_id": "sca.vulnerable_dependency",
                "file": "build.gradle.kts",
                "line": 31,
                "severity": "CRITICAL",
                "explanation": "Уязвимость CVE-2022-42889 (а не выдуманная CVE-2099-12345).",
                "risk": "RCE",
                "recommendation": "Обновить commons-text до 1.10.0",
            }
        ],
    }

    node = AiExplainNode()
    ctx = NodeContext(run_id="r3", node_id="ai1", workspace=tmp_path)
    finding = Finding(
        category="SCA",
        path="build.gradle.kts",
        line=31,
        group="org.apache.commons",
        artifact="commons-text",
        version="1.9",
        advisoryId="CVE-2022-42889",
        severity="CRITICAL",
        rule_id="sca.vulnerable_dependency",
    )

    with patch("services.ai_service.analyze_findings", new=AsyncMock(return_value=mock_ai_report)):
        out = await node.run(ctx, {"findings": [finding]}, Params())

    rep = out["report"]
    assert rep["validation"]["mode"] == "llm"
    assert rep["validation"]["ai_status"] == "Успешно"
    assert rep["validation"]["passed"] is True
    assert rep["validation"]["dropped_cve"] == 1
    assert rep["validation"]["vuln_db_checked"] is True
    assert "CVE-2022-42889" in rep["items"][0]["explanation"]
    assert "CVE-2099-12345" not in rep["items"][0]["explanation"]
    assert rep["items"][0]["fix_steps"] == ["Обновить commons-text до 1.10.0"]


@pytest.mark.asyncio
async def test_ai_explain_openai_compatible_ollama_retry_and_secret_redaction(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    from app.config import get_settings

    get_settings.cache_clear()
    captured_payloads: list[str] = []

    async def fake_chat_completion(messages, *, model=None, api_key=None, base_url=None, **kwargs):
        captured_payloads.append(messages[-1]["content"])
        if len(captured_payloads) == 1:
            return "not-valid-json-first-try"
        return (
            '```json\n'
            '{"summary": "Найдена 1 проблема.", "items": ['
            '{"finding_ref": 0, "explanation": "Найден встроенный секрет в Cfg.kt:5.", '
            '"risk": "HIGH", "fix_steps": ["Вынести в env"]}]}\n'
            '```'
        )

    node = AiExplainNode()
    ctx = NodeContext(run_id="r4", node_id="ai1", workspace=tmp_path)
    finding = Finding(
        category="SECRET",
        path="Cfg.kt",
        **{"class": "api-key"},
        line=5,
        severity="HIGH",
        description="api_key='sk-TopSecretValue1234567890abcd'",
        evidence='val k = "sk-TopSecretValue1234567890abcd"',
    )

    with patch("app.nodes.ai.llm_client.chat_completion", new=fake_chat_completion):
        out = await node.run(
            ctx,
            {"findings": [finding]},
            Params(provider="openai_compatible", base_url="http://localhost:11434/v1", model="llama3.2"),
        )

    rep = out["report"]
    assert rep["validation"]["mode"] == "llm"
    assert rep["validation"]["retried"] is True
    assert rep["validation"]["passed"] is True
    assert len(captured_payloads) == 2
    for payload in captured_payloads:
        assert "sk-TopSecretValue1234567890abcd" not in payload

