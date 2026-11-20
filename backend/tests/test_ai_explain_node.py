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
async def test_ai_explain_fallback_when_no_key(tmp_path, monkeypatch):
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
    assert rep["validation"]["mode"] == "fallback"
    assert len(rep["items"]) == 1


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
    assert rep["validation"]["passed"] is True
    assert rep["validation"]["dropped_cve"] == 1
    assert "CVE-2022-42889" in rep["items"][0]["explanation"]
    assert "CVE-2099-12345" not in rep["items"][0]["explanation"]
    assert rep["items"][0]["fix_steps"] == ["Обновить commons-text до 1.10.0"]
