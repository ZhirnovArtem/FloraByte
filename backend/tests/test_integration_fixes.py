"""Regression checks for fixed bundled workflows and AI source references."""

import json
from pathlib import Path

import app.nodes  # noqa: F401
from app.engine.graph import validate_graph
from app.nodes.registry import NODE_REGISTRY
from app.nodes.ai.validator import validate_llm_response


TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


def test_all_bundled_templates_are_valid_graphs():
    for file in sorted(TEMPLATES.glob("*.json")):
        validate_graph(json.loads(file.read_text(encoding="utf-8"))["graph"], NODE_REGISTRY)


def test_full_security_scan_routes_ai_report_to_both_notification_branches():
    graph = json.loads((TEMPLATES / "full-security-scan.json").read_text(encoding="utf-8"))["graph"]
    edges = graph["edges"]
    assert any(e["source"] == "m1" and e["target"] == "ai1" for e in edges)
    assert not any(e["source"] == "e1" and e["target"] == "ai1" for e in edges)
    assert any(e["source"] == "if1" and e.get("sourceHandle") == "true" for e in edges)
    assert any(e["source"] == "if1" and e.get("sourceHandle") == "false" for e in edges)


def test_ai_invalid_source_location_is_rejected():
    findings = [{"category": "SAST", "path": "src/main/Controller.kt", "line": 42, "severity": "HIGH"}]
    raw = json.dumps({"summary": "test", "items": [
        {"finding_ref": 0, "explanation": "Bug in src/main/Other.kt:42", "fix_steps": []}
    ]})
    parsed, meta = validate_llm_response(raw, findings)
    assert parsed is not None and parsed.items == []
    assert meta["dropped_items"] == 1


def test_plaintext_telegram_token_in_workflow_is_rejected():
    from app.engine.graph import GraphError
    import pytest
    graph = {"nodes": [{"id": "t", "type": "trigger.manual", "params": {}},
                       {"id": "tg", "type": "notify.telegram", "params": {"bot_token": "unsafe"}}],
             "edges": [{"id": "e", "source": "t", "target": "tg"}]}
    with pytest.raises(GraphError, match="plaintext"):
        validate_graph(graph, NODE_REGISTRY)
