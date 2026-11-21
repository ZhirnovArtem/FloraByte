"""AI Workflow Generator endpoint: natural-language prompt -> validated DAG."""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.nodes.registry import list_node_types

router = APIRouter(prefix="/api/ai", tags=["ai"])


class GenerateWorkflowRequest(BaseModel):
    prompt: str = Field(..., min_length=2, max_length=2000)


def _validate_generated_graph(graph: dict[str, Any]) -> dict[str, Any] | None:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list) or not nodes:
        return None
    valid_types = {s["type"] for s in list_node_types()}
    node_ids: set[str] = set()
    cleaned_nodes = []
    for idx, n in enumerate(nodes):
        if not isinstance(n, dict):
            return None
        ntype = str(n.get("type") or "")
        if ntype not in valid_types:
            return None
        nid = str(n.get("id") or f"n{idx + 1}")
        if nid in node_ids:
            return None
        node_ids.add(nid)
        pos = n.get("position") if isinstance(n.get("position"), dict) else {"x": 80 + idx * 180, "y": 160}
        params = n.get("params") if isinstance(n.get("params"), dict) else {}
        cleaned_nodes.append({"id": nid, "type": ntype, "params": params, "position": pos})

    cleaned_edges = []
    for idx, e in enumerate(edges):
        if not isinstance(e, dict):
            return None
        src = str(e.get("source") or "")
        tgt = str(e.get("target") or "")
        if src not in node_ids or tgt not in node_ids or src == tgt:
            return None
        cleaned_edges.append(
            {
                "id": str(e.get("id") or f"e{idx + 1}"),
                "source": src,
                "sourceHandle": e.get("sourceHandle"),
                "target": tgt,
                "targetHandle": e.get("targetHandle"),
            }
        )
    return {"nodes": cleaned_nodes, "edges": cleaned_edges}


def _deterministic_workflow_from_prompt(prompt: str) -> dict[str, Any]:
    text = prompt.lower()
    use_cron = any(k in text for k in ("cron", "schedule", "nightly", "распис", "ноч", "ежедн"))
    use_git = any(k in text for k in ("git", "github", "repo", "репозитор"))

    want_secrets = any(k in text for k in ("secret", "секрет", "token", "токен", "key", "ключ"))
    want_sca = any(k in text for k in ("sca", "cve", "depend", "зависим", "gradle", "библиот"))
    want_sast = any(k in text for k in ("sast", "code", "sql", "код", "уязвим", "static"))
    if not (want_secrets or want_sca or want_sast):
        want_secrets = want_sca = want_sast = True

    want_ai = any(k in text for k in ("ai", "llm", "explain", "объясн", "резюм", "анализ", "ии"))
    want_tg = any(k in text for k in ("telegram", "tg", "телеграм", "бот", "уведом"))
    want_wh = any(k in text for k in ("webhook", "вебхук", "http", "slack"))
    want_if = any(k in text for k in ("if", "gate", "порог", "услов", "critical", "high", "если"))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    if use_cron:
        nodes.append({"id": "t1", "type": "trigger.schedule", "params": {"cron": "0 2 * * *"}, "position": {"x": 40, "y": 200}})
    else:
        nodes.append({"id": "t1", "type": "trigger.manual", "params": {}, "position": {"x": 40, "y": 200}})

    if use_git:
        nodes.append(
            {
                "id": "s1",
                "type": "source.git_clone",
                "params": {"url": "https://github.com/TBagirov/training", "branch": "main"},
                "position": {"x": 230, "y": 200},
            }
        )
    else:
        nodes.append(
            {
                "id": "s1",
                "type": "source.upload_zip",
                "params": {"upload_id": ""},
                "position": {"x": 230, "y": 200},
            }
        )
    edges.append({"id": "e1", "source": "t1", "target": "s1"})

    scanners: list[tuple[str, str]] = []
    if want_secrets:
        scanners.append(("sc1", "scanner.secrets"))
    if want_sca:
        scanners.append(("sc2", "scanner.sca"))
    if want_sast:
        scanners.append(("sc3", "scanner.sast"))

    y_start = 200 - (len(scanners) - 1) * 65
    for idx, (sid, stype) in enumerate(scanners):
        nodes.append({"id": sid, "type": stype, "params": {}, "position": {"x": 440, "y": y_start + idx * 120}})
        edges.append({"id": f"e-src-{sid}", "source": "s1", "target": sid})

    nodes.append({"id": "m1", "type": "findings.merge", "params": {}, "position": {"x": 650, "y": 200}})
    handles = ("a", "b", "c")
    for idx, (sid, _) in enumerate(scanners):
        edges.append({"id": f"e-m-{sid}", "source": sid, "target": "m1", "targetHandle": handles[idx]})

    nodes.append({"id": "e1", "type": "findings.export", "params": {}, "position": {"x": 860, "y": 90}})
    edges.append({"id": "e-exp", "source": "m1", "target": "e1"})

    last_report_node = "m1"
    last_handle = "findings"
    if want_ai:
        nodes.append({"id": "ai1", "type": "ai.explain", "params": {}, "position": {"x": 860, "y": 280}})
        edges.append({"id": "e-ai", "source": "m1", "sourceHandle": "findings", "target": "ai1", "targetHandle": "findings"})
        last_report_node = "ai1"
        last_handle = "report"

    next_x = 1070
    if want_if and (want_tg or want_wh):
        nodes.append(
            {
                "id": "if1",
                "type": "logic.if_else",
                "params": {"left": "findings.count", "op": ">", "right": "0"},
                "position": {"x": next_x, "y": 280},
            }
        )
        edges.append({"id": "e-if", "source": last_report_node, "sourceHandle": last_handle, "target": "if1", "targetHandle": "in"})
        last_report_node = "if1"
        last_handle = "true"
        next_x += 220

    if want_tg:
        nodes.append({"id": "tg1", "type": "notify.telegram", "params": {"dry_run": True}, "position": {"x": next_x, "y": 210}})
        edges.append({"id": "e-tg", "source": last_report_node, "sourceHandle": last_handle, "target": "tg1", "targetHandle": "report"})

    if want_wh:
        nodes.append(
            {
                "id": "wh1",
                "type": "notify.webhook",
                "params": {"url": "https://example.org/webhook", "dry_run": True},
                "position": {"x": next_x, "y": 350},
            }
        )
        edges.append({"id": "e-wh", "source": last_report_node, "sourceHandle": last_handle, "target": "wh1", "targetHandle": "report"})

    return {"nodes": nodes, "edges": edges}


async def _try_llm_generate(prompt: str) -> dict[str, Any] | None:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("LLM_API_KEY")
    if not api_key:
        return None
    node_types = [s["type"] for s in list_node_types()]
    sys_msg = (
        "Generate a valid security workflow DAG JSON with keys 'nodes' and 'edges'. "
        f"Allowed node types ONLY: {node_types}. Return raw JSON only."
    )
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "gemini":
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": f"{sys_msg}\nUser request: {prompt}"}]}]}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.post(url, json=payload)
            if r.status_code != 200:
                return None
            raw_text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if not match:
                return None
            parsed = json.loads(match.group(0))
            return _validate_generated_graph(parsed)
        except Exception:
            return None
    return None


@router.post("/generate-workflow")
async def generate_workflow(req: GenerateWorkflowRequest):
    """Generate a validated workflow graph from a natural-language prompt."""
    llm_graph = await _try_llm_generate(req.prompt)
    if llm_graph is not None:
        return {
            "name": "AI Generated Workflow",
            "mode": "llm",
            "graph": llm_graph,
        }

    fallback_graph = _deterministic_workflow_from_prompt(req.prompt)
    validated = _validate_generated_graph(fallback_graph)
    return {
        "name": "AI Generated Workflow",
        "mode": "rule_based",
        "graph": validated or fallback_graph,
    }
