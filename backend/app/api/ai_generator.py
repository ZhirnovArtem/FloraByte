"""AI Workflow Generator endpoint: natural-language prompt -> validated DAG."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.core.auth import get_optional_user
from app.core.db import get_session
from app.core.models import User
from app.engine.graph import GraphError, validate_graph
from app.nodes.ai.providers import provider_manager
from app.nodes.custom_manager import build_effective_registry

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ai", tags=["ai"])

_URL_RE = re.compile(r"https?://[^\s,;\"'<>()]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TIME_RE = re.compile(r"(?:в|at)?\s*(\d{1,2})[:.](\d{2})\b", re.IGNORECASE)
_CRON_RE = re.compile(r"\b(\d{1,2}|\*)\s+(\d{1,2}|\*)\s+(\d{1,2}|\*)\s+(\d{1,2}|\*)\s+(\d{1,2}(?:-\d{1,2})?|\*)\b")


class GenerateWorkflowRequest(BaseModel):
    prompt: str = Field(..., min_length=2, max_length=2000)


def _extract_cron(text: str) -> tuple[str | None, str | None]:
    cron_match = _CRON_RE.search(text)
    if cron_match:
        expr = cron_match.group(0)
        return expr, f"по расписанию ({expr})"

    lower = text.lower()
    if any(k in lower for k in ("каждый час", "ежечасно", "hourly")):
        return "0 * * * *", "каждый час (0 * * * *)"

    tm = _TIME_RE.search(text)
    hour: int | None = None
    minute: int | None = None
    if tm:
        h, m = int(tm.group(1)), int(tm.group(2))
        if 0 <= h <= 23 and 0 <= m <= 59:
            hour, minute = h, m

    if any(k in lower for k in ("по будням", "будн", "weekdays")):
        h, m = (hour if hour is not None else 9), (minute if minute is not None else 0)
        return f"{m} {h} * * 1-5", f"по будням в {h:02d}:{m:02d}"

    if any(k in lower for k in ("каждую неделю", "еженедельно", "по понедельникам", "weekly")):
        h, m = (hour if hour is not None else 10), (minute if minute is not None else 0)
        return f"{m} {h} * * 1", f"еженедельно (пн {h:02d}:{m:02d})"

    if hour is not None and minute is not None:
        return f"{minute} {hour} * * *", f"ежедневно в {hour:02d}:{minute:02d}"

    if any(k in lower for k in ("ноч", "nightly")):
        return "0 2 * * *", "ночью в 02:00"

    if any(k in lower for k in ("cron", "schedule", "распис", "ежедн", "каждый день", "daily")):
        return "0 9 * * *", "ежедневно в 09:00"

    return None, None


def _describe_catalog_for_llm(registry: dict[str, type]) -> list[dict[str, Any]]:
    items = []
    for ntype, cls in sorted(registry.items()):
        schema = cls.Params.model_json_schema() if hasattr(cls, "Params") else {}
        props = list((schema.get("properties") or {}).keys())
        items.append(
            {
                "type": ntype,
                "label": getattr(cls, "label", ntype),
                "group": getattr(cls, "group", "other"),
                "inputs": [{"name": p.name, "kind": p.kind} for p in getattr(cls, "inputs", [])],
                "outputs": [{"name": p.name, "kind": p.kind} for p in getattr(cls, "outputs", [])],
                "param_keys": props,
            }
        )
    return items


def _normalize_and_validate_graph(
    graph: dict[str, Any],
    registry: dict[str, type],
) -> dict[str, Any] | None:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list) or not nodes:
        return None

    node_ids: set[str] = set()
    node_types_by_id: dict[str, str] = {}
    cleaned_nodes: list[dict[str, Any]] = []

    for idx, n in enumerate(nodes):
        if not isinstance(n, dict):
            return None
        ntype = str(n.get("type") or "").strip()
        if ntype not in registry:
            return None
        nid = str(n.get("id") or f"n{idx + 1}").strip()
        if not nid or nid in node_ids:
            return None
        node_ids.add(nid)
        node_types_by_id[nid] = ntype

        pos = n.get("position")
        if not isinstance(pos, dict) or "x" not in pos or "y" not in pos:
            pos = {"x": 60 + idx * 210, "y": 200}
        params = dict(n.get("params")) if isinstance(n.get("params"), dict) else {}
        cleaned_nodes.append({"id": nid, "type": ntype, "params": params, "position": pos})

    cleaned_edges: list[dict[str, Any]] = []
    for idx, e in enumerate(edges):
        if not isinstance(e, dict):
            return None
        src = str(e.get("source") or "").strip()
        tgt = str(e.get("target") or "").strip()
        if src not in node_ids or tgt not in node_ids or src == tgt:
            return None
        src_handle = e.get("sourceHandle")
        tgt_handle = e.get("targetHandle")

        # Auto-repair omitted sourceHandle on multi-output logic nodes when obvious
        src_cls = registry[node_types_by_id[src]]
        if not src_handle and len(getattr(src_cls, "outputs", [])) > 1:
            src_handle = src_cls.outputs[0].name

        cleaned_edges.append(
            {
                "id": str(e.get("id") or f"e{idx + 1}"),
                "source": src,
                "sourceHandle": src_handle,
                "target": tgt,
                "targetHandle": tgt_handle,
            }
        )

    candidate = {"nodes": cleaned_nodes, "edges": cleaned_edges}
    try:
        validate_graph(candidate, registry)
    except GraphError as exc:
        logger.debug("Generated graph failed validate_graph: %s", exc)
        return None
    return candidate


def _deterministic_workflow_from_prompt(prompt: str) -> tuple[str, str, dict[str, Any]]:
    text = prompt.strip()
    lower = text.lower()

    cron_expr, cron_desc = _extract_cron(text)
    urls = _URL_RE.findall(text)
    emails = _EMAIL_RE.findall(text)

    git_url = next(
        (u.rstrip(".,)") for u in urls if any(h in u.lower() for h in ("github.com", "gitlab.com", "bitbucket.org", ".git"))),
        "https://github.com/TBagirov/training",
    )
    webhook_url = next((u.rstrip(".,)") for u in urls if u.rstrip(".,)") != git_url), "https://example.org/webhook")

    branch = "main"
    bm = re.search(r"(?:ветк[аеуи]?|branch)\s+([A-Za-z0-9_./-]+)", text, re.IGNORECASE)
    if bm:
        branch = bm.group(1)

    use_git = any(k in lower for k in ("git", "github", "gitlab", "repo", "репозитор", "ссылк")) or git_url in text

    want_secrets = any(k in lower for k in ("secret", "секрет", "token", "токен", "ключ", "key", "парол", "утечк"))
    want_sca = any(k in lower for k in ("sca", "cve", "depend", "зависим", "gradle", "библиот", "пакет"))
    want_sast = any(
        k in lower
        for k in ("sast", "sql", "xss", "инъекц", "статическ", "уязвим", "static")
    ) or ("код" in lower and not want_secrets and not want_sca)

    if not (want_secrets or want_sca or want_sast):
        want_secrets = want_sca = want_sast = True

    want_ai = any(k in lower for k in ("ai", "llm", "explain", "объясн", "резюм", "рекомендац", "ии", "нейросет"))
    want_email = bool(emails) or any(k in lower for k in ("почт", "email", "e-mail", "mail", "письм"))
    want_tg = any(k in lower for k in ("telegram", "tg", "телеграм", "телег", "бот"))
    want_wh = any(k in lower for k in ("webhook", "вебхук", "http", "slack", "discord", "mattermost"))
    want_if = any(k in lower for k in ("if", "gate", "порог", "услов", "если", "только при", "при налич"))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    parts_summary: list[str] = []

    if cron_expr:
        nodes.append(
            {
                "id": "t1",
                "type": "trigger.schedule",
                "params": {"cron": cron_expr},
                "position": {"x": 40, "y": 200},
            }
        )
        parts_summary.append(f"Триггер: расписание ({cron_desc})")
    else:
        nodes.append({"id": "t1", "type": "trigger.manual", "params": {}, "position": {"x": 40, "y": 200}})
        parts_summary.append("Триггер: ручной запуск")

    if use_git:
        nodes.append(
            {
                "id": "s1",
                "type": "source.git_clone",
                "params": {"url": git_url, "branch": branch},
                "position": {"x": 240, "y": 200},
            }
        )
        parts_summary.append(f"Источник: Git ({git_url}, ветка {branch})")
    else:
        nodes.append(
            {
                "id": "s1",
                "type": "source.upload_zip",
                "params": {"upload_id": ""},
                "position": {"x": 240, "y": 200},
            }
        )
        parts_summary.append("Источник: ZIP-архив")
    edges.append({"id": "edge-t1-s1", "source": "t1", "target": "s1"})

    scanners: list[tuple[str, str, str]] = []
    if want_secrets:
        scanners.append(("sc1", "scanner.secrets", "Секреты"))
    if want_sca:
        scanners.append(("sc2", "scanner.sca", "SCA"))
    if want_sast:
        scanners.append(("sc3", "scanner.sast", "SAST"))

    y_start = 200 - (len(scanners) - 1) * 65
    for idx, (sid, stype, _) in enumerate(scanners):
        nodes.append({"id": sid, "type": stype, "params": {}, "position": {"x": 450, "y": y_start + idx * 120}})
        edges.append({"id": f"edge-src-{sid}", "source": "s1", "target": sid})
    parts_summary.append("Сканеры: " + ", ".join(label for _, _, label in scanners))

    nodes.append({"id": "m1", "type": "findings.merge", "params": {}, "position": {"x": 670, "y": 200}})
    handles = ("a", "b", "c")
    for idx, (sid, _, _) in enumerate(scanners):
        edges.append({"id": f"edge-m-{sid}", "source": sid, "target": "m1", "targetHandle": handles[idx]})

    next_x = 880
    findings_node = "m1"
    findings_handle = "findings"

    # Place If/Else BEFORE export/AI so it evaluates Findings directly and gates downstream report & alerts
    if want_if:
        if any(k in lower for k in ("critical", "критич")):
            if_params = {"left": "findings.by_severity.CRITICAL", "op": ">", "right": "0"}
            cond_label = "CRITICAL > 0"
        elif any(k in lower for k in ("high", "высок")):
            if_params = {"left": "findings.by_severity.HIGH", "op": ">", "right": "0"}
            cond_label = "HIGH > 0"
        else:
            if_params = {"left": "findings.count", "op": ">", "right": "0"}
            cond_label = "findings.count > 0"

        nodes.append(
            {
                "id": "if1",
                "type": "logic.if_else",
                "params": if_params,
                "position": {"x": next_x, "y": 200},
            }
        )
        edges.append(
            {
                "id": "edge-if1",
                "source": findings_node,
                "sourceHandle": findings_handle,
                "target": "if1",
                "targetHandle": "findings",
            }
        )
        findings_node = "if1"
        findings_handle = "true"
        next_x += 210
        parts_summary.append(f"Условие: {cond_label}")

    if want_ai:
        nodes.append({"id": "ai1", "type": "ai.explain", "params": {}, "position": {"x": next_x, "y": 200}})
        edges.append(
            {
                "id": "edge-ai1",
                "source": findings_node,
                "sourceHandle": findings_handle,
                "target": "ai1",
                "targetHandle": "findings",
            }
        )
        next_x += 210
        nodes.append({"id": "exp1", "type": "findings.export", "params": {}, "position": {"x": next_x, "y": 200}})
        edges.append(
            {
                "id": "edge-exp1",
                "source": "ai1",
                "sourceHandle": "report",
                "target": "exp1",
                "targetHandle": "report",
            }
        )
        parts_summary.append("AI-анализ: включён")
    else:
        nodes.append({"id": "exp1", "type": "findings.export", "params": {}, "position": {"x": next_x, "y": 200}})
        edges.append(
            {
                "id": "edge-exp1",
                "source": findings_node,
                "sourceHandle": findings_handle,
                "target": "exp1",
                "targetHandle": "findings",
            }
        )

    next_x += 210
    notify_y = 140
    channels_used: list[str] = []

    if want_email:
        to_email = emails[0] if emails else ""
        nodes.append(
            {
                "id": "em1",
                "type": "notify.email",
                "params": {
                    "to_email": to_email,
                    "subject": "FloraByte Security Report",
                    "dry_run": not bool(to_email),
                },
                "position": {"x": next_x, "y": notify_y},
            }
        )
        edges.append(
            {
                "id": "edge-em1",
                "source": "exp1",
                "sourceHandle": "report",
                "target": "em1",
                "targetHandle": "report",
            }
        )
        notify_y += 140
        channels_used.append(f"Email ({to_email})" if to_email else "Email (укажите адрес)")

    if want_tg:
        nodes.append(
            {
                "id": "tg1",
                "type": "notify.telegram",
                "params": {"dry_run": True},
                "position": {"x": next_x, "y": notify_y},
            }
        )
        edges.append(
            {
                "id": "edge-tg1",
                "source": "exp1",
                "sourceHandle": "report",
                "target": "tg1",
                "targetHandle": "report",
            }
        )
        notify_y += 140
        channels_used.append("Telegram")

    if want_wh:
        nodes.append(
            {
                "id": "wh1",
                "type": "notify.webhook",
                "params": {"url": webhook_url, "dry_run": webhook_url == "https://example.org/webhook"},
                "position": {"x": next_x, "y": notify_y},
            }
        )
        edges.append(
            {
                "id": "edge-wh1",
                "source": "exp1",
                "sourceHandle": "report",
                "target": "wh1",
                "targetHandle": "report",
            }
        )
        channels_used.append("Webhook")

    if channels_used:
        parts_summary.append("Доставка: " + ", ".join(channels_used))
    else:
        parts_summary.append("Отчёт: JSON / Markdown / PDF")

    title_parts = [cron_desc or "Проверка"]
    title_parts.append("Git" if use_git else "ZIP")
    title_parts.append("+".join(label for _, _, label in scanners))
    if channels_used:
        title_parts.append(", ".join(channels_used))
    name = " · ".join(title_parts)[:80]
    summary = " | ".join(parts_summary)
    return name, summary, {"nodes": nodes, "edges": edges}


async def _try_llm_generate(
    prompt: str,
    registry: dict[str, type],
    owner_id: str | None = None,
) -> tuple[str | None, str | None, str | None, dict[str, Any] | None]:
    provider, api_key, model, base_url = provider_manager.resolve_runtime_config(owner_id=owner_id)
    try:
        adapter = provider_manager.get_adapter(provider)
        adapter.validate_config(api_key, model, base_url)
    except Exception:
        return None, None, None, None

    catalog_desc = _describe_catalog_for_llm(registry)
    sys_msg = (
        "You are a security workflow DAG architect for FloraByte.\n"
        "Convert the user's request into a valid JSON object with keys:\n"
        '  "name": short Russian workflow title,\n'
        '  "summary": short Russian summary of chosen blocks,\n'
        '  "nodes": list of {"id", "type", "params", "position": {"x": int, "y": int}},\n'
        '  "edges": list of {"id", "source", "sourceHandle", "target", "targetHandle"}.\n'
        "Rules:\n"
        "1. Start with exactly one trigger.* node (trigger.schedule with cron e.g. '0 14 * * *', or trigger.manual).\n"
        "2. Connect trigger -> source.* -> scanner.* -> findings.merge -> (optional logic.if_else on findings with sourceHandle='true') -> (optional ai.explain) -> findings.export -> notify.*.\n"
        "3. Never include plaintext secrets/tokens/passwords in params; set dry_run=true when email/webhook/telegram target is unknown.\n"
        "4. Port kinds must match: Workspace->Workspace, Findings->Findings, Report->Report (Any accepts/connects to any).\n"
        f"Available node types and ports:\n{json.dumps(catalog_desc, ensure_ascii=False)}\n"
        "Return raw JSON ONLY (no markdown fences)."
    )
    try:
        raw_text = await adapter.generate_text(
            system_prompt=sys_msg,
            user_prompt=f"Запрос пользователя: {prompt}",
            model=model,
            api_key=api_key,
            base_url=base_url,
        )
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if not match:
            return None, None, None, None
        parsed = json.loads(match.group(0))
        graph_obj = parsed.get("graph") if isinstance(parsed.get("graph"), dict) else parsed
        validated = _normalize_and_validate_graph(graph_obj, registry)
        if validated is None:
            return None, None, None, None
        title = str(parsed.get("name") or "").strip()[:80] or None
        summary = str(parsed.get("summary") or "").strip()[:300] or None
        return provider, title, summary, validated
    except Exception as exc:
        logger.info("LLM workflow generation fallback (%s): %s", provider, exc)
        return None, None, None, None


@router.post("/generate-workflow")
async def generate_workflow(
    req: GenerateWorkflowRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_optional_user),
):
    """Generate a validated, pre-configured workflow graph from a natural-language prompt."""
    owner_id = user.id if user else None
    registry = build_effective_registry(session, owner_id=owner_id)

    fb_name, fb_summary, fb_graph = _deterministic_workflow_from_prompt(req.prompt)
    provider, llm_name, llm_summary, llm_graph = await _try_llm_generate(
        req.prompt,
        registry=registry,
        owner_id=owner_id,
    )
    if llm_graph is not None:
        return {
            "name": llm_name or fb_name,
            "summary": llm_summary or fb_summary,
            "mode": "llm",
            "provider": provider,
            "graph": llm_graph,
        }

    validated = _normalize_and_validate_graph(fb_graph, registry)
    return {
        "name": fb_name,
        "summary": fb_summary,
        "mode": "rule_based",
        "provider": None,
        "graph": validated or fb_graph,
    }
