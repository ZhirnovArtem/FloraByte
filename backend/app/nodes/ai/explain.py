"""ai.explain — AI explanation node wired to AI_AND_INTEGRATION/AI_CODE_CHECKER."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import mask_evidence, redact_text
from app.core.models import Credential, Finding
from app.nodes.ai.validator import fallback_report, validate_llm_response
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)

_AI_CHECKER_DIR = Path(__file__).resolve().parents[4] / "AI_AND_INTEGRATION" / "AI_CODE_CHECKER"
if _AI_CHECKER_DIR.is_dir() and str(_AI_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(_AI_CHECKER_DIR))

MAX_BATCH_SIZE = 32


class Params(BaseModel):
    credential_id: str = Field("", description="LLM credential id (preferred)")
    model: str = Field("", description="Override Gemini model name (GEMINI_MODEL)")


def _findings_as_dicts(inputs: dict[str, Any]) -> list[dict]:
    raw = inputs.get("findings") or inputs.get("in") or inputs.get("a") or []
    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]
    out: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, Finding):
            out.append(item.model_dump(by_alias=True))
        elif isinstance(item, dict):
            out.append(item)
    return out


def _resolve_gemini_config(params: Params) -> tuple[str | None, str | None]:
    settings = get_settings()
    key = settings.llm_api_key or os.getenv("GEMINI_API_KEY", "").strip() or None
    model = params.model or os.getenv("GEMINI_MODEL", "").strip() or None
    if params.credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, params.credential_id)
            if cred and cred.encrypted_value:
                raw = decrypt(cred.encrypted_value)
                parts = [p.strip() for p in raw.split("|")]
                if parts[0]:
                    key = parts[0]
                if len(parts) > 2 and parts[2]:
                    model = model or parts[2]
    return key, model


def _to_canonical_security_findings(findings: list[dict]) -> list[dict]:
    """Map platform Finding dicts into AI_CODE_CHECKER SecurityFinding v1.0 dicts."""
    canonical: list[dict] = []
    for f in findings:
        cat = str(f.get("category") or "FINDING")
        rule_id = str(
            f.get("rule_id")
            or f.get("class")
            or f.get("advisoryId")
            or f"{cat.lower()}.finding"
        ).strip() or "unknown"
        file_path = str(f.get("path") or "unknown").strip() or "unknown"
        line = f.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            line = None
        sev = str(f.get("severity") or "MEDIUM").strip() or "MEDIUM"
        desc = f.get("description")
        if not desc or not str(desc).strip():
            detail = f.get("class") or (
                f"{f.get('group', '')}:{f.get('artifact', '')}@{f.get('version', '')}"
                if cat == "SCA"
                else ""
            )
            desc = f"{cat}: {detail}".strip(": ") or "Security finding"
        msg = redact_text(str(desc))[:1000]
        ev_raw = f.get("evidence")
        ev = mask_evidence(str(ev_raw)) if ev_raw else None
        canonical.append(
            {
                "rule_id": rule_id,
                "file": file_path,
                "line": line,
                "severity": sev,
                "message": msg,
                "evidence": ev,
            }
        )
    return canonical


async def _call_ai_code_checker(findings: list[dict], api_key: str, model: str | None) -> dict[str, Any]:
    from services.ai_service import analyze_findings  # type: ignore[import-not-found]

    canonical = _to_canonical_security_findings(findings)
    prev_key = os.environ.get("GEMINI_API_KEY")
    prev_model = os.environ.get("GEMINI_MODEL")
    os.environ["GEMINI_API_KEY"] = api_key
    if model:
        os.environ["GEMINI_MODEL"] = model
    try:
        all_items: list[dict] = []
        summaries: list[str] = []
        for offset in range(0, len(canonical), MAX_BATCH_SIZE):
            batch = canonical[offset : offset + MAX_BATCH_SIZE]
            report = await analyze_findings(batch)
            if report.get("summary"):
                summaries.append(str(report["summary"]))
            for idx_in_batch, entry in enumerate(report.get("findings") or []):
                all_items.append(
                    {
                        "finding_ref": offset + idx_in_batch,
                        "explanation": str(entry.get("explanation") or ""),
                        "risk": str(entry.get("risk") or ""),
                        "fix_steps": [str(entry["recommendation"])] if entry.get("recommendation") else [],
                    }
                )
        return {
            "summary": " ".join(summaries).strip() or f"Проанализировано находок: {len(findings)}.",
            "items": all_items,
        }
    finally:
        if prev_key is None:
            os.environ.pop("GEMINI_API_KEY", None)
        else:
            os.environ["GEMINI_API_KEY"] = prev_key
        if prev_model is None:
            os.environ.pop("GEMINI_MODEL", None)
        else:
            os.environ["GEMINI_MODEL"] = prev_model


@register_node
class AiExplainNode(BaseNode):
    type = "ai.explain"
    label = "AI Explain"
    group = "ai"
    inputs = [
        Port(name="findings", kind="Findings"),
        Port(name="in", kind="Findings"),
    ]
    outputs = [Port(name="report", kind="Report")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        findings = _findings_as_dicts(inputs)
        validation: dict[str, Any] = {
            "passed": False,
            "retried": False,
            "dropped_items": 0,
            "dropped_cve": 0,
        }

        if not findings:
            fb = fallback_report([])
            return {
                "report": {
                    "summary": fb.summary,
                    "items": [],
                    "validation": {**validation, "passed": True, "mode": "empty"},
                    "findings": [],
                }
            }

        key, model = _resolve_gemini_config(params)

        parsed = None
        try:
            if not key:
                raise RuntimeError("GEMINI_API_KEY / LLM API key not configured")
            raw_obj = await _call_ai_code_checker(findings, key, model)
            parsed, validation = validate_llm_response(json.dumps(raw_obj, ensure_ascii=False), findings)
            if parsed is None or not validation.get("passed"):
                validation["retried"] = True
                raw_obj2 = await _call_ai_code_checker(findings, key, model)
                parsed, validation2 = validate_llm_response(json.dumps(raw_obj2, ensure_ascii=False), findings)
                validation = {**validation2, "retried": True}
        except Exception as e:
            logger.warning("AI_CODE_CHECKER explain failed: %s — using fallback", e)
            validation["errors"] = validation.get("errors") or []
            validation["errors"].append(str(e))
            parsed = None

        if parsed is None or not parsed.items:
            parsed = fallback_report(findings)
            validation["passed"] = False
            validation["mode"] = "fallback"
        else:
            validation["mode"] = "llm"

        return {
            "report": {
                "summary": parsed.summary,
                "items": [it.model_dump() for it in parsed.items],
                "validation": validation,
                "findings": findings,
            }
        }
