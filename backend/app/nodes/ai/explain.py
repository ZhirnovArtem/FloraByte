from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.models import Credential, Finding
from app.nodes.ai.llm_client import chat_completion
from app.nodes.ai.prompts import SYSTEM_PROMPT, build_user_payload
from app.nodes.ai.validator import fallback_report, validate_llm_response
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from sqlmodel import Session

logger = logging.getLogger(__name__)


class Params(BaseModel):
    credential_id: str = Field("", description="LLM credential id (preferred)")
    model: str = Field("", description="Override model name")
    base_url: str = Field("", description="Override OpenAI-compatible base URL")


def _findings_as_dicts(inputs: dict[str, Any]) -> list[dict]:
    raw = inputs.get("findings") or inputs.get("in") or inputs.get("a") or []
    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]
    out: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, Finding):
            d = item.model_dump(by_alias=True)
            # strip raw secrets — evidence should already be masked
            out.append(d)
        elif isinstance(item, dict):
            out.append(item)
    return out


def _resolve_llm_key(params: Params) -> tuple[str | None, str | None, str | None]:
    settings = get_settings()
    key = settings.llm_api_key or None
    base = params.base_url or None
    model = params.model or None
    if params.credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, params.credential_id)
            if cred and cred.encrypted_value:
                raw = decrypt(cred.encrypted_value)
                # token or token|base_url|model
                parts = [p.strip() for p in raw.split("|")]
                key = parts[0] or key
                if len(parts) > 1 and parts[1]:
                    base = base or parts[1]
                if len(parts) > 2 and parts[2]:
                    model = model or parts[2]
    return key, base, model


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

        key, base, model = _resolve_llm_key(params)
        settings = get_settings()

        async def _call() -> tuple[Any, dict]:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_payload(findings)},
            ]
            raw = await chat_completion(
                messages,
                model=model,
                api_key=key,
                base_url=base,
            )
            return validate_llm_response(raw, findings)

        parsed = None
        try:
            if not key and not settings.llm_api_key:
                raise RuntimeError("LLM API key not configured")
            parsed, validation = await _call()
            if parsed is None or not validation.get("passed"):
                validation["retried"] = True
                parsed, validation2 = await _call()
                validation = {**validation2, "retried": True}
        except Exception as e:
            logger.warning("LLM explain failed: %s — using fallback", e)
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
