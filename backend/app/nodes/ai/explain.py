"""ai.explain — Universal AI Explain node backed by AIProviderManager (no fallback)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.masking import mask_evidence, redact_text
from app.core.models import Finding
from app.nodes.ai.providers import provider_manager
from app.nodes.ai.validator import load_known_advisories, validate_llm_response
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)

_AI_CHECKER_DIR = Path(__file__).resolve().parents[4] / "AI_AND_INTEGRATION" / "AI_CODE_CHECKER"
if _AI_CHECKER_DIR.is_dir() and str(_AI_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(_AI_CHECKER_DIR))

MAX_BATCH_SIZE = 32
AI_ERROR_USER_MESSAGE = "AI-анализ не выполнен. Проверьте API-ключ и доступность модели."


class Params(BaseModel):
    credential_id: str = Field("", description="LLM credential id (optional)")
    model: str = Field("", description="Optional model name override")
    provider: str = Field("", description="Provider id override (defaults to active user AI provider)")
    base_url: str = Field("", description="Optional provider base URL override")


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


def _to_canonical_security_findings(findings: list[dict]) -> list[dict]:
    """Map platform Finding dicts into canonical SecurityFinding v1.0 dicts."""
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


async def _run_checker_batch_without_env_mutation(
    batch: list[dict], api_key: str, model: str | None
) -> dict[str, Any]:
    """Strictly verify Gemini key, API availability, model availability, and run AI_CODE_CHECKER."""
    import services.ai_service as ai_svc  # type: ignore[import-not-found]

    if getattr(ai_svc.analyze_findings, "__module__", "") != "services.ai_service":
        return await ai_svc.analyze_findings(batch)

    parsed_findings = ai_svc._parse_findings(batch)
    requested_model = (model or "").strip()
    configured_model = requested_model or ai_svc.DEFAULT_MODEL
    async with httpx.AsyncClient(timeout=ai_svc.TIMEOUT_SECONDS) as client:
        available = await ai_svc._list_generation_models(client, api_key)
        if not available:
            raise ai_svc.AIServiceError("Gemini API не вернул моделей с поддержкой generateContent.")
        if requested_model and requested_model not in available:
            raise ai_svc.AIServiceError(
                f"Выбранная модель '{requested_model}' недоступна в Gemini API или не поддерживает generateContent."
            )

        queue = ai_svc._candidate_models(available, configured_model)
        last_error: ai_svc.AIServiceError | None = None
        attempts = 0
        while queue and attempts < ai_svc.MAX_MODEL_ATTEMPTS:
            mdl = queue.pop(0)
            attempts += 1
            try:
                payload = await ai_svc._generate_with_retry(client, api_key, mdl, parsed_findings)
            except ai_svc._SwitchModel as exc:
                last_error = exc.error
                if exc.permanent:
                    ai_svc._unavailable_models.add(mdl)
                ai_svc._promote_recommended(queue, exc.recommended, available)
                continue
            ai_svc._remember_model(mdl)
            return ai_svc._build_report(payload, parsed_findings)

    if last_error is not None:
        raise ai_svc.AIServiceError(
            "Не удалось получить анализ ни от одной доступной модели Gemini "
            f"с поддержкой generateContent. Последняя ошибка: {last_error}",
            status_code=last_error.status_code,
            detail=last_error.detail,
        )
    raise ai_svc.AIServiceError("Gemini API не вернул моделей с поддержкой generateContent.")


async def _call_ai_code_checker(findings: list[dict], api_key: str, model: str | None) -> dict[str, Any]:
    is_canonical = bool(findings and isinstance(findings[0], dict) and "file" in findings[0] and "path" not in findings[0])
    canonical = findings if is_canonical else _to_canonical_security_findings(findings)
    all_items: list[dict] = []
    summaries: list[str] = []
    for offset in range(0, len(canonical), MAX_BATCH_SIZE):
        batch = canonical[offset : offset + MAX_BATCH_SIZE]
        report = await _run_checker_batch_without_env_mutation(batch, api_key, model)
        if not isinstance(report, dict) or not report.get("findings"):
            raise RuntimeError("Gemini вернул пустой отчёт без объяснений находок.")
        if report.get("summary"):
            summaries.append(str(report["summary"]))
        for idx_in_batch, entry in enumerate(report.get("findings") or []):
            all_items.append(
                {
                    "finding_ref": offset + idx_in_batch,
                    "explanation": str(entry.get("explanation") or ""),
                    "risk": str(entry.get("risk") or ""),
                    "priority": str(entry.get("severity") or ""),
                    "fix_steps": [str(entry["recommendation"])] if entry.get("recommendation") else [],
                }
            )
    summary = " ".join(summaries).strip()
    if not summary or not all_items:
        raise RuntimeError("Ответ Gemini не содержит обязательных полей summary/items.")
    return {
        "summary": summary,
        "items": all_items,
    }


@register_node
class AiExplainNode(BaseNode):
    type = "ai.explain"
    label = "AI Explain"
    group = "ai"
    continue_downstream_on_error = True
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
            "errors": [],
        }

        if not findings:
            return {
                "report": {
                    "status": "empty",
                    "summary": "Находок для анализа нет.",
                    "items": [],
                    "validation": {
                        **validation,
                        "passed": True,
                        "mode": "empty",
                        "ai_status": "Нет находок",
                        "error": None,
                        "fallback_reason": None,
                    },
                    "findings": [],
                }
            }

        provider, key, model, base_url = provider_manager.resolve_runtime_config(
            owner_id=ctx.owner_id,
            credential_id=params.credential_id,
            provider_override=params.provider,
            model_override=params.model,
            base_url_override=params.base_url,
        )
        settings = get_settings()
        known_advisories = load_known_advisories(settings.vuln_db_path)

        parsed = None
        error_msg: str | None = None
        provider_label = provider
        eff_model = model or ""
        try:
            adapter = provider_manager.get_adapter(provider)
            provider_label = adapter.spec.label
            eff_model = adapter.resolve_model(model)
            adapter.validate_config(key, model, base_url)
            canonical = _to_canonical_security_findings(findings)

            async def _invoke() -> str:
                return await adapter.explain(
                    canonical,
                    api_key=key,
                    model=model,
                    base_url=base_url,
                    timeout=float(settings.llm_timeout_sec),
                )

            raw_text = await _invoke()
            parsed, validation = validate_llm_response(raw_text, findings, known_advisories=known_advisories)
            if parsed is None or not validation.get("passed"):
                validation["retried"] = True
                raw_text2 = await _invoke()
                parsed, validation2 = validate_llm_response(raw_text2, findings, known_advisories=known_advisories)
                validation = {**validation2, "retried": True}

            if parsed is None or not validation.get("passed") or not parsed.items or not parsed.summary.strip():
                errs = "; ".join(validation.get("errors") or []) or "Ответ модели не прошёл строгую проверку."
                raise RuntimeError(errs)
        except Exception as e:
            safe_err = redact_text(str(e), [key] if key else None)
            logger.warning("AI Explain failed (provider=%s, no fallback): %s", provider, safe_err)
            errors = list(validation.get("errors") or [])
            if safe_err and safe_err not in errors:
                errors.append(safe_err)
            validation["errors"] = errors
            error_msg = safe_err or AI_ERROR_USER_MESSAGE
            parsed = None

        validation["provider"] = provider
        validation["provider_label"] = provider_label
        validation["model"] = eff_model

        if parsed is None:
            validation["passed"] = False
            validation["mode"] = "error"
            validation["ai_status"] = "Ошибка"
            validation["error"] = error_msg or AI_ERROR_USER_MESSAGE
            validation["fallback_reason"] = None
            return {
                "report": {
                    "status": "error",
                    "summary": "",
                    "items": [],
                    "validation": validation,
                    "findings": findings,
                }
            }

        validation["passed"] = True
        validation["mode"] = "llm"
        validation["ai_status"] = "Успешно"
        validation["error"] = None
        validation["fallback_reason"] = None

        return {
            "report": {
                "status": "ok",
                "summary": parsed.summary,
                "items": [it.model_dump() for it in parsed.items],
                "validation": validation,
                "findings": findings,
            }
        }
