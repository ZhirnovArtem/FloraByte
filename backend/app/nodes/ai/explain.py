"""ai.explain — Strict AI explanation node wired to AI_AND_INTEGRATION/AI_CODE_CHECKER (no fallback)."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import mask_evidence, redact_text
from app.core.models import Credential, Finding, IntegrationSetting
from app.nodes.ai.llm_client import (
    DEFAULT_PROVIDER_MODELS,
    OPENAI_STYLE_PROVIDERS,
    SUPPORTED_LLM_PROVIDERS,
    is_private_or_local_url,
    resolve_base_url,
)
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
    credential_id: str = Field("", description="LLM credential id (preferred)")
    model: str = Field("", description="Optional model name override")
    provider: str = Field("", description="gemini | ollama | vllm | openai_compatible (defaults to LLM_PROVIDER)")
    base_url: str = Field("", description="Optional OpenAI-compatible base_url (e.g. Ollama http://localhost:11434/v1)")


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


def _resolve_gemini_config(params: Params, owner_id: str | None = None) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (api_key, model, base_url, provider_override)."""
    settings = get_settings()
    key = settings.llm_api_key or os.getenv("GEMINI_API_KEY", "").strip() or None
    model = params.model.strip() or os.getenv("GEMINI_MODEL", "").strip() or None
    base_url = params.base_url.strip() or None
    provider_override = params.provider.strip().lower() or None

    if params.credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, params.credential_id)
            if cred and cred.encrypted_value:
                raw = decrypt(cred.encrypted_value)
                parts = [p.strip() for p in raw.split("|")]
                if parts[0]:
                    key = parts[0]
                if len(parts) > 1 and parts[1]:
                    base_url = base_url or parts[1]
                if len(parts) > 2 and parts[2]:
                    model = model or parts[2]
    else:
        try:
            with Session(get_engine()) as session:
                integ = None
                if owner_id:
                    integ = session.get(IntegrationSetting, f"{owner_id}:ai")
                if integ is None:
                    integ = session.get(IntegrationSetting, "ai")
                if integ and integ.enabled:
                    cfg = integ.config_json or {}
                    if not key and integ.encrypted_secret:
                        try:
                            saved_key = decrypt(integ.encrypted_secret).strip()
                            if saved_key:
                                key = saved_key
                        except Exception:
                            pass
                    if not provider_override and cfg.get("provider"):
                        provider_override = str(cfg["provider"]).strip().lower()
                    if not model and cfg.get("model"):
                        model = str(cfg["model"]).strip()
                    if not base_url and cfg.get("base_url"):
                        base_url = str(cfg["base_url"]).strip()
        except Exception:
            pass
    return key, model, base_url, provider_override


def _validate_api_key_format(api_key: str | None, provider: str, base_url: str) -> None:
    if provider == "gemini":
        if not api_key or not api_key.strip():
            raise RuntimeError("Отсутствует API-ключ Gemini (LLM_API_KEY). Проверьте настройки интеграции.")
        cleaned = api_key.strip()
        if any(ch.isspace() for ch in cleaned) or len(cleaned) < 8:
            raise RuntimeError("Некорректный формат API-ключа Gemini. Проверьте настройки интеграции.")
        return

    # Local / closed-loop LLM providers (ollama, vllm) work without API key in private infrastructure
    if provider in ("ollama", "vllm"):
        if not base_url or not base_url.strip():
            raise RuntimeError(f"Не указан URL для локального провайдера {provider}.")
        return

    if not api_key or not api_key.strip():
        if not is_private_or_local_url(base_url):
            raise RuntimeError("Отсутствует API-ключ для удалённой OpenAI-compatible модели.")


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


async def _run_checker_batch_without_env_mutation(
    batch: list[dict], api_key: str, model: str | None
) -> dict[str, Any]:
    """Strictly verify Gemini key, API availability, model availability, and run AI_CODE_CHECKER."""
    import services.ai_service as ai_svc  # type: ignore[import-not-found]

    # Respect monkeypatched analyze_findings in tests
    if getattr(ai_svc.analyze_findings, "__module__", "") != "services.ai_service":
        return await ai_svc.analyze_findings(batch)

    parsed_findings = ai_svc._parse_findings(batch)
    requested_model = (model or "").strip()
    configured_model = requested_model or ai_svc.DEFAULT_MODEL
    async with httpx.AsyncClient(timeout=ai_svc.TIMEOUT_SECONDS) as client:
        # Step 2.2 & 2.3: verify API key & Gemini API availability
        available = await ai_svc._list_generation_models(client, api_key)
        if not available:
            raise ai_svc.AIServiceError("Gemini API не вернул моделей с поддержкой generateContent.")

        # Step 2.4: verify explicitly selected model availability
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
    canonical = _to_canonical_security_findings(findings)
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


async def _call_openai_compatible(
    findings: list[dict],
    api_key: str | None,
    model: str | None,
    base_url: str | None = None,
    provider: str = "openai_compatible",
) -> str:
    """JSON-only response from OpenAI-style local/cloud models (Ollama, vLLM, Gemini OpenAI); validated after call."""
    from app.nodes.ai.llm_client import chat_completion

    compact = _to_canonical_security_findings(findings)
    safe_input = [
        {"finding_ref": i, **item} for i, item in enumerate(compact)
    ]
    text = await chat_completion(
        [
            {"role": "system", "content": (
                "You are a security explainer, NOT a vulnerability detector. "
                "Only explain provided findings. Return a JSON object with keys 'summary' and 'items'. "
                "Each item has integer finding_ref, string explanation (what was found, where, why dangerous), "
                "string risk (LOW/MEDIUM/HIGH/CRITICAL + impact), string[] fix_steps (concrete code/config changes). "
                "Reference only provided finding_ref numbers, paths and advisory IDs. "
                "Never fabricate CVEs; never disclose credentials or literal secret values. "
                "Use Russian language. Return JSON only."
            )},
            {"role": "user", "content": json.dumps(safe_input, ensure_ascii=False)},
        ],
        model=model,
        api_key=api_key,
        base_url=base_url,
        provider=provider,
    )
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            cleaned = "\n".join(lines[1:-1]).strip()
    return cleaned


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

        key, model, base_url, provider_override = _resolve_gemini_config(params, owner_id=ctx.owner_id)
        settings = get_settings()
        provider = (provider_override or settings.llm_provider).strip().lower()
        effective_base = resolve_base_url(provider, base_url)
        if not model and provider in OPENAI_STYLE_PROVIDERS:
            model = DEFAULT_PROVIDER_MODELS.get(provider) or settings.llm_model
        known_advisories = load_known_advisories(settings.vuln_db_path)

        parsed = None
        error_msg: str | None = None
        try:
            if provider not in SUPPORTED_LLM_PROVIDERS:
                raise ValueError("LLM_PROVIDER должен быть 'gemini', 'ollama', 'vllm' или 'openai_compatible'.")

            # Stage 2 step 1 & 2: strict key presence & format check before any call
            _validate_api_key_format(key, provider, effective_base)

            async def _invoke() -> str:
                if provider in OPENAI_STYLE_PROVIDERS:
                    return await _call_openai_compatible(findings, key, model, effective_base, provider=provider)
                res = await _call_ai_code_checker(findings, key or "", model)
                return json.dumps(res, ensure_ascii=False)

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
            logger.warning("AI Explain failed (no fallback): %s", safe_err)
            errors = list(validation.get("errors") or [])
            if safe_err and safe_err not in errors:
                errors.append(safe_err)
            validation["errors"] = errors
            error_msg = safe_err or AI_ERROR_USER_MESSAGE
            parsed = None

        # Stage 3: never return templated/fallback recommendations on error
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
