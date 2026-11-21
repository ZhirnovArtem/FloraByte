"""Integrations API — one-time encrypted setup for AI and Telegram, plus connection checks and on-demand send."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.auth import check_owner, get_current_user
from app.core.crypto import decrypt, encrypt
from app.core.db import get_session
from app.core.masking import mask_secret, redact_text
from app.core.models import IntegrationSetting, Run, User
from app.core.run_analytics import load_run_findings
from app.nodes.ai.llm_client import (
    DEFAULT_PROVIDER_MODELS,
    OPENAI_STYLE_PROVIDERS,
    SUPPORTED_LLM_PROVIDERS,
    is_private_or_local_url,
    resolve_base_url,
    verify_openai_compatible_connection,
)
from app.nodes.notify.telegram import (
    _format_message,
    normalize_bot_token,
    send_telegram_message,
    validate_token_format,
    verify_telegram_connection,
)

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


class AiIntegrationUpdate(BaseModel):
    provider: str = Field("gemini", description="gemini | openai_compatible")
    model: str = Field("gemini-2.5-flash", description="Model identifier")
    base_url: str = Field("", description="Optional OpenAI-compatible base URL")
    api_key: str = Field("", description="Optional new API key (keeps existing if blank)")
    enabled: bool = True


class AiIntegrationTest(BaseModel):
    provider: str = ""
    model: str = ""
    base_url: str = ""
    api_key: str = ""


class TelegramIntegrationUpdate(BaseModel):
    bot_token: str = Field("", description="Optional new Bot Token (keeps existing if blank)")
    chat_id: str = Field(..., description="Target Telegram chat ID")
    auto_send: bool = Field(True, description="Auto-add Telegram and send report after scan")
    enabled: bool = True
    verify: bool = Field(True, description="Verify token & chat_id via Telegram API before saving")


class TelegramIntegrationTest(BaseModel):
    bot_token: str = ""
    chat_id: str = ""


def _integ_key(user: Optional[User], kind: str) -> str:
    return f"{user.id}:{kind}" if user is not None else kind


def _get_integ_row(session: Session, user: Optional[User], kind: str) -> IntegrationSetting | None:
    if user is not None:
        row = session.get(IntegrationSetting, f"{user.id}:{kind}")
        if row is not None:
            return row
    return session.get(IntegrationSetting, kind)


def _read_ai_status(session: Session, user: Optional[User] = None) -> dict[str, Any]:
    settings = get_settings()
    row = _get_integ_row(session, user, "ai")
    env_key = (settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")).strip()
    if row and row.enabled:
        cfg = row.config_json or {}
        saved_key = ""
        if row.encrypted_secret:
            try:
                saved_key = decrypt(row.encrypted_secret).strip()
            except Exception:
                saved_key = ""
        effective_key = saved_key or env_key
        provider = str(cfg.get("provider") or settings.llm_provider or "gemini").strip().lower()
        base_url = resolve_base_url(provider, str(cfg.get("base_url") or settings.llm_base_url or ""))
        is_local = provider in ("ollama", "vllm") or (
            provider == "openai_compatible" and is_private_or_local_url(base_url)
        )
        return {
            "configured": bool(effective_key or is_local),
            "enabled": row.enabled,
            "source": "settings" if saved_key else ("env" if env_key else ("local" if is_local else "none")),
            "provider": provider,
            "model": str(cfg.get("model") or DEFAULT_PROVIDER_MODELS.get(provider) or os.getenv("GEMINI_MODEL", "") or "gemini-2.5-flash"),
            "base_url": base_url,
            "api_key_preview": mask_secret(effective_key, keep_last=4) if effective_key else "",
        }

    default_provider = (settings.llm_provider or "gemini").strip().lower()
    default_base = resolve_base_url(default_provider, settings.llm_base_url)
    is_default_local = default_provider in ("ollama", "vllm") or (
        default_provider == "openai_compatible" and is_private_or_local_url(default_base)
    )
    return {
        "configured": bool(env_key or is_default_local),
        "enabled": bool(env_key or is_default_local),
        "source": "env" if env_key else ("local" if is_default_local else "none"),
        "provider": default_provider,
        "model": os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_PROVIDER_MODELS.get(default_provider) or settings.llm_model or "gemini-2.5-flash",
        "base_url": default_base,
        "api_key_preview": mask_secret(env_key, keep_last=4) if env_key else "",
    }


def _read_telegram_status(session: Session, user: Optional[User] = None) -> dict[str, Any]:
    settings = get_settings()
    row = _get_integ_row(session, user, "telegram")
    env_token = normalize_bot_token(settings.telegram_bot_token)
    env_chat = (settings.telegram_chat_id or "").strip()

    if row and row.enabled:
        cfg = row.config_json or {}
        saved_token = ""
        if row.encrypted_secret:
            try:
                saved_token = normalize_bot_token(decrypt(row.encrypted_secret))
            except Exception:
                saved_token = ""
        effective_token = saved_token or env_token
        effective_chat = str(cfg.get("chat_id") or env_chat or "").strip()
        return {
            "configured": bool(effective_token and effective_chat),
            "enabled": row.enabled,
            "auto_send": row.auto_send,
            "source": "settings" if saved_token else ("env" if env_token else "none"),
            "chat_id": effective_chat,
            "bot_token_preview": mask_secret(effective_token, keep_last=4) if effective_token else "",
            "bot_username": str(cfg.get("bot_username") or ""),
            "verified": bool(cfg.get("verified")),
        }

    return {
        "configured": bool(env_token and env_chat),
        "enabled": bool(env_token and env_chat),
        "auto_send": bool(env_token and env_chat),
        "source": "env" if (env_token and env_chat) else "none",
        "chat_id": env_chat,
        "bot_token_preview": mask_secret(env_token, keep_last=4) if env_token else "",
        "bot_username": "",
        "verified": False,
    }


@router.get("")
def get_integrations(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    return {
        "ai": _read_ai_status(session, user),
        "telegram": _read_telegram_status(session, user),
    }


@router.put("/ai")
def save_ai_integration(
    body: AiIntegrationUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    provider = body.provider.strip().lower() or "gemini"
    if provider not in SUPPORTED_LLM_PROVIDERS:
        raise HTTPException(400, "provider must be gemini, ollama, vllm, or openai_compatible")

    key = _integ_key(user, "ai")
    row = session.get(IntegrationSetting, key)
    secret = row.encrypted_secret if row else ""
    if body.api_key.strip():
        secret = encrypt(body.api_key.strip())

    if not row:
        row = IntegrationSetting(kind=key)
    row.enabled = body.enabled
    row.encrypted_secret = secret
    row.config_json = {
        "provider": provider,
        "model": body.model.strip() or DEFAULT_PROVIDER_MODELS.get(provider) or "gemini-2.5-flash",
        "base_url": resolve_base_url(provider, body.base_url) if provider in OPENAI_STYLE_PROVIDERS else body.base_url.strip(),
    }
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return _read_ai_status(session, user)


@router.post("/ai/test")
async def test_ai_integration(
    body: AiIntegrationTest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    status = _read_ai_status(session, user)
    row = _get_integ_row(session, user, "ai")
    settings = get_settings()

    provider = (body.provider or status["provider"] or "gemini").strip().lower()
    model = (body.model or status["model"] or "gemini-2.5-flash").strip()
    base_url = (body.base_url or status["base_url"] or settings.llm_base_url).strip()

    key = body.api_key.strip()
    if not key and row and row.encrypted_secret:
        try:
            key = decrypt(row.encrypted_secret).strip()
        except Exception:
            key = ""
    if not key:
        key = (settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")).strip()

    if provider == "gemini":
        if not key:
            return {"ok": False, "detail": "AI API-ключ не задан."}
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": key},
                    params={"pageSize": 100},
                )
            if resp.status_code == 200:
                models = resp.json().get("models") or []
                gen_models = {
                    str(m.get("name", "")).removeprefix("models/").strip()
                    for m in models
                    if isinstance(m, dict) and "generateContent" in (m.get("supportedGenerationMethods") or [])
                }
                if model and model not in gen_models:
                    return {
                        "ok": False,
                        "provider": provider,
                        "model": model,
                        "detail": f"API-ключ действителен, но модель '{model}' недоступна для generateContent.",
                    }
                return {"ok": True, "provider": provider, "model": model, "detail": "Подключение к Gemini API и доступность модели подтверждены."}
            if resp.status_code in (400, 401, 403):
                return {
                    "ok": False,
                    "provider": provider,
                    "model": model,
                    "detail": f"Неверный API-ключ Gemini или доступ запрещён (HTTP {resp.status_code}).",
                }
            return {
                "ok": False,
                "provider": provider,
                "model": model,
                "detail": redact_text(f"Gemini API вернул HTTP {resp.status_code}", [key]),
            }
        except Exception as exc:
            return {"ok": False, "provider": provider, "model": model, "detail": redact_text(str(exc), [key])}

    # ollama / vllm / openai_compatible
    target_base = resolve_base_url(provider, base_url)
    res = await verify_openai_compatible_connection(target_base, model=model, api_key=key)
    return {"provider": provider, "model": model, **res}


@router.delete("/ai")
def delete_ai_integration(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    row = session.get(IntegrationSetting, _integ_key(user, "ai"))
    if row:
        session.delete(row)
        session.commit()
    return {"ok": True}


@router.post("/telegram/test")
async def test_telegram_integration(
    body: TelegramIntegrationTest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    row = _get_integ_row(session, user, "telegram")
    settings = get_settings()

    token = normalize_bot_token(body.bot_token)
    if not token and row and row.encrypted_secret:
        try:
            token = normalize_bot_token(decrypt(row.encrypted_secret))
        except Exception:
            token = ""
    if not token:
        token = normalize_bot_token(settings.telegram_bot_token)

    chat_id = (body.chat_id or "").strip()
    if not chat_id and row:
        chat_id = str((row.config_json or {}).get("chat_id") or "").strip()
    if not chat_id:
        chat_id = (settings.telegram_chat_id or "").strip()

    return await verify_telegram_connection(token, chat_id)


@router.put("/telegram")
async def save_telegram_integration(
    body: TelegramIntegrationUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    key = _integ_key(user, "telegram")
    row = session.get(IntegrationSetting, key)
    token = normalize_bot_token(body.bot_token)
    if not token and row and row.encrypted_secret:
        try:
            token = normalize_bot_token(decrypt(row.encrypted_secret))
        except Exception:
            token = ""
    if not token:
        token = normalize_bot_token(get_settings().telegram_bot_token)

    chat_id = body.chat_id.strip()
    try:
        validate_token_format(token)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not chat_id:
        raise HTTPException(400, "Укажите chat_id для Telegram.")

    bot_username = str((row.config_json or {}).get("bot_username") or "") if row else ""
    verified = False
    if body.verify:
        check = await verify_telegram_connection(token, chat_id)
        if not check.get("ok"):
            raise HTTPException(400, str(check.get("error") or "Не удалось проверить подключение к Telegram"))
        bot_username = str(check.get("bot_username") or "")
        verified = True

    if not row:
        row = IntegrationSetting(kind=key)
    row.enabled = body.enabled
    row.auto_send = body.auto_send
    row.encrypted_secret = encrypt(token)
    row.config_json = {
        "chat_id": chat_id,
        "bot_username": bot_username,
        "verified": verified,
    }
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return _read_telegram_status(session, user)


@router.delete("/telegram")
def delete_telegram_integration(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    row = session.get(IntegrationSetting, _integ_key(user, "telegram"))
    if row:
        session.delete(row)
        session.commit()
    return {"ok": True}


@router.post("/telegram/send-run/{run_id}")
async def send_run_to_telegram(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    check_owner(run.owner_id, user)

    tg = _read_telegram_status(session, user)
    row = _get_integ_row(session, user, "telegram")
    settings = get_settings()

    token = ""
    if row and row.encrypted_secret:
        try:
            token = normalize_bot_token(decrypt(row.encrypted_secret))
        except Exception:
            token = ""
    if not token:
        token = normalize_bot_token(settings.telegram_bot_token)
    chat_id = tg.get("chat_id") or settings.telegram_chat_id or ""

    if not token or not chat_id:
        raise HTTPException(400, "Telegram-интеграция не настроена. Укажите Bot Token и chat_id в разделе «Интеграции».")

    findings = load_run_findings(run)
    ai_rep = run.ai_report_json or {}
    payload_report = {
        "findings": findings,
        "summary": ai_rep.get("summary"),
        "items": ai_rep.get("items") or [],
        "validation": ai_rep.get("validation") or {},
    }
    text = _format_message(payload_report, run.id)
    try:
        res = await send_telegram_message(token, chat_id, text)
        return res
    except Exception as exc:
        raise HTTPException(502, redact_text(str(exc), [token])) from exc
