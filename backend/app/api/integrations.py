"""Integrations API — one-time encrypted setup for AI and Telegram, plus connection checks and on-demand send."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.auth import check_owner, get_current_user
from app.core.crypto import decrypt, encrypt
from app.core.db import get_session
from app.core.masking import mask_secret, redact_text
from app.core.models import IntegrationSetting, Run, User
from app.core.run_analytics import load_run_findings
from app.nodes.ai.llm_client import is_private_or_local_url
from app.nodes.ai.providers import PROVIDER_SPECS, provider_manager
from app.nodes.notify.telegram import (
    _format_message,
    normalize_bot_token,
    send_telegram_message,
    validate_token_format,
    verify_telegram_connection,
)

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


class AiIntegrationUpdate(BaseModel):
    provider: str = Field("gemini", description="Provider id from /api/integrations/ai/providers")
    model: str = Field("", description="Model identifier")
    base_url: str = Field("", description="Optional provider base URL")
    api_key: str = Field("", description="Optional new API key (keeps existing if blank)")
    enabled: bool = True
    activate: bool = True


class AiIntegrationTest(BaseModel):
    provider: str = ""
    model: str = ""
    base_url: str = ""
    api_key: str = ""


class AiModelsRequest(BaseModel):
    provider: str = ""
    base_url: str = ""
    api_key: str = ""


class AiActivateRequest(BaseModel):
    provider: str = Field(..., min_length=1)


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


def _profile_key(user: Optional[User], provider: str) -> str:
    pid = provider.strip().lower()
    return f"{user.id}:ai:{pid}" if user is not None else f"ai:{pid}"


def _decrypt_row_secret(row: IntegrationSetting | None) -> str:
    if not row or not row.encrypted_secret:
        return ""
    try:
        return decrypt(row.encrypted_secret).strip()
    except Exception:
        return ""


def _is_configured_provider(provider: str, key: str, base_url: str) -> bool:
    if key:
        return True
    spec = PROVIDER_SPECS.get(provider)
    if not spec or spec.auth_type != "optional_key":
        return False
    if provider in ("ollama", "vllm"):
        return bool(base_url)
    return is_private_or_local_url(base_url)


def _read_ai_status(session: Session, user: Optional[User] = None) -> dict[str, Any]:
    settings = get_settings()
    row = _get_integ_row(session, user, "ai")
    env_provider = (settings.llm_provider or "gemini").strip().lower()
    env_key = (settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")).strip()

    if row and row.enabled:
        cfg = row.config_json or {}
        provider = str(cfg.get("provider") or env_provider or "gemini").strip().lower()
        spec = PROVIDER_SPECS.get(provider)
        prof_row = session.get(IntegrationSetting, _profile_key(user, provider))
        saved_key = _decrypt_row_secret(prof_row) or _decrypt_row_secret(row)
        effective_key = saved_key or (env_key if provider == env_provider else "")
        raw_base = str(cfg.get("base_url") or (prof_row.config_json or {}).get("base_url") if prof_row else cfg.get("base_url") or "")
        base_url = spec.default_base_url if (spec and not raw_base) else raw_base
        model = str(cfg.get("model") or (spec.default_model if spec else "") or "gemini-2.5-flash")
        configured = _is_configured_provider(provider, effective_key, base_url)
        source = (
            "settings"
            if saved_key
            else ("env" if (env_key and provider == env_provider) else ("local" if configured else "none"))
        )
        return {
            "configured": configured,
            "enabled": row.enabled,
            "source": source,
            "provider": provider,
            "provider_label": spec.label if spec else provider,
            "model": model,
            "base_url": base_url,
            "api_key_preview": mask_secret(effective_key, keep_last=4) if effective_key else "",
        }

    default_spec = PROVIDER_SPECS.get(env_provider)
    default_base = (
        settings.llm_base_url
        if env_provider != "gemini"
        else (default_spec.default_base_url if default_spec else "")
    )
    default_model = (
        os.getenv("GEMINI_MODEL", "").strip()
        or (default_spec.default_model if default_spec else "")
        or settings.llm_model
        or "gemini-2.5-flash"
    )
    configured = _is_configured_provider(env_provider, env_key, default_base)
    return {
        "configured": configured,
        "enabled": configured,
        "source": "env" if env_key else ("local" if configured else "none"),
        "provider": env_provider,
        "provider_label": default_spec.label if default_spec else env_provider,
        "model": default_model,
        "base_url": default_base,
        "api_key_preview": mask_secret(env_key, keep_last=4) if env_key else "",
    }


def _list_saved_ai_profiles(session: Session, user: Optional[User]) -> list[dict[str, Any]]:
    active = _read_ai_status(session, user)
    active_provider = active["provider"] if active["configured"] else ""
    profiles: list[dict[str, Any]] = []
    for pid, spec in PROVIDER_SPECS.items():
        row = session.get(IntegrationSetting, _profile_key(user, pid))
        if not row or not row.enabled:
            continue
        cfg = row.config_json or {}
        key = _decrypt_row_secret(row)
        base_url = str(cfg.get("base_url") or spec.default_base_url)
        model = str(cfg.get("model") or spec.default_model)
        profiles.append(
            {
                "provider": pid,
                "label": spec.label,
                "model": model,
                "base_url": base_url,
                "configured": _is_configured_provider(pid, key, base_url),
                "is_active": pid == active_provider and active["source"] == "settings",
                "api_key_preview": mask_secret(key, keep_last=4) if key else "",
            }
        )
    return profiles


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


@router.get("/ai/providers")
def list_ai_providers(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    return {
        "providers": provider_manager.list_specs(),
        "profiles": _list_saved_ai_profiles(session, user),
        "active": _read_ai_status(session, user),
    }


@router.put("/ai")
def save_ai_integration(
    body: AiIntegrationUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    provider = body.provider.strip().lower() or "gemini"
    if provider not in PROVIDER_SPECS:
        raise HTTPException(400, f"Неизвестный AI-провайдер: {provider}")
    spec = PROVIDER_SPECS[provider]

    prof_key = _profile_key(user, provider)
    prof_row = session.get(IntegrationSetting, prof_key)
    active_key = _integ_key(user, "ai")
    active_row = session.get(IntegrationSetting, active_key)

    secret = prof_row.encrypted_secret if prof_row else ""
    if not secret and active_row and (active_row.config_json or {}).get("provider") == provider:
        secret = active_row.encrypted_secret
    if body.api_key.strip():
        secret = encrypt(body.api_key.strip())

    model = body.model.strip() or spec.default_model
    base_url = body.base_url.strip() or spec.default_base_url
    cfg = {"provider": provider, "model": model, "base_url": base_url}

    if not prof_row:
        prof_row = IntegrationSetting(kind=prof_key)
    prof_row.enabled = body.enabled
    prof_row.encrypted_secret = secret
    prof_row.config_json = cfg
    prof_row.updated_at = datetime.now(timezone.utc)
    session.add(prof_row)

    if body.activate:
        if not active_row:
            active_row = IntegrationSetting(kind=active_key)
        active_row.enabled = body.enabled
        active_row.encrypted_secret = secret
        active_row.config_json = cfg
        active_row.updated_at = datetime.now(timezone.utc)
        session.add(active_row)

    session.commit()
    return _read_ai_status(session, user)


@router.post("/ai/activate")
def activate_ai_provider(
    body: AiActivateRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    provider = body.provider.strip().lower()
    if provider not in PROVIDER_SPECS:
        raise HTTPException(400, f"Неизвестный AI-провайдер: {provider}")
    prof_row = session.get(IntegrationSetting, _profile_key(user, provider))
    if not prof_row or not prof_row.enabled:
        raise HTTPException(404, f"Сохранённый профиль для {provider} не найден")

    active_key = _integ_key(user, "ai")
    active_row = session.get(IntegrationSetting, active_key)
    if not active_row:
        active_row = IntegrationSetting(kind=active_key)
    active_row.enabled = True
    active_row.encrypted_secret = prof_row.encrypted_secret
    active_row.config_json = dict(prof_row.config_json or {"provider": provider})
    active_row.updated_at = datetime.now(timezone.utc)
    session.add(active_row)
    session.commit()
    return _read_ai_status(session, user)


def _resolve_test_params(
    session: Session,
    user: Optional[User],
    provider_raw: str,
    model_raw: str,
    base_url_raw: str,
    api_key_raw: str,
) -> tuple[str, str, str, str]:
    status = _read_ai_status(session, user)
    settings = get_settings()
    provider = (provider_raw or status["provider"] or "gemini").strip().lower()
    spec = PROVIDER_SPECS.get(provider)
    prof_row = session.get(IntegrationSetting, _profile_key(user, provider))
    active_row = _get_integ_row(session, user, "ai")

    prof_cfg = (prof_row.config_json or {}) if prof_row else {}
    model = (
        model_raw.strip()
        or str(prof_cfg.get("model") or "")
        or (status["model"] if provider == status["provider"] else "")
        or (spec.default_model if spec else "")
    )
    base_url = (
        base_url_raw.strip()
        or str(prof_cfg.get("base_url") or "")
        or (status["base_url"] if provider == status["provider"] else "")
        or (spec.default_base_url if spec else "")
    )

    key = api_key_raw.strip()
    if not key:
        key = _decrypt_row_secret(prof_row)
    if not key and active_row and (active_row.config_json or {}).get("provider") == provider:
        key = _decrypt_row_secret(active_row)
    if not key and provider == (settings.llm_provider or "gemini").strip().lower():
        key = (settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")).strip()
    return provider, model, base_url, key


@router.post("/ai/models")
async def discover_ai_models(
    body: AiModelsRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    provider, _, base_url, key = _resolve_test_params(
        session, user, body.provider, "", body.base_url, body.api_key
    )
    try:
        adapter = provider_manager.get_adapter(provider)
        models = await adapter.list_models(key, base_url)
        return {"ok": True, "provider": provider, "models": models, "detail": f"Найдено моделей: {len(models)}"}
    except Exception as exc:
        return {"ok": False, "provider": provider, "models": [], "detail": redact_text(str(exc), [key] if key else None)}


@router.post("/ai/test")
async def test_ai_integration(
    body: AiIntegrationTest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    provider, model, base_url, key = _resolve_test_params(
        session, user, body.provider, body.model, body.base_url, body.api_key
    )
    try:
        adapter = provider_manager.get_adapter(provider)
    except ValueError as exc:
        return {"ok": False, "provider": provider, "model": model, "models": [], "detail": str(exc)}
    res = await adapter.test_connection(key, model, base_url)
    return {"provider": provider, "model": model, **res}


@router.delete("/ai")
def delete_ai_integration(
    provider: str = Query(default="", description="Optional provider id to delete"),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    pid = provider.strip().lower()
    active_row = session.get(IntegrationSetting, _integ_key(user, "ai"))
    if pid:
        prof_row = session.get(IntegrationSetting, _profile_key(user, pid))
        if prof_row:
            session.delete(prof_row)
        if active_row and (active_row.config_json or {}).get("provider") == pid:
            session.delete(active_row)
    else:
        if active_row:
            active_pid = str((active_row.config_json or {}).get("provider") or "").strip().lower()
            session.delete(active_row)
            if active_pid:
                prof_row = session.get(IntegrationSetting, _profile_key(user, active_pid))
                if prof_row:
                    session.delete(prof_row)
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
