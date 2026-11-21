"""Unified OpenAI-compatible LLM client (Ollama, vLLM, OpenAI-compatible, Gemini OpenAI endpoint)."""

from __future__ import annotations

import ipaddress
import json
import logging
from urllib.parse import urlsplit

import httpx

from app.config import get_settings
from app.core.masking import redact_text

logger = logging.getLogger(__name__)

OPENAI_STYLE_PROVIDERS = frozenset({"ollama", "vllm", "openai_compatible"})
SUPPORTED_LLM_PROVIDERS = frozenset({"gemini", *OPENAI_STYLE_PROVIDERS})
DEFAULT_PROVIDER_BASE_URLS = {
    "ollama": "http://localhost:11434/v1",
    "vllm": "http://localhost:8000/v1",
}
DEFAULT_PROVIDER_MODELS = {
    "ollama": "llama3.2",
    "vllm": "Qwen/Qwen2.5-7B-Instruct",
    "gemini": "gemini-2.5-flash",
}


def resolve_base_url(provider: str, base_url: str | None = None) -> str:
    cleaned = (base_url or "").strip().rstrip("/")
    if cleaned:
        return cleaned
    if provider in DEFAULT_PROVIDER_BASE_URLS:
        return DEFAULT_PROVIDER_BASE_URLS[provider]
    return get_settings().llm_base_url.strip().rstrip("/")


def is_private_or_local_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").strip().lower()
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        # Single-label Docker/Compose service name (e.g. "ollama", "vllm")
        return "." not in host


async def verify_openai_compatible_connection(
    base_url: str,
    model: str = "",
    api_key: str | None = None,
    timeout: float = 12.0,
) -> dict[str, object]:
    target_base = (base_url or "").strip().rstrip("/")
    if not target_base:
        return {"ok": False, "detail": "Не указан base_url для локального / OpenAI-compatible провайдера."}
    headers = {"Authorization": f"Bearer {api_key.strip()}"} if api_key and api_key.strip() else {}
    secrets = [api_key.strip()] if api_key and api_key.strip() else None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{target_base}/models", headers=headers)
        if resp.status_code != 200:
            return {
                "ok": False,
                "detail": redact_text(f"LLM API вернул HTTP {resp.status_code}", secrets),
            }
        data = resp.json() if resp.content else {}
        models_raw = data.get("data") if isinstance(data, dict) else None
        if isinstance(models_raw, list) and model.strip():
            available_ids = {
                str(m.get("id") or "").strip()
                for m in models_raw
                if isinstance(m, dict) and m.get("id")
            }
            if available_ids and model.strip() not in available_ids:
                # Allow Ollama tag shorthand (e.g. "llama3.2" matching "llama3.2:latest")
                if f"{model.strip()}:latest" not in available_ids:
                    return {
                        "ok": False,
                        "detail": f"Сервер доступен, но модель '{model.strip()}' не найдена в /models.",
                    }
        return {"ok": True, "detail": "Подключение к LLM API и доступность модели подтверждены."}
    except Exception as exc:
        return {"ok": False, "detail": redact_text(str(exc), secrets)}


async def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    provider: str = "openai_compatible",
    temperature: float = 0.2,
    timeout: float | None = None,
) -> str:
    settings = get_settings()
    base = resolve_base_url(provider, base_url)
    key = (api_key or "").strip() or (settings.llm_api_key or "").strip()
    mdl = (model or "").strip() or DEFAULT_PROVIDER_MODELS.get(provider) or settings.llm_model
    timeout = timeout or settings.llm_timeout_sec

    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    body = {
        "model": mdl,
        "messages": messages,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }

    secrets = [key] if key else None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                # Some Ollama/vLLM builds reject response_format — retry without it
                body.pop("response_format", None)
                resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise RuntimeError(
                    redact_text(f"LLM API ({provider}) вернул HTTP {resp.status_code}", secrets)
                )
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
    except Exception as exc:
        raise RuntimeError(redact_text(str(exc), secrets)) from exc
