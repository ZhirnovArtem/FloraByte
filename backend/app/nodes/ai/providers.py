"""Universal AI Provider Manager and provider adapters (Gemini, OpenAI-compatible, Claude, GigaChat, Ollama, vLLM)."""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from sqlmodel import Session

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import redact_text
from app.core.models import Credential, IntegrationSetting
from app.nodes.ai.llm_client import is_private_or_local_url

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 60.0

SYSTEM_EXPLAIN_PROMPT = (
    "You are a security explainer, NOT a vulnerability detector. "
    "Only explain provided findings. Return a JSON object with keys 'summary' and 'items'. "
    "Each item has integer finding_ref, string explanation (what was found, where, why dangerous), "
    "string risk (severity assessment + potential consequences/impact), "
    "string priority (CRITICAL/HIGH/MEDIUM/LOW remediation priority), "
    "string[] fix_steps (concrete code/config changes). "
    "Reference only provided finding_ref numbers, paths and advisory IDs. "
    "Never fabricate CVEs; never disclose credentials or literal secret values. "
    "Use Russian language. Return JSON only."
)


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    adapter_kind: str  # gemini | openai_compatible | anthropic | gigachat
    auth_type: str  # api_key | oauth2_basic | optional_key
    default_base_url: str
    default_model: str
    supports_model_discovery: bool = True
    requires_url_input: bool = False
    key_hint: str = "Введите API-ключ провайдера"


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "gemini": ProviderSpec(
        id="gemini",
        label="Google Gemini",
        adapter_kind="gemini",
        auth_type="api_key",
        default_base_url="https://generativelanguage.googleapis.com/v1beta",
        default_model="gemini-2.5-flash",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="Google AI Studio API Key (AIza...)",
    ),
    "gigachat": ProviderSpec(
        id="gigachat",
        label="Sber GigaChat",
        adapter_kind="gigachat",
        auth_type="oauth2_basic",
        default_base_url="https://gigachat.devices.sberbank.ru/api/v1",
        default_model="GigaChat",
        supports_model_discovery=True,
        requires_url_input=True,
        key_hint="Authorization key (Base64) или client_id:client_secret",
    ),
    "openai": ProviderSpec(
        id="openai",
        label="OpenAI",
        adapter_kind="openai_compatible",
        auth_type="api_key",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="OpenAI API Key (sk-...)",
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        label="Anthropic Claude",
        adapter_kind="anthropic",
        auth_type="api_key",
        default_base_url="https://api.anthropic.com/v1",
        default_model="claude-3-5-haiku-latest",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="Anthropic API Key (sk-ant-...)",
    ),
    "deepseek": ProviderSpec(
        id="deepseek",
        label="DeepSeek",
        adapter_kind="openai_compatible",
        auth_type="api_key",
        default_base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="DeepSeek API Key (sk-...)",
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        label="OpenRouter",
        adapter_kind="openai_compatible",
        auth_type="api_key",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-4o-mini",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="OpenRouter API Key (sk-or-...)",
    ),
    "mistral": ProviderSpec(
        id="mistral",
        label="Mistral AI",
        adapter_kind="openai_compatible",
        auth_type="api_key",
        default_base_url="https://api.mistral.ai/v1",
        default_model="mistral-small-latest",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="Mistral API Key",
    ),
    "qwen": ProviderSpec(
        id="qwen",
        label="Qwen (Alibaba DashScope)",
        adapter_kind="openai_compatible",
        auth_type="api_key",
        default_base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        default_model="qwen-plus",
        supports_model_discovery=True,
        requires_url_input=False,
        key_hint="DashScope API Key",
    ),
    "ollama": ProviderSpec(
        id="ollama",
        label="Ollama (локальная / закрытый контур)",
        adapter_kind="openai_compatible",
        auth_type="optional_key",
        default_base_url="http://localhost:11434/v1",
        default_model="llama3.2",
        supports_model_discovery=True,
        requires_url_input=True,
        key_hint="Необязателен для локального сервера",
    ),
    "vllm": ProviderSpec(
        id="vllm",
        label="vLLM (локальная / закрытый контур)",
        adapter_kind="openai_compatible",
        auth_type="optional_key",
        default_base_url="http://localhost:8000/v1",
        default_model="Qwen/Qwen2.5-7B-Instruct",
        supports_model_discovery=True,
        requires_url_input=True,
        key_hint="Необязателен для закрытого контура",
    ),
    "openai_compatible": ProviderSpec(
        id="openai_compatible",
        label="Другой OpenAI-compatible API",
        adapter_kind="openai_compatible",
        auth_type="optional_key",
        default_base_url="",
        default_model="",
        supports_model_discovery=True,
        requires_url_input=True,
        key_hint="API-ключ (обязателен для удалённых сервисов)",
    ),
}


def strip_markdown_json_fence(text: str) -> str:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            return "\n".join(lines[1:-1]).strip()
    return cleaned


class BaseProviderAdapter(ABC):
    def __init__(self, spec: ProviderSpec) -> None:
        self.spec = spec

    def resolve_url(self, base_url: str | None) -> str:
        cleaned = (base_url or "").strip().rstrip("/")
        return cleaned or self.spec.default_base_url.rstrip("/")

    def resolve_model(self, model: str | None) -> str:
        return (model or "").strip() or self.spec.default_model

    def validate_config(self, api_key: str | None, model: str | None, base_url: str | None) -> None:
        key = (api_key or "").strip()
        eff_url = self.resolve_url(base_url)
        if self.spec.auth_type == "api_key":
            if not key:
                raise RuntimeError(f"Отсутствует API-ключ для провайдера {self.spec.label}.")
            if any(ch.isspace() for ch in key) or len(key) < 8:
                raise RuntimeError(f"Некорректный формат API-ключа для провайдера {self.spec.label}.")
        elif self.spec.auth_type == "oauth2_basic":
            if not key:
                raise RuntimeError(f"Отсутствует Authorization key для {self.spec.label}.")
            if any(ch.isspace() for ch in key) or len(key) < 8:
                raise RuntimeError(f"Некорректный формат ключа авторизации для {self.spec.label}.")
        else:
            if not eff_url:
                raise RuntimeError(f"Не указан API URL для провайдера {self.spec.label}.")
            if not key and self.spec.id == "openai_compatible" and not is_private_or_local_url(eff_url):
                raise RuntimeError("Отсутствует API-ключ для удалённой OpenAI-compatible модели.")

    @abstractmethod
    async def list_models(self, api_key: str | None, base_url: str | None) -> list[str]:
        ...

    @abstractmethod
    async def test_connection(self, api_key: str | None, model: str | None, base_url: str | None) -> dict[str, Any]:
        ...

    @abstractmethod
    async def explain(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> str:
        """Return JSON string matching {'summary': str, 'items': [...]}."""
        ...

    @abstractmethod
    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = 20.0,
    ) -> str:
        """Generate free-form / JSON text for auxiliary tasks (e.g. workflow generation)."""
        ...


class GeminiAdapter(BaseProviderAdapter):
    async def list_models(self, api_key: str | None, base_url: str | None) -> list[str]:
        key = (api_key or "").strip()
        if not key:
            raise RuntimeError("Отсутствует API-ключ Gemini.")
        eff_url = self.resolve_url(base_url)
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    f"{eff_url}/models",
                    headers={"x-goog-api-key": key},
                    params={"pageSize": 100},
                )
            if resp.status_code in (400, 401, 403):
                raise RuntimeError(f"Неверный API-ключ Gemini или доступ запрещён (HTTP {resp.status_code}).")
            if resp.status_code != 200:
                raise RuntimeError(redact_text(f"Gemini API вернул HTTP {resp.status_code}", [key]))
            models = resp.json().get("models") or []
            out = [
                str(m.get("name", "")).removeprefix("models/").strip()
                for m in models
                if isinstance(m, dict) and "generateContent" in (m.get("supportedGenerationMethods") or [])
            ]
            return sorted({m for m in out if m})
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка соединения с Gemini API: {exc}", [key])) from exc

    async def test_connection(self, api_key: str | None, model: str | None, base_url: str | None) -> dict[str, Any]:
        key = (api_key or "").strip()
        eff_model = self.resolve_model(model)
        try:
            self.validate_config(key, eff_model, base_url)
            available = await self.list_models(key, base_url)
            if not available:
                return {"ok": False, "models": [], "detail": "Gemini API не вернул моделей с поддержкой generateContent."}
            if eff_model and eff_model not in available:
                return {
                    "ok": False,
                    "models": available,
                    "detail": f"API-ключ действителен, но модель '{eff_model}' недоступна для generateContent.",
                }
            return {
                "ok": True,
                "models": available,
                "detail": "Подключение к Gemini API и доступность модели подтверждены.",
            }
        except Exception as exc:
            return {"ok": False, "models": [], "detail": redact_text(str(exc), [key] if key else None)}

    async def explain(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> str:
        # Delegate to app.nodes.ai.explain._call_ai_code_checker so existing AI_CODE_CHECKER
        # integration and test monkeypatches keep working identically.
        from app.nodes.ai.explain import _call_ai_code_checker

        res = await _call_ai_code_checker(canonical_findings, (api_key or "").strip(), (model or "").strip() or None)
        return json.dumps(res, ensure_ascii=False)

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = 20.0,
    ) -> str:
        key = (api_key or "").strip()
        eff_url = self.resolve_url(base_url)
        eff_model = self.resolve_model(model)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{eff_url}/models/{eff_model}:generateContent",
                headers={"x-goog-api-key": key},
                json={"contents": [{"parts": [{"text": f"{system_prompt}\n{user_prompt}"}]}]},
            )
        if resp.status_code != 200:
            raise RuntimeError(redact_text(f"Gemini API HTTP {resp.status_code}", [key] if key else None))
        return str(resp.json()["candidates"][0]["content"]["parts"][0]["text"])


class OpenAICompatibleAdapter(BaseProviderAdapter):
    async def list_models(self, api_key: str | None, base_url: str | None) -> list[str]:
        eff_url = self.resolve_url(base_url)
        if not eff_url:
            raise RuntimeError(f"Не указан API URL для {self.spec.label}.")
        key = (api_key or "").strip()
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        secrets = [key] if key else None
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(f"{eff_url}/models", headers=headers)
            if resp.status_code in (401, 403):
                raise RuntimeError(f"Неверный API-ключ или доступ запрещён ({self.spec.label}, HTTP {resp.status_code}).")
            if resp.status_code != 200:
                raise RuntimeError(redact_text(f"{self.spec.label} вернул HTTP {resp.status_code}", secrets))
            payload = resp.json() if resp.content else {}
            raw_list = payload.get("data") if isinstance(payload, dict) else (payload if isinstance(payload, list) else [])
            names = [
                str(m.get("id") or m.get("name") or "").strip()
                for m in (raw_list or [])
                if isinstance(m, dict) and (m.get("id") or m.get("name"))
            ]
            return sorted({n for n in names if n})
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка соединения с {self.spec.label}: {exc}", secrets)) from exc

    async def test_connection(self, api_key: str | None, model: str | None, base_url: str | None) -> dict[str, Any]:
        key = (api_key or "").strip()
        eff_model = self.resolve_model(model)
        eff_url = self.resolve_url(base_url)
        secrets = [key] if key else None
        try:
            self.validate_config(key, eff_model, eff_url)
            available = await self.list_models(key, eff_url)
            if available and eff_model:
                if eff_model not in available and f"{eff_model}:latest" not in available:
                    return {
                        "ok": False,
                        "models": available,
                        "detail": f"Сервер {self.spec.label} доступен, но модель '{eff_model}' не найдена в /models.",
                    }
            return {
                "ok": True,
                "models": available,
                "detail": f"Подключение к {self.spec.label} и доступность модели подтверждены.",
            }
        except Exception as exc:
            return {"ok": False, "models": [], "detail": redact_text(str(exc), secrets)}

    async def explain(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> str:
        from app.nodes.ai.llm_client import chat_completion

        eff_url = self.resolve_url(base_url)
        eff_model = self.resolve_model(model)
        if not eff_model:
            raise RuntimeError(f"Не указана модель для провайдера {self.spec.label}.")

        safe_input = [{"finding_ref": i, **item} for i, item in enumerate(canonical_findings)]
        raw = await chat_completion(
            [
                {"role": "system", "content": SYSTEM_EXPLAIN_PROMPT},
                {"role": "user", "content": json.dumps(safe_input, ensure_ascii=False)},
            ],
            model=eff_model,
            api_key=(api_key or "").strip() or None,
            base_url=eff_url,
            provider=self.spec.id,
            timeout=timeout,
        )
        return strip_markdown_json_fence(raw)

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = 20.0,
    ) -> str:
        from app.nodes.ai.llm_client import chat_completion

        return await chat_completion(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model=self.resolve_model(model),
            api_key=(api_key or "").strip() or None,
            base_url=self.resolve_url(base_url),
            provider=self.spec.id,
            timeout=timeout,
        )


class AnthropicAdapter(BaseProviderAdapter):
    _CURATED_MODELS = [
        "claude-sonnet-4-20250514",
        "claude-3-7-sonnet-latest",
        "claude-3-5-haiku-latest",
    ]

    def _headers(self, key: str) -> dict[str, str]:
        return {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    async def list_models(self, api_key: str | None, base_url: str | None) -> list[str]:
        key = (api_key or "").strip()
        if not key:
            raise RuntimeError("Отсутствует API-ключ Anthropic Claude.")
        eff_url = self.resolve_url(base_url)
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(f"{eff_url}/models", headers=self._headers(key))
            if resp.status_code in (401, 403):
                raise RuntimeError(f"Неверный API-ключ Anthropic Claude (HTTP {resp.status_code}).")
            if resp.status_code == 200:
                data = resp.json().get("data") or []
                models = sorted({str(m.get("id") or "").strip() for m in data if isinstance(m, dict) and m.get("id")})
                if models:
                    return models
            if resp.status_code == 404:
                return list(self._CURATED_MODELS)
            raise RuntimeError(redact_text(f"Anthropic API вернул HTTP {resp.status_code}", [key]))
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка соединения с Anthropic API: {exc}", [key])) from exc

    async def test_connection(self, api_key: str | None, model: str | None, base_url: str | None) -> dict[str, Any]:
        key = (api_key or "").strip()
        eff_model = self.resolve_model(model)
        try:
            self.validate_config(key, eff_model, base_url)
            available = await self.list_models(key, base_url)
            if available and eff_model and eff_model not in available:
                return {
                    "ok": False,
                    "models": available,
                    "detail": f"Ключ Anthropic действителен, но модель '{eff_model}' не найдена.",
                }
            return {
                "ok": True,
                "models": available,
                "detail": "Подключение к Anthropic Claude подтверждено.",
            }
        except Exception as exc:
            return {"ok": False, "models": [], "detail": redact_text(str(exc), [key] if key else None)}

    async def explain(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> str:
        key = (api_key or "").strip()
        eff_url = self.resolve_url(base_url)
        eff_model = self.resolve_model(model)
        safe_input = [{"finding_ref": i, **item} for i, item in enumerate(canonical_findings)]
        body = {
            "model": eff_model,
            "max_tokens": 4096,
            "system": SYSTEM_EXPLAIN_PROMPT,
            "messages": [{"role": "user", "content": json.dumps(safe_input, ensure_ascii=False)}],
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(f"{eff_url}/messages", headers=self._headers(key), json=body)
            if resp.status_code in (401, 403):
                raise RuntimeError(f"Неверный API-ключ Anthropic Claude (HTTP {resp.status_code}).")
            if resp.status_code >= 400:
                raise RuntimeError(redact_text(f"Anthropic API вернул HTTP {resp.status_code}", [key]))
            data = resp.json()
            blocks = data.get("content") or []
            texts = [str(b.get("text") or "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
            return strip_markdown_json_fence("".join(texts))
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка Anthropic Claude: {exc}", [key])) from exc

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = 20.0,
    ) -> str:
        key = (api_key or "").strip()
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{self.resolve_url(base_url)}/messages",
                headers=self._headers(key),
                json={
                    "model": self.resolve_model(model),
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(redact_text(f"Anthropic API HTTP {resp.status_code}", [key]))
        blocks = resp.json().get("content") or []
        return "".join(str(b.get("text") or "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")


class GigaChatAdapter(BaseProviderAdapter):
    OAUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"

    @staticmethod
    def _basic_credentials(raw_key: str) -> str:
        cleaned = raw_key.strip()
        if cleaned.lower().startswith("basic "):
            cleaned = cleaned[6:].strip()
        elif ":" in cleaned:
            cleaned = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
        return cleaned

    @staticmethod
    def _ssl_verify() -> bool:
        val = os.getenv("GIGACHAT_VERIFY_SSL", "1").strip().lower()
        return val not in ("0", "false", "no")

    async def _fetch_access_token(self, client: httpx.AsyncClient, raw_key: str) -> str:
        basic = self._basic_credentials(raw_key)
        scope = os.getenv("GIGACHAT_SCOPE", "GIGACHAT_API_PERS").strip() or "GIGACHAT_API_PERS"
        resp = await client.post(
            self.OAUTH_URL,
            headers={
                "Authorization": f"Basic {basic}",
                "RqUID": str(uuid.uuid4()),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={"scope": scope},
        )
        if resp.status_code in (400, 401, 403):
            raise RuntimeError(f"Ошибка авторизации GigaChat OAuth2 (HTTP {resp.status_code}). Проверьте Authorization key.")
        if resp.status_code != 200:
            raise RuntimeError(redact_text(f"GigaChat OAuth2 вернул HTTP {resp.status_code}", [raw_key, basic]))
        token = str((resp.json() or {}).get("access_token") or "").strip()
        if not token:
            raise RuntimeError("GigaChat OAuth2 не вернул access_token.")
        return token

    async def list_models(self, api_key: str | None, base_url: str | None) -> list[str]:
        key = (api_key or "").strip()
        if not key:
            raise RuntimeError("Отсутствует ключ авторизации GigaChat.")
        eff_url = self.resolve_url(base_url)
        secrets = [key, self._basic_credentials(key)]
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify()) as client:
                access_token = await self._fetch_access_token(client, key)
                secrets.append(access_token)
                resp = await client.get(
                    f"{eff_url}/models",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                )
            if resp.status_code != 200:
                raise RuntimeError(redact_text(f"GigaChat /models вернул HTTP {resp.status_code}", secrets))
            data = resp.json().get("data") or []
            models = sorted({str(m.get("id") or "").strip() for m in data if isinstance(m, dict) and m.get("id")})
            return models
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка соединения с GigaChat API: {exc}", secrets)) from exc

    async def test_connection(self, api_key: str | None, model: str | None, base_url: str | None) -> dict[str, Any]:
        key = (api_key or "").strip()
        eff_model = self.resolve_model(model)
        secrets = [key] if key else None
        try:
            self.validate_config(key, eff_model, base_url)
            available = await self.list_models(key, base_url)
            if available and eff_model and eff_model not in available:
                return {
                    "ok": False,
                    "models": available,
                    "detail": f"Авторизация GigaChat успешна, но модель '{eff_model}' не найдена.",
                }
            return {
                "ok": True,
                "models": available,
                "detail": "Подключение к GigaChat API и доступность модели подтверждены.",
            }
        except Exception as exc:
            return {"ok": False, "models": [], "detail": redact_text(str(exc), secrets)}

    async def explain(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> str:
        key = (api_key or "").strip()
        eff_url = self.resolve_url(base_url)
        eff_model = self.resolve_model(model)
        secrets = [key, self._basic_credentials(key)]
        safe_input = [{"finding_ref": i, **item} for i, item in enumerate(canonical_findings)]
        body = {
            "model": eff_model,
            "messages": [
                {"role": "system", "content": SYSTEM_EXPLAIN_PROMPT},
                {"role": "user", "content": json.dumps(safe_input, ensure_ascii=False)},
            ],
            "temperature": 0.2,
        }
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=self._ssl_verify()) as client:
                access_token = await self._fetch_access_token(client, key)
                secrets.append(access_token)
                resp = await client.post(
                    f"{eff_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json=body,
                )
            if resp.status_code in (401, 403):
                raise RuntimeError(f"GigaChat отклонил запрос (HTTP {resp.status_code}).")
            if resp.status_code >= 400:
                raise RuntimeError(redact_text(f"GigaChat API вернул HTTP {resp.status_code}", secrets))
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            raw = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            return strip_markdown_json_fence(raw)
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(redact_text(f"Ошибка GigaChat: {exc}", secrets)) from exc

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        api_key: str | None,
        model: str | None,
        base_url: str | None,
        timeout: float = 20.0,
    ) -> str:
        key = (api_key or "").strip()
        eff_url = self.resolve_url(base_url)
        eff_model = self.resolve_model(model)
        async with httpx.AsyncClient(timeout=timeout, verify=self._ssl_verify()) as client:
            access_token = await self._fetch_access_token(client, key)
            resp = await client.post(
                f"{eff_url}/chat/completions",
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json={
                    "model": eff_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(redact_text(f"GigaChat API HTTP {resp.status_code}", [key, access_token]))
        content = resp.json()["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)


class AIProviderManager:
    """Central registry and runtime resolver for all AI provider adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseProviderAdapter] = {}
        for spec in PROVIDER_SPECS.values():
            self.register(spec)

    def register(self, spec: ProviderSpec) -> None:
        if spec.adapter_kind == "gemini":
            self._adapters[spec.id] = GeminiAdapter(spec)
        elif spec.adapter_kind == "anthropic":
            self._adapters[spec.id] = AnthropicAdapter(spec)
        elif spec.adapter_kind == "gigachat":
            self._adapters[spec.id] = GigaChatAdapter(spec)
        else:
            self._adapters[spec.id] = OpenAICompatibleAdapter(spec)

    def list_specs(self) -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "label": s.label,
                "adapter_kind": s.adapter_kind,
                "auth_type": s.auth_type,
                "default_base_url": s.default_base_url,
                "default_model": s.default_model,
                "supports_model_discovery": s.supports_model_discovery,
                "requires_url_input": s.requires_url_input,
                "key_hint": s.key_hint,
            }
            for s in PROVIDER_SPECS.values()
        ]

    def get_adapter(self, provider: str) -> BaseProviderAdapter:
        pid = (provider or "gemini").strip().lower()
        if pid not in self._adapters:
            raise ValueError(
                f"Неизвестный AI-провайдер '{provider}'. Поддерживаются: {', '.join(sorted(self._adapters))}."
            )
        return self._adapters[pid]

    def resolve_runtime_config(
        self,
        *,
        owner_id: str | None = None,
        credential_id: str = "",
        provider_override: str = "",
        model_override: str = "",
        base_url_override: str = "",
    ) -> tuple[str, str | None, str | None, str | None]:
        """Resolve (provider, api_key, model, base_url) dynamically from DB + env without backend restart."""
        settings = get_settings()
        env_key = (settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")).strip() or None
        env_provider = (settings.llm_provider or "gemini").strip().lower()
        env_model = os.getenv("GEMINI_MODEL", "").strip() or (
            settings.llm_model if env_provider != "gemini" else None
        )
        env_base = settings.llm_base_url.strip() or None

        provider = provider_override.strip().lower()
        key: str | None = None
        model: str | None = model_override.strip() or None
        base_url: str | None = base_url_override.strip() or None

        if credential_id:
            with Session(get_engine()) as session:
                cred = session.get(Credential, credential_id)
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
                    active_row = session.get(IntegrationSetting, f"{owner_id}:ai") if owner_id else None
                    if active_row is None:
                        active_row = session.get(IntegrationSetting, "ai")
                    if active_row and active_row.enabled:
                        cfg = active_row.config_json or {}
                        active_prov = str(cfg.get("provider") or "").strip().lower()
                        target_prov = provider or active_prov
                        prof_row = None
                        if owner_id and target_prov:
                            prof_row = session.get(IntegrationSetting, f"{owner_id}:ai:{target_prov}")
                        chosen = prof_row if (prof_row and prof_row.enabled) else (
                            active_row if (not provider or provider == active_prov) else None
                        )
                        if chosen and chosen.enabled:
                            c_cfg = chosen.config_json or {}
                            if not provider and c_cfg.get("provider"):
                                provider = str(c_cfg["provider"]).strip().lower()
                            if chosen.encrypted_secret:
                                try:
                                    saved_key = decrypt(chosen.encrypted_secret).strip()
                                    if saved_key:
                                        key = saved_key
                                except Exception:
                                    pass
                            if not model and c_cfg.get("model"):
                                model = str(c_cfg["model"]).strip()
                            if not base_url and c_cfg.get("base_url"):
                                base_url = str(c_cfg["base_url"]).strip()
            except Exception:
                pass

        eff_provider = provider or env_provider or "gemini"
        if not key and eff_provider == env_provider:
            key = env_key
        if not model and eff_provider == env_provider:
            model = env_model
        if not base_url and eff_provider == env_provider and eff_provider != "gemini":
            base_url = env_base
        return eff_provider, key, model, base_url


provider_manager = AIProviderManager()
