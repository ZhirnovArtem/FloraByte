"""OpenAI-compatible LLM client (Gemini / Ollama / vLLM via base_url switch)."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


async def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.2,
    timeout: float | None = None,
) -> str:
    settings = get_settings()
    base = (base_url or settings.llm_base_url).rstrip("/")
    key = api_key or settings.llm_api_key
    mdl = model or settings.llm_model
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

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 400:
            # some providers reject response_format — retry without
            body.pop("response_format", None)
            resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else json.dumps(content)
