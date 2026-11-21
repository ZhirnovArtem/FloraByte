"""Phase 8 tests: Telegram and Webhook delivery, retries, dry_run safe mode, and secret redaction."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.config import get_settings
from app.nodes.base import NodeContext
from app.nodes.notify.telegram import Params as TgParams, TelegramNotifyNode
from app.nodes.notify.webhook import Params as WhParams, WebhookNotifyNode


@pytest.mark.asyncio
async def test_telegram_dry_run_safe_and_redacted(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    get_settings.cache_clear()

    node = TelegramNotifyNode()
    ctx = NodeContext(run_id="r-tg-dry", node_id="tg1", workspace=tmp_path)
    report = {
        "findings": [
            {
                "category": "SECRET",
                "path": "App.kt",
                "class": "api-key",
                "line": 7,
                "severity": "HIGH",
                "description": "api_key='sk-LeakTest1234567890abcdef'",
            }
        ],
        "items": [
            {"finding_ref": 0, "explanation": "Found hardcoded key", "fix_steps": ["Use env"]}
        ],
    }
    out = await node.run(ctx, {"report": report}, TgParams(dry_run=True))
    assert out["out"]["dry_run"] is True
    assert out["out"]["sent"] is False
    assert "sk-LeakTest1234567890abcdef" not in out["out"]["preview"]


@pytest.mark.asyncio
async def test_telegram_retry_on_503_and_redacts_token_on_error(tmp_path, monkeypatch):
    secret_tok = "123456789:AATestSecretBotTokenForPhase8"
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", secret_tok)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "99999")
    get_settings.cache_clear()

    calls = 0

    async def fake_post(self, url, json=None, **kwargs):
        nonlocal calls
        calls += 1
        req = httpx.Request("POST", url)
        if calls == 1:
            return httpx.Response(503, request=req)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 42}}, request=req)

    node = TelegramNotifyNode()
    ctx = NodeContext(run_id="r-tg-retry", node_id="tg1", workspace=tmp_path)
    with patch.object(httpx.AsyncClient, "post", new=fake_post), patch("asyncio.sleep", new=AsyncMock()):
        out = await node.run(ctx, {"report": {"findings": []}}, TgParams())
    assert calls == 2
    assert out["out"]["sent"] is True
    assert out["out"]["message_id"] == 42

    # Ensure transport error redacts token
    async def failing_post(self, url, json=None, **kwargs):
        raise httpx.ConnectError(f"Failed connecting to https://api.telegram.org/bot{secret_tok}/sendMessage")

    with patch.object(httpx.AsyncClient, "post", new=failing_post), patch("asyncio.sleep", new=AsyncMock()):
        with pytest.raises(RuntimeError) as exc_info:
            await node.run(ctx, {"report": {"findings": []}}, TgParams())
    assert secret_tok not in str(exc_info.value)


@pytest.mark.asyncio
async def test_webhook_dry_run_retry_and_redirect_rejection(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOK_HOST_ALLOWLIST", "")
    get_settings.cache_clear()

    fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    loop = asyncio.get_running_loop()

    node = WebhookNotifyNode()
    ctx = NodeContext(run_id="r-wh", node_id="wh1", workspace=tmp_path)

    # Dry run validates SSRF & redacts secrets without HTTP POST
    with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=fake_addr)):
        dry = await node.run(
            ctx,
            {"report": {"findings": [], "note": "ghp_SecretTokenShouldNotLeak1234567890"}},
            WhParams(url="https://hooks.example.com/cb", dry_run=True),
        )
    assert dry["out"]["dry_run"] is True
    assert dry["out"]["sent"] is False

    # Retry on 502 succeeds on 2nd attempt
    attempts = 0

    class _FakeStreamCtx:
        def __init__(self, status_code: int):
            self.status_code = status_code

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def aiter_bytes(self):
            yield b'{"ok":true}'

    def fake_stream(self, method, url, **kwargs):
        nonlocal attempts
        attempts += 1
        return _FakeStreamCtx(502 if attempts == 1 else 200)

    with (
        patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=fake_addr)),
        patch.object(httpx.AsyncClient, "stream", new=fake_stream),
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        ok = await node.run(ctx, {"report": {"findings": []}}, WhParams(url="https://hooks.example.com/cb"))
    assert attempts == 2
    assert ok["out"]["sent"] is True
    assert ok["out"]["status_code"] == 200

    # 302 redirect fails immediately without retry
    redir_attempts = 0

    def fake_redirect(self, method, url, **kwargs):
        nonlocal redir_attempts
        redir_attempts += 1
        return _FakeStreamCtx(302)

    with (
        patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=fake_addr)),
        patch.object(httpx.AsyncClient, "stream", new=fake_redirect),
    ):
        with pytest.raises(RuntimeError, match="redirects not permitted"):
            await node.run(ctx, {"report": {"findings": []}}, WhParams(url="https://hooks.example.com/cb"))
    assert redir_attempts == 1
