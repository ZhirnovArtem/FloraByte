"""notify.telegram — send report summary to Telegram bot."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import redact_text
from app.core.models import Credential
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from sqlmodel import Session

logger = logging.getLogger(__name__)

TELEGRAM_TIMEOUT_SEC = 15.0
TELEGRAM_MAX_RETRIES = 3


class Params(BaseModel):
    credential_id: str = Field("", description="Telegram bot credential id")
    chat_id: str = Field("", description="Override chat id if not in credential/env")
    dry_run: bool = Field(False, description="Safe test mode: format and redact message without calling Telegram API")


def _resolve_token_and_chat(params: Params) -> tuple[str, str]:
    settings = get_settings()
    token = settings.telegram_bot_token
    chat_id = params.chat_id or settings.telegram_chat_id

    if params.credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, params.credential_id)
            if cred and cred.encrypted_value:
                raw = decrypt(cred.encrypted_value)
                # formats: "token" or "token|chat_id" or JSON-like
                if "|" in raw:
                    parts = raw.split("|", 1)
                    token = token or parts[0].strip()
                    chat_id = chat_id or parts[1].strip()
                else:
                    token = token or raw.strip()

    if not token:
        raise ValueError(
            "Telegram bot token not configured. Set TELEGRAM_BOT_TOKEN env, "
            "or credential_id"
        )
    if not chat_id:
        raise ValueError(
            "Telegram chat_id not configured. Set TELEGRAM_CHAT_ID env, "
            "credential value as token|chat_id, or params.chat_id"
        )
    return token, chat_id


def _format_message(report: dict[str, Any] | None, run_id: str) -> str:
    if not report:
        return f"AI Security Workflow\nRun: {run_id}\nНаходок нет."

    findings = report.get("findings") or []
    if not findings and isinstance(report.get("report_json"), dict):
        findings = report["report_json"].get("findings") or []

    lines = [
        "🔒 *AI Security Workflow*",
        f"Run: `{run_id}`",
        f"Находок: *{len(findings)}*",
        "",
    ]
    for i, f in enumerate(findings[:15], 1):
        cat = f.get("category", "?")
        path = f.get("path", "?")
        sev = f.get("severity") or "—"
        if cat == "SCA":
            detail = f"{f.get('group')}:{f.get('artifact')}@{f.get('version')} ({f.get('advisoryId')})"
        else:
            detail = f.get("class") or "—"
            line = f.get("line")
            if line:
                detail = f"{detail} :{line}"
        lines.append(f"{i}. [{cat}] `{path}` — {detail} ({sev})")

    if len(findings) > 15:
        lines.append(f"… и ещё {len(findings) - 15}")

    md = report.get("report_md")
    if md and len(findings) == 0:
        lines.append("")
        lines.append("Находок нет.")

    ai_items = report.get("items") or []
    if ai_items:
        lines.extend(["", "AI-рекомендации:"])
        for item in ai_items[:5]:
            if not isinstance(item, dict):
                continue
            ref = item.get("finding_ref", "?")
            explanation = str(item.get("explanation") or "").replace("`", "'")
            steps = item.get("fix_steps") or []
            lines.append(f"• Находка #{ref}: {explanation[:200]}")
            if steps:
                lines.append(f"  Исправление: {str(steps[0])[:260]}")
        mode = (report.get("validation") or {}).get("mode", "")
        if mode == "fallback":
            lines.append("(AI недоступен: показаны резервные рекомендации)")

    text = "\n".join(lines)
    # Telegram limit ~4096
    if len(text) > 4000:
        text = text[:3990] + "\n…"
    return redact_text(text)


@register_node
class TelegramNotifyNode(BaseNode):
    type = "notify.telegram"
    label = "Telegram"
    group = "notify"
    inputs = [
        Port(name="report", kind="Report"),
        Port(name="in", kind="Any"),
    ]
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        report = inputs.get("report") or inputs.get("in")
        if isinstance(report, dict) and "report" in report and "findings" not in report:
            report = report["report"]

        text = _format_message(report if isinstance(report, dict) else None, ctx.run_id)

        if params.dry_run:
            target_chat = params.chat_id or get_settings().telegram_chat_id or "dry-run"
            logger.info("Telegram dry_run for run=%s chat_id=%s", ctx.run_id, target_chat)
            return {
                "out": {
                    "sent": False,
                    "dry_run": True,
                    "chat_id": target_chat,
                    "preview_length": len(text),
                    "preview": redact_text(text[:400]),
                }
            }

        token, chat_id = _resolve_token_and_chat(params)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        last_err: Exception | None = None
        data: dict[str, Any] = {}
        try:
            async with httpx.AsyncClient(timeout=TELEGRAM_TIMEOUT_SEC) as client:
                for attempt in range(TELEGRAM_MAX_RETRIES):
                    try:
                        resp = await client.post(url, json=payload)
                        if resp.status_code == 400 and "parse_mode" in payload:
                            # retry without markdown if parse error
                            payload.pop("parse_mode", None)
                            resp = await client.post(url, json=payload)
                        if resp.status_code == 200:
                            data = resp.json()
                            if not data.get("ok"):
                                raise RuntimeError("Telegram API rejected the message")
                            break
                        if resp.status_code in (429, 500, 502, 503, 504) and attempt + 1 < TELEGRAM_MAX_RETRIES:
                            await asyncio.sleep(0.25 * (2 ** attempt))
                            continue
                        raise RuntimeError(f"Telegram API error HTTP {resp.status_code}")
                    except (httpx.TimeoutException, httpx.TransportError) as exc:
                        last_err = exc
                        if attempt + 1 < TELEGRAM_MAX_RETRIES:
                            await asyncio.sleep(0.25 * (2 ** attempt))
                            continue
                        raise RuntimeError(redact_text(f"Telegram delivery error: {exc}", [token])) from exc
        except Exception as exc:
            raise RuntimeError(redact_text(str(exc), [token])) from exc

        logger.info("Telegram message sent to chat_id=%s for run=%s", chat_id, ctx.run_id)
        return {
            "out": {
                "sent": True,
                "chat_id": chat_id,
                "message_id": (data.get("result") or {}).get("message_id"),
            }
        }
