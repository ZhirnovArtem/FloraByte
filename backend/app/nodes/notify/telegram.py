"""notify.telegram — send report summary to Telegram bot with pre-flight verification & auto-integration."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import redact_text
from app.core.models import Credential, IntegrationSetting
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)

TELEGRAM_TIMEOUT_SEC = 15.0
TELEGRAM_MAX_RETRIES = 3
_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")


class Params(BaseModel):
    credential_id: str = Field("", description="Telegram bot credential id")
    chat_id: str = Field("", description="Override chat id if not in credential/env")
    dry_run: bool = Field(False, description="Safe test mode: format and redact message without calling Telegram API")


def normalize_bot_token(raw: str) -> str:
    """Trim whitespace and strip accidental leading 'bot' prefix (e.g. 'bot123456:ABC')."""
    token = (raw or "").strip()
    if re.match(r"^bot\d+:", token, re.IGNORECASE):
        token = token[3:].strip()
    return token


def validate_token_format(token: str) -> None:
    if not token:
        raise ValueError("Токен Telegram-бота не задан.")
    if not _TOKEN_RE.match(token):
        raise ValueError(
            "Неверный формат токена Telegram-бота. Ожидается формат <bot_id>:<secret> (например 123456789:AA...)."
        )


def _explain_telegram_http_error(status_code: int, description: str = "") -> str:
    desc_l = (description or "").lower()
    if status_code == 404:
        return (
            "Telegram API вернул HTTP 404 (Not Found): проверьте правильность Bot Token "
            "(токен не должен содержать лишних пробелов или лишнего префикса 'bot')."
        )
    if status_code == 401:
        return "Telegram API отклонил токен бота (HTTP 401 Unauthorized): проверьте или перевыпустите токен в @BotFather."
    if status_code == 400:
        if "chat not found" in desc_l:
            return (
                "Чат Telegram не найден (chat_id неверен или пользователь ещё не нажал /start у бота)."
            )
        if "bot was blocked" in desc_l or "forbidden" in desc_l:
            return "Бот заблокирован пользователем или не добавлен в указанный чат."
        return f"Некорректный запрос к Telegram API (HTTP 400): {description or 'проверьте chat_id'}"
    if status_code == 403:
        return "Доступ запрещён (HTTP 403): бот заблокирован или не имеет прав писать в этот чат."
    return f"Telegram API error HTTP {status_code}" + (f": {description}" if description else "")


def _resolve_token_and_chat(params: Params, owner_id: str | None = None) -> tuple[str, str]:
    settings = get_settings()
    token = normalize_bot_token(settings.telegram_bot_token)
    chat_id = (params.chat_id or settings.telegram_chat_id or "").strip()

    if params.credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, params.credential_id)
            if cred and cred.encrypted_value:
                raw = decrypt(cred.encrypted_value)
                if "|" in raw:
                    parts = raw.split("|", 1)
                    token = token or normalize_bot_token(parts[0])
                    chat_id = chat_id or parts[1].strip()
                else:
                    token = token or normalize_bot_token(raw)
    else:
        # Auto-resolve saved Telegram integration from DB if available
        try:
            with Session(get_engine()) as session:
                integ = None
                if owner_id:
                    integ = session.get(IntegrationSetting, f"{owner_id}:telegram")
                if integ is None:
                    integ = session.get(IntegrationSetting, "telegram")
                if integ and integ.enabled:
                    cfg = integ.config_json or {}
                    if not token and integ.encrypted_secret:
                        try:
                            token = normalize_bot_token(decrypt(integ.encrypted_secret))
                        except Exception:
                            pass
                    if not chat_id and cfg.get("chat_id"):
                        chat_id = str(cfg["chat_id"]).strip()
        except Exception:
            pass

    if not token:
        raise ValueError(
            "Telegram-бот не настроен. Укажите Bot Token в настройках интеграций или TELEGRAM_BOT_TOKEN."
        )
    if ":" not in token or not token.split(":", 1)[0].isdigit():
        raise ValueError(
            "Неверный формат токена Telegram-бота. Ожидается формат <bot_id>:<secret> (например 123456789:AA...)."
        )
    if not chat_id:
        raise ValueError(
            "Не указан chat_id для Telegram. Укажите его в настройках интеграций или параметрах блока."
        )
    return token, chat_id


async def verify_telegram_connection(raw_token: str, raw_chat_id: str = "") -> dict[str, Any]:
    """Verify bot token via getMe (and optionally chat_id via getChat)."""
    token = normalize_bot_token(raw_token)
    chat_id = (raw_chat_id or "").strip()
    try:
        validate_token_format(token)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    try:
        async with httpx.AsyncClient(timeout=TELEGRAM_TIMEOUT_SEC) as client:
            me_resp = await client.get(f"https://api.telegram.org/bot{token}/getMe")
            try:
                me_data = me_resp.json()
            except Exception:
                me_data = {}
            if me_resp.status_code != 200 or not me_data.get("ok"):
                err = _explain_telegram_http_error(me_resp.status_code, str(me_data.get("description") or ""))
                return {"ok": False, "error": redact_text(err, [token])}
            bot_info = me_data.get("result") or {}
            bot_username = bot_info.get("username") or ""

            chat_title = ""
            if chat_id:
                chat_resp = await client.get(
                    f"https://api.telegram.org/bot{token}/getChat",
                    params={"chat_id": chat_id},
                )
                try:
                    chat_data = chat_resp.json()
                except Exception:
                    chat_data = {}
                if chat_resp.status_code != 200 or not chat_data.get("ok"):
                    err = _explain_telegram_http_error(
                        chat_resp.status_code, str(chat_data.get("description") or "")
                    )
                    return {
                        "ok": False,
                        "bot_username": bot_username,
                        "error": redact_text(err, [token]),
                    }
                c_res = chat_data.get("result") or {}
                chat_title = c_res.get("title") or c_res.get("username") or str(c_res.get("id") or chat_id)

            return {
                "ok": True,
                "bot_username": bot_username,
                "chat_title": chat_title,
                "error": None,
            }
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        return {"ok": False, "error": redact_text(f"Ошибка сети при проверке Telegram: {exc}", [token])}


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

    if report.get("summary"):
        lines.extend(["", f"Заключение: {str(report['summary'])[:450]}"])

    ai_items = report.get("items") or []
    if ai_items:
        lines.extend(["", "AI-рекомендации:"])
        for item in ai_items[:5]:
            if not isinstance(item, dict):
                continue
            ref = item.get("finding_ref", "?")
            explanation = str(item.get("explanation") or "").replace("`", "'")
            risk = str(item.get("risk") or "").replace("`", "'")
            steps = item.get("fix_steps") or []
            lines.append(f"• Находка #{ref}: {explanation[:180]}")
            if risk:
                lines.append(f"  Последствия: {risk[:140]}")
            if steps:
                lines.append(f"  Исправление: {str(steps[0])[:240]}")
        val = report.get("validation") or {}
        mode = val.get("mode", "")
        if mode == "fallback":
            lines.append("(AI недоступен или с ошибкой: показаны резервные рекомендации)")

    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:3990] + "\n…"
    return redact_text(text)


async def send_telegram_message(token: str, chat_id: str, text: str) -> dict[str, Any]:
    token = normalize_bot_token(token)
    if not token or ":" not in token or not token.split(":", 1)[0].isdigit():
        raise ValueError(
            "Неверный формат токена Telegram-бота. Ожидается формат <bot_id>:<secret> (например 123456789:AA...)."
        )
    chat_id = (chat_id or "").strip()
    if not chat_id:
        raise ValueError("Не указан chat_id для Telegram.")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": redact_text(text, [token]),
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    data: dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=TELEGRAM_TIMEOUT_SEC) as client:
            for attempt in range(TELEGRAM_MAX_RETRIES):
                try:
                    resp = await client.post(url, json=payload)
                    try:
                        resp_json = resp.json()
                    except Exception:
                        resp_json = {}
                    desc = str(resp_json.get("description") or "")
                    if resp.status_code == 400 and "parse_mode" in payload and "parse" in desc.lower():
                        payload.pop("parse_mode", None)
                        resp = await client.post(url, json=payload)
                        try:
                            resp_json = resp.json()
                        except Exception:
                            resp_json = {}
                        desc = str(resp_json.get("description") or "")
                    if resp.status_code == 200:
                        data = resp_json
                        if not data.get("ok"):
                            raise RuntimeError(desc or "Telegram API rejected the message")
                        break
                    if resp.status_code in (429, 500, 502, 503, 504) and attempt + 1 < TELEGRAM_MAX_RETRIES:
                        await asyncio.sleep(0.25 * (2 ** attempt))
                        continue
                    raise RuntimeError(_explain_telegram_http_error(resp.status_code, desc))
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    if attempt + 1 < TELEGRAM_MAX_RETRIES:
                        await asyncio.sleep(0.25 * (2 ** attempt))
                        continue
                    raise RuntimeError(redact_text(f"Telegram delivery error: {exc}", [token])) from exc
    except Exception as exc:
        raise RuntimeError(redact_text(str(exc), [token])) from exc

    return {
        "sent": True,
        "chat_id": chat_id,
        "message_id": (data.get("result") or {}).get("message_id"),
    }


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

        token, chat_id = _resolve_token_and_chat(params, owner_id=ctx.owner_id)
        out = await send_telegram_message(token, chat_id, text)
        logger.info("Telegram message sent to chat_id=%s for run=%s", chat_id, ctx.run_id)
        return {"out": out}
