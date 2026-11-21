"""notify.email — send security report summary via SMTP (STARTTLS/SSL) or Resend HTTPS API."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import redact_text
from app.core.models import Credential, IntegrationSetting, User
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RESEND_API_URL = "https://api.resend.com/emails"


def normalize_resend_api_key(raw: str) -> str:
    """Trim whitespace, quotes, and optional 'Bearer ' prefix from a pasted Resend API key."""
    key = (raw or "").strip().strip('"').strip("'").strip()
    if key.lower().startswith("bearer "):
        key = key[7:].strip().strip('"').strip("'").strip()
    return key


def validate_resend_api_key(raw: str) -> str:
    """Normalize and validate that the key matches Resend's 're_...' API key format."""
    key = normalize_resend_api_key(raw)
    if not key:
        raise ValueError(
            "Укажите API-ключ Resend (начинается с «re_»). "
            "Получите его в кабинете resend.com/api-keys."
        )
    if not key.startswith("re_") or len(key) < 8 or any(ch.isspace() for ch in key):
        raise ValueError(
            "Некорректный формат Resend API Key: ключ должен начинаться с «re_» и не содержать пробелов "
            "(не используйте здесь пароль приложения от почты или ключ от другой нейросети). "
            "Создайте новый ключ на resend.com/api-keys и вставьте его в поле «Resend API Key»."
        )
    return key


class Params(BaseModel):
    to_email: str = Field("", description="Recipient email address (optional if configured in Integrations)")
    subject: str = Field("FloraByte Security Report", description="Email subject")
    credential_id: str = Field("", description="Optional SMTP/Resend credential id")
    dry_run: bool = Field(False, description="Safe test mode: format and redact email without sending")


def extract_email_report_summary(inputs: dict[str, Any]) -> tuple[int, dict[str, int], str]:
    payload = inputs.get("report")
    if payload is None:
        payload = inputs.get("in")
    if payload is None and inputs:
        payload = next(iter(inputs.values()))

    if isinstance(payload, dict) and "report" in payload and "findings" not in payload:
        payload = payload["report"]

    findings: list[dict[str, Any]] = []
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        findings = payload["findings"]
    elif isinstance(payload, list):
        findings = payload

    by_sev: dict[str, int] = {}
    lines: list[str] = []
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity") or "UNKNOWN").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            if len(lines) < 15:
                lines.append(
                    f"- [{sev}] {f.get('category', '')}: {f.get('path', '')}:{f.get('line', '')} — "
                    f"{redact_text(str(f.get('description', ''))[:160])}"
                )

    summary_lines = [
        "FloraByte Security Report",
        f"Всего находок: {len(findings)}",
        f"По критичности: {json.dumps(by_sev, ensure_ascii=False)}",
    ]
    if isinstance(payload, dict) and payload.get("summary"):
        summary_lines.append("")
        summary_lines.append("Заключение AI:")
        summary_lines.append(redact_text(str(payload["summary"])))
    if lines:
        summary_lines.append("")
        summary_lines.append("Ключевые находки:")
        summary_lines.extend(lines)

    return len(findings), by_sev, redact_text("\n".join(summary_lines))


def resolve_email_runtime_config(
    owner_id: str | None = None,
    credential_id: str = "",
) -> dict[str, Any]:
    """Resolve Email transport config from IntegrationSetting -> Credential -> environment."""
    with Session(get_engine()) as session:
        row: IntegrationSetting | None = None
        if owner_id:
            row = session.get(IntegrationSetting, f"{owner_id}:email")
        if row is None:
            row = session.get(IntegrationSetting, "email")

        saved_secret = ""
        cfg: dict[str, Any] = {}
        if row and row.enabled:
            cfg = dict(row.config_json or {})
            if row.encrypted_secret:
                try:
                    saved_secret = decrypt(row.encrypted_secret).strip()
                except Exception:
                    saved_secret = ""

        cred_secret = ""
        if credential_id:
            cred = session.get(Credential, credential_id)
            if cred:
                try:
                    cred_secret = decrypt(cred.encrypted_value).strip()
                except Exception:
                    cred_secret = ""

        owner_email = ""
        if owner_id:
            u = session.get(User, owner_id)
            if u and u.email:
                owner_email = u.email.strip()

    env_resend = os.environ.get("RESEND_API_KEY", "").strip()
    env_host = os.environ.get("SMTP_HOST", "").strip()
    env_port = int(os.environ.get("SMTP_PORT", "587") or 587)
    env_user = os.environ.get("SMTP_USER", "").strip()
    env_pass = os.environ.get("SMTP_PASSWORD", "").strip()
    env_from = os.environ.get("SMTP_FROM", "").strip()
    env_to = os.environ.get("SMTP_TO", "").strip()
    env_tls = os.environ.get("SMTP_TLS", "1").strip().lower() not in ("0", "false", "no")

    transport = str(cfg.get("transport") or "").strip().lower()
    if not transport:
        if env_resend and not env_host:
            transport = "resend"
        else:
            transport = "smtp"

    smtp_host = str(cfg.get("smtp_host") or env_host or "").strip()
    smtp_port = int(cfg.get("smtp_port") or env_port or 587)
    smtp_user = str(cfg.get("smtp_user") or env_user or "").strip()
    use_tls = bool(cfg["use_tls"]) if "use_tls" in cfg else env_tls
    secret = cred_secret or saved_secret or (env_resend if transport == "resend" else env_pass)
    if transport == "resend" and secret:
        secret = normalize_resend_api_key(secret)
    default_to = str(cfg.get("default_to") or env_to or owner_email or "").strip()
    from_email = str(cfg.get("from_email") or env_from or smtp_user or "").strip()
    if not from_email:
        from_email = "onboarding@resend.dev" if transport == "resend" else "noreply@florabyte.local"

    return {
        "transport": transport,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "use_tls": use_tls,
        "secret": secret,
        "from_email": from_email,
        "default_to": default_to,
        "source": "settings" if (row and row.enabled) else ("env" if (env_host or env_resend) else "none"),
    }


def _send_smtp_sync(
    host: str,
    port: int,
    use_tls: bool,
    username: str,
    password: str,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        if int(port) == 465:
            with smtplib.SMTP_SSL(host, int(port), timeout=15) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, int(port), timeout=15) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise ValueError(
            "Ошибка авторизации SMTP (неверный логин или пароль приложения / App Password)."
        ) from exc
    except (TimeoutError, OSError) as exc:
        raise ValueError(
            f"Не удалось подключиться к SMTP {host}:{port} ({exc}). "
            "На бесплатном тарифе Render исходящие SMTP-порты 25/465/587 могут быть заблокированы — "
            "используйте транспорт Resend (HTTPS API, порт 443) в разделе «Интеграции → Email»."
        ) from exc


async def _send_resend_async(
    api_key: str,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
) -> str:
    api_key = validate_resend_api_key(api_key)
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(
            RESEND_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_addr,
                "to": [to_addr],
                "subject": subject,
                "text": body,
            },
        )
    if resp.status_code >= 400:
        err_detail = redact_text(resp.text[:300], [api_key])
        if resp.status_code == 401:
            raise ValueError(
                f"Resend API отклонил ключ (401: API key is invalid). "
                f"Проверьте ключ на resend.com/api-keys (возможно, ключ отозван, удалён или вставлен с ошибкой — "
                f"он должен начинаться с «re_»), затем вставьте новый ключ в поле «Resend API Key» и нажмите «Сохранить почту». "
                f"Ответ Resend: {err_detail}"
            )
        if resp.status_code == 403 and "only send testing emails to your own email" in err_detail.lower():
            raise ValueError(
                f"Resend ограничил тестовую отправку (403): с адреса onboarding@resend.dev можно отправлять письма "
                f"только на email вашего аккаунта Resend. Для отправки на {to_addr} подтвердите домен на resend.com/domains "
                f"или укажите email вашего аккаунта Resend."
            )
        raise ValueError(f"Resend API вернул {resp.status_code}: {err_detail}")
    try:
        data = resp.json()
        return str(data.get("id") or "")
    except Exception:
        return ""


async def send_email_message(
    *,
    cfg: dict[str, Any],
    to_addr: str,
    subject: str,
    body: str,
) -> dict[str, Any]:
    target = (to_addr or cfg.get("default_to") or "").strip()
    if not target or not _EMAIL_RE.match(target):
        raise ValueError(
            "Укажите корректный email получателя (в параметре to_email блока или в «Интеграции → Email»)."
        )

    transport = str(cfg.get("transport") or "smtp").lower()
    from_email = str(cfg.get("from_email") or "noreply@florabyte.local").strip()

    if transport == "resend":
        msg_id = await _send_resend_async(
            api_key=str(cfg.get("secret") or ""),
            from_addr=from_email,
            to_addr=target,
            subject=subject,
            body=body,
        )
        return {"sent": True, "transport": "resend", "to_email": target, "message_id": msg_id}

    smtp_host = str(cfg.get("smtp_host") or "").strip()
    if not smtp_host:
        raise ValueError(
            "Почта не настроена. Откройте «Интеграции → Email-уведомления» (можно выбрать Resend HTTPS API или SMTP) "
            "или задайте SMTP_HOST/RESEND_API_KEY в переменных окружения."
        )

    await asyncio.to_thread(
        _send_smtp_sync,
        smtp_host,
        int(cfg.get("smtp_port") or 587),
        bool(cfg.get("use_tls", True)),
        str(cfg.get("smtp_user") or ""),
        str(cfg.get("secret") or ""),
        from_email,
        target,
        subject,
        body,
    )
    return {"sent": True, "transport": "smtp", "to_email": target, "smtp_host": smtp_host}


@register_node
class EmailNotifyNode(BaseNode):
    type = "notify.email"
    label = "Email"
    group = "notify"
    inputs = [
        Port(name="report", kind="Report"),
        Port(name="in", kind="Any"),
    ]
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        cfg = resolve_email_runtime_config(owner_id=ctx.owner_id, credential_id=params.credential_id)
        to_addr = (params.to_email or cfg.get("default_to") or "").strip()
        subject = redact_text((params.subject or "FloraByte Security Report").strip())
        count, by_sev, body = extract_email_report_summary(inputs)

        if params.dry_run:
            return {
                "out": {
                    "sent": False,
                    "dry_run": True,
                    "transport": cfg.get("transport", "smtp"),
                    "to_email": to_addr or "(not set)",
                    "subject": subject,
                    "findings_count": count,
                    "by_severity": by_sev,
                    "preview": body[:600],
                }
            }

        res = await send_email_message(cfg=cfg, to_addr=to_addr, subject=subject, body=body)
        logger.info(
            "Security report email sent via %s to %s (findings=%d)",
            res.get("transport"),
            res.get("to_email"),
            count,
        )
        return {
            "out": {
                **res,
                "subject": subject,
                "findings_count": count,
                "by_severity": by_sev,
            }
        }
