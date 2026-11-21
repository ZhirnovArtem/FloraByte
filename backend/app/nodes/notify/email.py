"""notify.email — send security report summary to an email address via SMTP or safe dry_run."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import smtplib
from email.message import EmailMessage
from typing import Any

from pydantic import BaseModel, Field
from sqlmodel import Session

from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.masking import redact_text
from app.core.models import Credential
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Params(BaseModel):
    to_email: str = Field("", description="Recipient email address")
    subject: str = Field("FloraByte Security Report", description="Email subject")
    credential_id: str = Field("", description="Optional SMTP credential id")
    dry_run: bool = Field(False, description="Safe test mode: format and redact email without sending via SMTP")


def _extract_report_summary(inputs: dict[str, Any]) -> tuple[int, dict[str, int], str]:
    payload = inputs.get("report")
    if payload is None:
        payload = inputs.get("in")
    if payload is None and inputs:
        payload = next(iter(inputs.values()))

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
            if len(lines) < 10:
                lines.append(
                    f"- [{sev}] {f.get('category', '')}: {f.get('path', '')}:{f.get('line', '')} — "
                    f"{redact_text(str(f.get('description', ''))[:160])}"
                )

    summary_lines = [
        f"FloraByte Security Report",
        f"Total findings: {len(findings)}",
        f"By severity: {json.dumps(by_sev, ensure_ascii=False)}",
    ]
    if isinstance(payload, dict) and payload.get("summary"):
        summary_lines.append("")
        summary_lines.append(redact_text(str(payload["summary"])))
    if lines:
        summary_lines.append("")
        summary_lines.append("Top findings:")
        summary_lines.extend(lines)

    return len(findings), by_sev, redact_text("\n".join(summary_lines))


def _resolve_smtp_password(credential_id: str) -> str:
    if credential_id:
        with Session(get_engine()) as session:
            cred = session.get(Credential, credential_id)
            if cred:
                return decrypt(cred.encrypted_value)
    return os.environ.get("SMTP_PASSWORD", "").strip()


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

    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(msg)


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
        to_addr = (params.to_email or os.environ.get("SMTP_TO", "")).strip()
        subject = redact_text((params.subject or "FloraByte Security Report").strip())
        count, by_sev, body = _extract_report_summary(inputs)

        if params.dry_run:
            return {
                "out": {
                    "sent": False,
                    "dry_run": True,
                    "to_email": to_addr or "(not set)",
                    "subject": subject,
                    "findings_count": count,
                    "by_severity": by_sev,
                    "preview": body[:600],
                }
            }

        if not to_addr or not _EMAIL_RE.match(to_addr):
            raise ValueError("Укажите корректный email получателя в параметре to_email (или включите dry_run).")

        smtp_host = os.environ.get("SMTP_HOST", "").strip()
        if not smtp_host:
            raise ValueError(
                "SMTP_HOST не настроен на сервере. Задайте SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD или включите dry_run."
            )

        smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
        smtp_user = os.environ.get("SMTP_USER", "").strip()
        smtp_from = os.environ.get("SMTP_FROM", "").strip() or smtp_user or "noreply@florabyte.local"
        smtp_tls = os.environ.get("SMTP_TLS", "1").strip().lower() not in ("0", "false", "no")
        smtp_password = _resolve_smtp_password(params.credential_id)

        await asyncio.to_thread(
            _send_smtp_sync,
            smtp_host,
            smtp_port,
            smtp_tls,
            smtp_user,
            smtp_password,
            smtp_from,
            to_addr,
            subject,
            body,
        )
        logger.info("Security report email sent to %s (findings=%d)", to_addr, count)
        return {
            "out": {
                "sent": True,
                "to_email": to_addr,
                "subject": subject,
                "findings_count": count,
                "by_severity": by_sev,
            }
        }
