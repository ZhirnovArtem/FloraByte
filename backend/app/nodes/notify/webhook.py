"""notify.webhook — POST report JSON to an HTTP endpoint."""

from __future__ import annotations

import logging
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit
from typing import Any

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.models import Credential
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from sqlmodel import Session

logger = logging.getLogger(__name__)


class Params(BaseModel):
    url: str = Field(..., description="Webhook URL")
    credential_id: str = Field("", description="Optional credential for Authorization header")
    headers_json: str = Field("{}", description="Optional extra headers as JSON object string")


async def _validate_destination(url: str) -> None:
    """Reject internal destinations (SSRF) and optionally enforce an explicit host allowlist.

    For local webhook development, set WEBHOOK_HOST_ALLOWLIST=localhost; the
    allowlist must be explicitly configured to permit a local/private target.
    """
    split = urlsplit(url)
    if split.scheme not in ("https", "http") or not split.hostname or split.username or split.password:
        raise ValueError("Webhook must be an HTTP(S) URL without embedded credentials")
    host = split.hostname.lower().rstrip(".")
    allowed = {v.strip().lower().rstrip(".") for v in get_settings().webhook_host_allowlist.split(",") if v.strip()}
    if allowed and host not in allowed:
        raise PermissionError("Webhook hostname is not in WEBHOOK_HOST_ALLOWLIST")
    if host in allowed:
        return
    addresses = await asyncio.get_running_loop().getaddrinfo(host, split.port or (443 if split.scheme == "https" else 80), type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise PermissionError("Webhook cannot target private, loopback or reserved addresses")


@register_node
class WebhookNotifyNode(BaseNode):
    type = "notify.webhook"
    label = "Webhook"
    group = "notify"
    inputs = [
        Port(name="report", kind="Report"),
        Port(name="in", kind="Any"),
    ]
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        await _validate_destination(params.url)

        report = inputs.get("report") or inputs.get("in") or {}
        payload = {
            "run_id": ctx.run_id,
            "report": report if isinstance(report, dict) else {"value": str(report)},
        }

        headers = {"Content-Type": "application/json"}
        if params.headers_json and params.headers_json != "{}":
            import json
            try:
                extra = json.loads(params.headers_json)
                if isinstance(extra, dict):
                    headers.update({str(k): str(v) for k, v in extra.items()})
            except json.JSONDecodeError as e:
                raise ValueError(f"headers_json is not valid JSON: {e}") from e

        if params.credential_id:
            with Session(get_engine()) as session:
                cred = session.get(Credential, params.credential_id)
                if cred and cred.encrypted_value:
                    token = decrypt(cred.encrypted_value)
                    headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False) as client:
            resp = await client.post(params.url, json=payload, headers=headers)
            if resp.status_code >= 300:
                raise RuntimeError(f"Webhook failed HTTP {resp.status_code} (redirects not permitted)")

        logger.info("Webhook delivered for run=%s status=%s", ctx.run_id, resp.status_code)
        return {"out": {"sent": True, "status_code": resp.status_code, "sent_to_host": urlsplit(params.url).hostname}}
