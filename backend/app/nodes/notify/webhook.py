"""notify.webhook — POST report JSON to an HTTP endpoint with SSRF & DNS-rebinding protection."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.crypto import decrypt
from app.core.db import get_engine
from app.core.models import Credential
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 64 * 1024
WEBHOOK_TIMEOUT_SEC = 15.0


class Params(BaseModel):
    url: str = Field(..., description="Webhook URL")
    credential_id: str = Field("", description="Optional credential for Authorization header")
    headers_json: str = Field("{}", description="Optional extra headers as JSON object string")


async def _resolve_and_pin(url: str) -> tuple[str, str | None, str | None]:
    """Validate URL against SSRF/private/metadata IPs and return (target_url, host_header, sni_host).

    Resolves DNS immediately prior to connection and pins the validated IP in `target_url`
    so `httpx` does not perform a second DNS lookup (mitigates DNS rebinding).
    """
    split = urlsplit(url)
    if split.scheme not in ("https", "http") or not split.hostname or split.username or split.password:
        raise ValueError("Webhook must be an HTTP(S) URL without embedded credentials")

    host = split.hostname.lower().rstrip(".")
    allowed = {v.strip().lower().rstrip(".") for v in get_settings().webhook_host_allowlist.split(",") if v.strip()}
    if allowed and host not in allowed:
        raise PermissionError("Webhook hostname is not in WEBHOOK_HOST_ALLOWLIST")
    if host in allowed:
        return url, None, None

    port = split.port or (443 if split.scheme == "https" else 80)
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise PermissionError("Webhook hostname resolved to no addresses")

    validated_ips: list[str] = []
    for item in addresses:
        raw_ip = item[4][0].split("%", 1)[0]
        ip_obj = ipaddress.ip_address(raw_ip)
        if (
            not ip_obj.is_global
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        ):
            raise PermissionError("Webhook cannot target private, loopback, link-local or reserved addresses")
        validated_ips.append(raw_ip)

    chosen_ip = validated_ips[0]
    ip_host = f"[{chosen_ip}]" if ":" in chosen_ip else chosen_ip
    pinned_netloc = f"{ip_host}:{split.port}" if split.port else ip_host
    pinned_url = urlunsplit((split.scheme, pinned_netloc, split.path or "/", split.query, ""))
    sni_host = host if split.scheme == "https" else None
    return pinned_url, split.netloc, sni_host


async def _validate_destination(url: str) -> None:
    await _resolve_and_pin(url)


async def _post_pinned(
    target_url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    sni_host: str | None,
) -> int:
    extensions = {"sni_hostname": sni_host} if sni_host else None
    async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SEC, follow_redirects=False, trust_env=False) as client:
        async with client.stream("POST", target_url, json=payload, headers=headers, extensions=extensions) as resp:
            if resp.status_code >= 300:
                raise RuntimeError(f"Webhook failed HTTP {resp.status_code} (redirects not permitted)")
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise RuntimeError("Webhook response exceeded size limit")
            return resp.status_code


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
        target_url, host_header, sni_host = await _resolve_and_pin(params.url)

        report = inputs.get("report") or inputs.get("in") or {}
        payload = {
            "run_id": ctx.run_id,
            "report": report if isinstance(report, dict) else {"value": str(report)},
        }

        headers = {"Content-Type": "application/json"}
        if host_header:
            headers["Host"] = host_header
        if params.headers_json and params.headers_json != "{}":
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

        status_code = await _post_pinned(target_url, payload, headers, sni_host)
        logger.info("Webhook delivered for run=%s status=%s", ctx.run_id, status_code)
        return {"out": {"sent": True, "status_code": status_code, "sent_to_host": urlsplit(params.url).hostname}}
