"""notify.webhook — POST report JSON to an HTTP endpoint."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

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
        if not params.url.startswith("http://") and not params.url.startswith("https://"):
            raise ValueError("webhook url must start with http:// or https://")

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

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(params.url, json=payload, headers=headers)
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"Webhook failed HTTP {resp.status_code}: {resp.text[:300]}"
                )

        logger.info("Webhook delivered to %s for run=%s status=%s", params.url, ctx.run_id, resp.status_code)
        return {"out": {"sent": True, "status_code": resp.status_code, "url": params.url}}
