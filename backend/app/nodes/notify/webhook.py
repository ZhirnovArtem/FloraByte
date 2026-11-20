from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    url: str = Field(..., description="Webhook URL")
    credential_id: str = Field("", description="Optional auth header credential")

@register_node
class WebhookNotifyNode(BaseNode):
    type = "notify.webhook"
    label = "Webhook"
    group = "notify"
    inputs = [Port(name="report", kind="Report")]
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("notify.webhook — Phase E")
