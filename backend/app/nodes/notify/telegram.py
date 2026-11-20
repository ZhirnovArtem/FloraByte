from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    credential_id: str = Field("", description="Telegram bot credential id")
    chat_id: str = Field("", description="Override chat id if not in credential")

@register_node
class TelegramNotifyNode(BaseNode):
    type = "notify.telegram"
    label = "Telegram"
    group = "notify"
    inputs = [Port(name="report", kind="Report")]
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("notify.telegram — Phase C")
