from __future__ import annotations
from typing import Any
from pydantic import BaseModel
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    pass

@register_node
class ManualTriggerNode(BaseNode):
    type = "trigger.manual"
    label = "Manual Trigger"
    group = "trigger"
    inputs = []
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        return {"out": {"triggered": True, "run_id": ctx.run_id}}
