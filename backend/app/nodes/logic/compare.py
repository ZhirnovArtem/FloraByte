from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    left: str
    op: str = "=="
    right: str

@register_node
class CompareNode(BaseNode):
    type = "logic.compare"
    label = "Compare"
    group = "logic"
    inputs = [Port(name="in", kind="Any")]
    outputs = [Port(name="out", kind="Boolean")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("logic.compare — Phase D")
