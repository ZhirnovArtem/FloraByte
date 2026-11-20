from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    left: str = Field(..., description="Value path, e.g. findings.count or findings.max_severity")
    op: str = Field(">", description="== != > >= < <= in regex")
    right: str = Field(...)

@register_node
class IfElseNode(BaseNode):
    type = "logic.if_else"
    label = "If / Else"
    group = "logic"
    inputs = [Port(name="in", kind="Any")]
    outputs = [
        Port(name="true", kind="Any"),
        Port(name="false", kind="Any"),
    ]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("logic.if_else — Phase D")
