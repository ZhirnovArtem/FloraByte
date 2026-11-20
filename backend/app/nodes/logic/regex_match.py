from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    pattern: str
    source: str = Field("text", description="Input field or literal")

@register_node
class RegexMatchNode(BaseNode):
    type = "logic.regex"
    label = "Regex Match"
    group = "logic"
    inputs = [Port(name="in", kind="Any")]
    outputs = [
        Port(name="match", kind="Any"),
        Port(name="no_match", kind="Any"),
    ]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("logic.regex — Phase D")
