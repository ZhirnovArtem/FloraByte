from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    credential_id: str = Field("", description="LLM credential id (preferred)")
    model: str = Field("", description="Override model name")

@register_node
class AiExplainNode(BaseNode):
    type = "ai.explain"
    label = "AI Explain"
    group = "ai"
    inputs = [Port(name="findings", kind="Findings")]
    outputs = [Port(name="report", kind="Report")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("ai.explain + validator — Phase D")
