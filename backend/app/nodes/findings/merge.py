from __future__ import annotations
from typing import Any
from pydantic import BaseModel
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    pass

@register_node
class MergeFindingsNode(BaseNode):
    type = "findings.merge"
    label = "Merge Findings"
    group = "findings"
    inputs = [
        Port(name="a", kind="Findings"),
        Port(name="b", kind="Findings"),
        Port(name="c", kind="Findings"),
    ]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("findings.merge — Phase B")
