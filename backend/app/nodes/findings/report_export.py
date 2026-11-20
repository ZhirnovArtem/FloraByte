from __future__ import annotations
from typing import Any
from pydantic import BaseModel
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    pass

@register_node
class ReportExportNode(BaseNode):
    type = "findings.export"
    label = "Export Report"
    group = "findings"
    inputs = [Port(name="findings", kind="Findings")]
    outputs = [Port(name="report", kind="Report")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("findings.export — Phase B")
