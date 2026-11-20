from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    vuln_db_path: str = Field("", description="Override path to vulnerabilities.json")
    lockfile_priority: bool = True

@register_node
class ScaScannerNode(BaseNode):
    type = "scanner.sca"
    label = "SCA Scanner"
    group = "scanner"
    inputs = [Port(name="workspace", kind="Workspace")]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("scanner.sca adapter — Phase C")
