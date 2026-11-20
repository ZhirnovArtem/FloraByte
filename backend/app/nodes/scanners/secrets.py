from __future__ import annotations
from typing import Any
from pydantic import BaseModel
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

class Params(BaseModel):
    pass

@register_node
class SecretsScannerNode(BaseNode):
    type = "scanner.secrets"
    label = "Secrets Scanner"
    group = "scanner"
    inputs = [Port(name="workspace", kind="Workspace")]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("scanner.secrets adapter — Phase C (real impl by team 3/4)")
