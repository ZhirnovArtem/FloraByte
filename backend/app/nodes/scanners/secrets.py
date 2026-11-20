from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.config import get_settings
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
        root = inputs.get("workspace") or inputs.get("in")
        if not root:
            raise ValueError("scanner.secrets requires workspace input")
        root = Path(root)
        settings = get_settings()
        if settings.use_stub_scanners:
            from app.nodes.scanners._stubs import stub_secrets_scan
            findings = stub_secrets_scan(root, {})
        else:
            # Real implementation from team 3/4 not yet available
            findings = []
        return {"findings": findings}
