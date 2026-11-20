from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.config import get_settings
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
        assert isinstance(params, Params)
        root = inputs.get("workspace") or inputs.get("in")
        if not root:
            raise ValueError("scanner.sca requires workspace input")
        root = Path(root)
        settings = get_settings()
        scan_params = {
            "vuln_db_path": params.vuln_db_path or str(settings.vuln_db_path),
            "lockfile_priority": params.lockfile_priority,
        }
        if settings.use_stub_scanners:
            from app.nodes.scanners._stubs import stub_sca_scan
            findings = stub_sca_scan(root, scan_params)
        else:
            findings = []
        return {"findings": findings}
