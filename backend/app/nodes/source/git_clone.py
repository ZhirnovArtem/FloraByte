"""source.git_clone — shallow clone from allowlist, detect Gradle root."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, HttpUrl

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


class Params(BaseModel):
    url: str = Field(..., description="HTTPS git URL (must be in allowlist)")
    subdir: str = Field("", description="Subdirectory after clone")
    branch: str = Field("", description="Optional branch/tag")


@register_node
class GitCloneNode(BaseNode):
    type = "source.git_clone"
    label = "Git Clone"
    group = "source"
    inputs = []
    outputs = [Port(name="workspace", kind="Workspace")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raise NotImplementedError("source.git_clone — Phase B")
