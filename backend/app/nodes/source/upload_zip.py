"""source.upload_zip — unpack uploaded zip and detect Gradle project root."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


class Params(BaseModel):
    upload_id: str = Field(..., description="ID returned by POST /api/uploads")
    subdir: str = Field("", description="Optional subdirectory inside the archive")


@register_node
class UploadZipNode(BaseNode):
    type = "source.upload_zip"
    label = "Upload ZIP"
    group = "source"
    inputs = []
    outputs = [Port(name="workspace", kind="Workspace")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        # Implemented in Phase B
        raise NotImplementedError("source.upload_zip — Phase B")
