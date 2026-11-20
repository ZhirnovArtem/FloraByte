from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.logic.if_else import OPS, _compare, _resolve
from app.nodes.registry import register_node


class Params(BaseModel):
    left: str
    op: str = "=="
    right: str


@register_node
class CompareNode(BaseNode):
    type = "logic.compare"
    label = "Compare"
    group = "logic"
    inputs = [
        Port(name="in", kind="Any"),
        Port(name="findings", kind="Findings"),
    ]
    outputs = [Port(name="out", kind="Boolean")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        if params.op not in OPS:
            raise ValueError(f"op must be one of {OPS}")
        left = _resolve(params.left, inputs)
        right = params.right if params.op == "regex" else _resolve(params.right, inputs)
        return {"out": _compare(left, params.op, right)}
