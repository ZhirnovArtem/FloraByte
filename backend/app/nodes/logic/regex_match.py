from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

MAX_INPUT_LEN = 50_000


class Params(BaseModel):
    pattern: str
    source: str = Field("text", description="Input field name or leave to use text/in")


@register_node
class RegexMatchNode(BaseNode):
    type = "logic.regex"
    label = "Regex Match"
    group = "logic"
    inputs = [Port(name="in", kind="Any")]
    outputs = [
        Port(name="match", kind="Any"),
        Port(name="no_match", kind="Any"),
    ]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        raw = inputs.get(params.source) or inputs.get("text") or inputs.get("in") or ""
        if not isinstance(raw, str):
            raw = str(raw)
        if len(raw) > MAX_INPUT_LEN:
            raw = raw[:MAX_INPUT_LEN]
        try:
            # ReDoS guard: timeout via simple length limit already; compile check
            if len(params.pattern) > 500:
                raise ValueError("pattern too long")
            rx = re.compile(params.pattern)
            ok = bool(rx.search(raw))
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}") from e
        payload = inputs.get("in") or inputs
        if ok:
            return {"match": payload}
        return {"no_match": payload}
