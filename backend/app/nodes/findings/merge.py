"""findings.merge — merge multiple findings lists, deduplicate, sort by severity."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.core.models import Finding
from app.core.severity import Severity
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


def _key(f: Finding) -> tuple:
    if f.category == "SCA":
        return ("SCA", f.path, f.group, f.artifact, f.version, f.advisoryId)
    return (f.category, f.path, f.class_, f.line)


def _as_finding(item: Any) -> Finding | None:
    if isinstance(item, Finding):
        return item
    if isinstance(item, dict):
        try:
            return Finding.model_validate(item)
        except Exception:
            return None
    return None


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
        Port(name="findings", kind="Findings"),
        Port(name="in", kind="Findings"),
    ]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        collected: list[Finding] = []
        for val in inputs.values():
            if isinstance(val, list):
                for item in val:
                    f = _as_finding(item)
                    if f:
                        collected.append(f)
            else:
                f = _as_finding(val)
                if f:
                    collected.append(f)

        seen: set[tuple] = set()
        unique: list[Finding] = []
        for f in collected:
            k = _key(f)
            if k in seen:
                continue
            seen.add(k)
            unique.append(f)

        def sort_key(f: Finding):
            rank = 0
            if f.severity:
                try:
                    rank = Severity(f.severity).rank
                except Exception:
                    rank = 0
            return (-rank, f.category, f.path or "", f.line or 0)

        unique.sort(key=sort_key)
        return {"findings": unique}
