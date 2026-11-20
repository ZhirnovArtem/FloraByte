from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

OPS = {"==", "!=", ">", ">=", "<", "<=", "in", "regex"}


def _resolve(path: str, inputs: dict[str, Any]) -> Any:
    """Resolve structural paths like findings.count, findings.max_severity, findings.by_category.SECRET."""
    if path in inputs:
        return inputs[path]
    # try nested from findings list
    findings = inputs.get("findings")
    if findings is None:
        findings = inputs.get("in")
    if findings is None:
        findings = inputs.get("a")
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    if path.startswith("findings.") and isinstance(findings, list):
        rest = path[len("findings.") :]
        if rest == "count":
            return len(findings)
        if rest == "max_severity":
            order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            best = 0
            best_name = None
            for f in findings:
                sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", None)
                r = order.get(str(sev or ""), 0)
                if r > best:
                    best = r
                    best_name = sev
            return best_name
        if rest.startswith("by_category."):
            cat = rest.split(".", 1)[1]
            return sum(
                1
                for f in findings
                if (f.get("category") if isinstance(f, dict) else getattr(f, "category", None)) == cat
            )
        if rest.startswith("by_severity."):
            sev = rest.split(".", 1)[1]
            return sum(
                1
                for f in findings
                if (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", None)) == sev
            )
    # literal
    if path.lower() in ("true", "false"):
        return path.lower() == "true"
    try:
        if "." in path:
            return float(path)
        return int(path)
    except ValueError:
        return path


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == "regex":
        try:
            return bool(re.search(str(right), str(left)))
        except re.error:
            return False
    if op == "in":
        return str(left) in str(right)
    # numeric if possible
    try:
        lf, rf = float(left), float(right)
        left, right = lf, rf
    except (TypeError, ValueError):
        left, right = str(left), str(right)
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    raise ValueError(f"Unknown op: {op}")


class Params(BaseModel):
    left: str = Field(..., description="Value path, e.g. findings.count or findings.max_severity")
    op: str = Field(">", description="== != > >= < <= in regex")
    right: str = Field(...)


@register_node
class IfElseNode(BaseNode):
    type = "logic.if_else"
    label = "If / Else"
    group = "logic"
    inputs = [
        Port(name="in", kind="Any"),
        Port(name="findings", kind="Findings"),
    ]
    outputs = [
        Port(name="true", kind="Any"),
        Port(name="false", kind="Any"),
    ]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        if params.op not in OPS:
            raise ValueError(f"op must be one of {OPS}")
        left = _resolve(params.left, inputs)
        right = _resolve(params.right, inputs)
        # right for regex is the pattern literal
        if params.op == "regex":
            right = params.right
        ok = _compare(left, params.op, right)
        # pass through original payload
        payload = inputs.get("findings") or inputs.get("in") or inputs
        if ok:
            return {"true": payload}
        return {"false": payload}
