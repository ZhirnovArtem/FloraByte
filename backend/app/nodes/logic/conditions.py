"""Structural conditions only — no eval. Sources: findings.*, literals."""

from __future__ import annotations

import re
from typing import Any


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _findings_from_inputs(inputs: dict[str, Any]) -> list:
    for key in ("findings", "in", "a", "b", "report"):
        val = inputs.get(key)
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            if isinstance(val.get("findings"), list):
                return val["findings"]
            if isinstance(val.get("report_json", {}).get("findings"), list):
                return val["report_json"]["findings"]
    for val in inputs.values():
        if isinstance(val, list):
            return val
    return []


def resolve_value(expr: str, inputs: dict[str, Any]) -> Any:
    """Resolve left/right from findings.* paths or literal."""
    expr = (expr or "").strip()
    findings = _findings_from_inputs(inputs)

    if expr == "findings.count":
        return len(findings)

    if expr == "findings.max_severity":
        best = 0
        best_name = None
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else (f.get("severity") if isinstance(f, dict) else None)
            rank = SEVERITY_RANK.get(str(sev or ""), 0)
            if rank > best:
                best = rank
                best_name = sev
        return best_name or "LOW"

    m = re.match(r"findings\.by_category\[(.+)\]", expr)
    if m:
        cat = m.group(1).strip().strip("'\"")
        n = 0
        for f in findings:
            c = f.category if hasattr(f, "category") else (f.get("category") if isinstance(f, dict) else None)
            if c == cat:
                n += 1
        return n

    if expr.startswith("findings."):
        return None

    # numeric literal
    try:
        if "." in expr:
            return float(expr)
        return int(expr)
    except ValueError:
        pass

    # boolean
    if expr.lower() in ("true", "false"):
        return expr.lower() == "true"

    # strip quotes for string literal
    if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
        return expr[1:-1]

    return expr


def compare(left: Any, op: str, right: Any) -> bool:
    op = (op or "==").strip()

    # severity-aware
    if isinstance(left, str) and left in SEVERITY_RANK and isinstance(right, str) and right in SEVERITY_RANK:
        left, right = SEVERITY_RANK[left], SEVERITY_RANK[right]

    # try numeric
    try:
        lf, rf = float(left), float(right)
        left, right = lf, rf
    except (TypeError, ValueError):
        pass

    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left > right  # type: ignore
    if op == ">=":
        return left >= right  # type: ignore
    if op == "<":
        return left < right  # type: ignore
    if op == "<=":
        return left <= right  # type: ignore
    if op == "in":
        return str(left) in str(right)
    if op == "regex":
        return _safe_regex_search(str(right), str(left))
    raise ValueError(f"Unsupported operator: {op}")


def _safe_regex_search(pattern: str, text: str, timeout_chars: int = 50_000) -> bool:
    """Regex with length limit to reduce ReDoS risk (no eval, bounded input)."""
    if len(text) > timeout_chars:
        text = text[:timeout_chars]
    if len(pattern) > 500:
        raise ValueError("Regex pattern too long")
    try:
        return re.search(pattern, text, timeout=1) is not None  # type: ignore[call-arg]
    except TypeError:
        # Python < 3.11 may not support timeout=
        return re.search(pattern, text) is not None
    except re.error as e:
        raise ValueError(f"Invalid regex: {e}") from e
