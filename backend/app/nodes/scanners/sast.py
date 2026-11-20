"""SAST scanner node — adapter over team package `scanners.sast`."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.masking import mask_evidence, redact_text
from app.core.models import Finding
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanners.sast.engine import run as sast_run  # noqa: E402

# Map SAST rule IDs to organisers' `class` codes (docs/submission-format.md)
_RULE_TO_CLASS: dict[str, str] = {
    "SAST-INJ-001": "sql-injection",
    "SAST-SEC-001": "route-authorization",
    "SAST-SEC-003": "credentialed-cors",
    "SAST-TLS-001": "tls-verification",
    "SAST-AUTH-001": "object-authorization",
    "SAST-IDOR-001": "object-authorization",
    "SAST-SEC-002": "csrf-disabled",
    "SAST-SEC-005": "insecure-password-storage",
    "SAST-INJ-002": "command-injection",
    "SAST-CRY-001": "weak-hash",
    "SAST-CFG-001": "exposed-actuator",
    "SAST-CFG-002": "h2-console-enabled",
    "SAST-LOG-001": "sensitive-logging",
}


def _map_class(rule_id: str) -> str:
    return _RULE_TO_CLASS.get(rule_id, rule_id.lower())


def scan(root: Path, params: dict | None = None) -> list[Finding]:
    params = params or {}
    cfg = {"exclude_tests": params.get("exclude_tests", True)}
    if params.get("enabled_rules") is not None:
        cfg["enabled_rules"] = params["enabled_rules"]

    result = sast_run(str(root), cfg)
    out: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for f in result.findings:
        rel_path = f.file.replace("\\", "/").lstrip("./")
        cls = _map_class(f.rule_id)
        key = (rel_path, cls, f.line)
        if key in seen:
            continue
        seen.add(key)

        sev_raw = f.severity.value
        sev = "LOW" if sev_raw == "INFO" else sev_raw
        if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            sev = "MEDIUM"
        conf = 1.0 if f.confidence.value == "HIGH" else (0.7 if f.confidence.value == "MEDIUM" else 0.4)

        out.append(
            Finding(
                category="SAST",
                path=rel_path,
                **{"class": cls},
                line=f.line,
                endLine=f.line,
                severity=sev,
                description=redact_text(f.message),
                remediation=f.remediation,
                rule_id=f.rule_id,
                evidence=mask_evidence(f.evidence),
                confidence=conf,
            )
        )
    return out


class Params(BaseModel):
    exclude_tests: bool = True


@register_node
class SastScannerNode(BaseNode):
    type = "scanner.sast"
    label = "SAST Scanner"
    group = "scanner"
    inputs = [Port(name="workspace", kind="Workspace")]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        root = inputs.get("workspace") or inputs.get("in")
        if not root:
            raise ValueError("scanner.sast requires workspace input")
        root = Path(root)
        settings = get_settings()
        if settings.use_stub_scanners:
            from app.nodes.scanners._stubs import stub_sast_scan

            findings = stub_sast_scan(root, {})
        else:
            findings = await asyncio.to_thread(scan, root, {"exclude_tests": params.exclude_tests})
        return {"findings": findings}
