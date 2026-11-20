"""findings.export — write report.json (organisers format) + report.md from same findings set."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.core.models import Finding
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


def _as_findings(val: Any) -> list[Finding]:
    if val is None:
        return []
    if isinstance(val, list):
        out = []
        for item in val:
            if isinstance(item, Finding):
                out.append(item)
            elif isinstance(item, dict):
                try:
                    out.append(Finding.model_validate(item))
                except Exception:
                    pass
        return out
    return []


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# Security findings report", ""]
    if not findings:
        lines.append("Находок нет.")
        return "\n".join(lines)

    lines.append(f"Всего находок: **{len(findings)}**")
    lines.append("")
    lines.append("| # | Category | Path | Class / Advisory | Line | Severity |")
    lines.append("|---|----------|------|------------------|------|----------|")
    for i, f in enumerate(findings, 1):
        if f.category == "SCA":
            detail = f"{f.group}:{f.artifact}@{f.version} ({f.advisoryId})"
            line = "—"
        else:
            detail = f.class_ or "—"
            line = str(f.line) if f.line else "—"
            if f.endLine and f.endLine != f.line:
                line = f"{f.line}–{f.endLine}"
        sev = f.severity or "—"
        lines.append(f"| {i} | {f.category} | `{f.path}` | {detail} | {line} | {sev} |")

    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {f.category} — {f.path}")
        if f.description:
            lines.append(f"**Description:** {f.description}")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
        if f.evidence:
            lines.append(f"**Evidence (masked):** `{f.evidence}`")
        lines.append("")
    return "\n".join(lines)


class Params(BaseModel):
    pass


@register_node
class ReportExportNode(BaseNode):
    type = "findings.export"
    label = "Export Report"
    group = "findings"
    inputs = [
        Port(name="findings", kind="Findings"),
        Port(name="in", kind="Findings"),
        Port(name="a", kind="Findings"),
    ]
    outputs = [Port(name="report", kind="Report")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        findings: list[Finding] = []
        for key in ("findings", "in", "a", "b", "c"):
            if key in inputs:
                findings = _as_findings(inputs[key])
                if findings or key == "findings":
                    break
        if not findings:
            # try any list value
            for v in inputs.values():
                findings = _as_findings(v)
                if findings:
                    break

        report_json = {"findings": [f.to_submission() for f in findings]}
        report_md = render_markdown(findings)

        out_dir = Path(ctx.workspace) / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "report.json"
        md_path = out_dir / "report.md"
        json_path.write_text(json.dumps(report_json, ensure_ascii=False, indent=2), encoding="utf-8")
        md_path.write_text(report_md, encoding="utf-8")

        # Also copy to a stable place under runs for API download
        return {
            "report": {
                "findings": report_json["findings"],
                "report_json": report_json,
                "report_md": report_md,
                "json_path": str(json_path),
                "md_path": str(md_path),
            }
        }
