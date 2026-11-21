"""findings.export — write report.json (organisers format) + enriched report.md (confirmed AI only)."""

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
    if isinstance(val, dict) and "findings" in val:
        val = val["findings"]
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


def _extract_ai_report(inputs: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("report", "in", "a", "b", "c"):
        val = inputs.get(key)
        if isinstance(val, dict) and ("items" in val or "summary" in val or "validation" in val):
            return val
    for val in inputs.values():
        if isinstance(val, dict) and ("items" in val or "summary" in val or "validation" in val):
            return val
    return None


def is_confirmed_ai_report(ai_report: dict[str, Any] | None) -> bool:
    if not ai_report:
        return False
    val = ai_report.get("validation") or {}
    return val.get("mode") == "llm" and val.get("passed") is True and bool(ai_report.get("items"))


def render_markdown(findings: list[Finding], ai_report: dict[str, Any] | None = None) -> str:
    lines = ["# Security findings report", ""]
    confirmed_ai = is_confirmed_ai_report(ai_report)

    if ai_report:
        val = ai_report.get("validation") or {}
        mode = val.get("mode")
        if confirmed_ai:
            lines.append("**AI-анализ:** Успешно — Gemini успешно обработал результаты сканирования.")
            if ai_report.get("summary"):
                lines.append(f"**Общее заключение:** {ai_report['summary']}")
        elif mode == "empty":
            lines.append("**AI-анализ:** Нет находок")
        else:
            lines.append("**AI-анализ:** Ошибка — AI-анализ не выполнен. Проверьте API-ключ и доступность модели.")
            err = val.get("error") or (val.get("errors")[0] if isinstance(val.get("errors"), list) and val.get("errors") else "")
            if err:
                lines.append(f"**Причина:** {err}")
        lines.append("")

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

    ai_by_ref: dict[int, dict[str, Any]] = {}
    if confirmed_ai and ai_report and isinstance(ai_report.get("items"), list):
        for item in ai_report["items"]:
            if isinstance(item, dict) and isinstance(item.get("finding_ref"), int):
                ai_by_ref[item["finding_ref"]] = item

    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {f.category} — {f.path}")
        if f.severity:
            lines.append(f"**Severity:** {f.severity}")
        if f.line:
            lines.append(f"**Line:** {f.line}")
        if f.description:
            lines.append(f"**Description:** {f.description}")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
        if f.evidence:
            lines.append(f"**Evidence (masked):** `{f.evidence}`")
        ai_item = ai_by_ref.get(i - 1)
        if ai_item:
            if ai_item.get("explanation"):
                lines.append(f"**AI-объяснение:** {ai_item['explanation']}")
            if ai_item.get("risk"):
                lines.append(f"**Возможные последствия:** {ai_item['risk']}")
            steps = ai_item.get("fix_steps") or []
            if steps:
                lines.append("**Пошаговые рекомендации:**")
                for step in steps:
                    lines.append(f"- {step}")
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
        Port(name="report", kind="Report"),
        Port(name="in", kind="Findings"),
        Port(name="a", kind="Findings"),
    ]
    outputs = [Port(name="report", kind="Report")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        ai_report = _extract_ai_report(inputs)
        findings: list[Finding] = []
        for key in ("report", "findings", "in", "a", "b", "c"):
            if key in inputs:
                findings = _as_findings(inputs[key])
                if findings or key in ("findings", "report"):
                    break
        if not findings:
            for v in inputs.values():
                findings = _as_findings(v)
                if findings:
                    break

        report_json = {"findings": [f.to_submission() for f in findings]}
        report_md = render_markdown(findings, ai_report=ai_report)

        out_dir = Path(ctx.workspace) / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "report.json"
        md_path = out_dir / "report.md"
        json_path.write_text(json.dumps(report_json, ensure_ascii=False, indent=2), encoding="utf-8")
        md_path.write_text(report_md, encoding="utf-8")

        out_report: dict[str, Any] = {
            "findings": report_json["findings"],
            "report_json": report_json,
            "report_md": report_md,
            "json_path": str(json_path),
            "md_path": str(md_path),
        }
        if ai_report:
            val = ai_report.get("validation") or {}
            if is_confirmed_ai_report(ai_report) or val.get("mode") == "empty":
                out_report["summary"] = ai_report.get("summary", "")
                out_report["items"] = ai_report.get("items", [])
            else:
                # Never propagate unconfirmed/templated AI recommendations on error
                out_report["summary"] = ""
                out_report["items"] = []
            if "validation" in ai_report:
                out_report["validation"] = val

        return {"report": out_report}
