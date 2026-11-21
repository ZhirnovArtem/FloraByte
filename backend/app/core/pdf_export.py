"""Pure-Python multi-page PDF 1.4 export for security scan reports (no external deps)."""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone

from app.core.masking import redact_text
from app.core.run_analytics import build_severity_dashboard

_CYRILLIC_TO_LATIN = str.maketrans({
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "А": "A", "Б": "B", "В": "V", "Г": "G", "Д": "D", "Е": "E", "Ё": "Yo", "Ж": "Zh",
    "З": "Z", "И": "I", "Й": "Y", "K": "K", "К": "K", "Л": "L", "М": "M", "Н": "N", "О": "O",
    "П": "P", "Р": "R", "С": "S", "Т": "T", "У": "U", "Ф": "F", "Х": "Kh", "Ц": "Ts",
    "Ч": "Ch", "Ш": "Sh", "Щ": "Shch", "Ъ": "", "Ы": "Y", "Ь": "", "Э": "E", "Ю": "Yu", "Я": "Ya",
    "—": "-", "–": "-", "«": '"', "»": '"', "№": "#",
})


def _pdf_safe_text(text: str) -> str:
    s = redact_text(str(text or "")).translate(_CYRILLIC_TO_LATIN)
    cleaned = "".join(ch if 32 <= ord(ch) <= 126 else "?" for ch in s)
    return cleaned.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_lines(run_id: str, status: str, findings: list[dict], ai_report: dict | None) -> list[tuple[str, bool]]:
    dash = build_severity_dashboard(findings)
    lines: list[tuple[str, bool]] = [
        ("FloraByte AI Security Workflow - Scan Report", True),
        (f"Run ID: {run_id}   Status: {status}   Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", False),
        ("", False),
        ("Severity Summary", True),
        (
            f"Total: {dash['total']}  |  CRITICAL: {dash['by_severity'].get('CRITICAL', 0)}  |  "
            f"HIGH: {dash['by_severity'].get('HIGH', 0)}  |  "
            f"MEDIUM: {dash['by_severity'].get('MEDIUM', 0)}  |  "
            f"LOW: {dash['by_severity'].get('LOW', 0)}",
            False,
        ),
        (f"Categories: {dash['by_category']}", False),
        ("", False),
    ]

    val = (ai_report or {}).get("validation") or {}
    confirmed_ai = bool(
        ai_report
        and val.get("mode") == "llm"
        and val.get("passed") is True
        and isinstance(ai_report.get("items"), list)
        and len(ai_report["items"]) > 0
    )

    if confirmed_ai and ai_report and ai_report.get("summary"):
        lines.append(("AI Executive Summary", True))
        for wrapped in textwrap.wrap(str(ai_report.get("summary")), width=90):
            lines.append((wrapped, False))
        ai_status = val.get("ai_status") or "Успешно"
        prov_label = val.get("provider_label") or val.get("provider") or "AI"
        model_label = f" ({val['model']})" if val.get("model") else ""
        lines.append((f"AI Provider: {prov_label}{model_label} | Status: {ai_status} (mode={val.get('mode', 'llm')} passed={val.get('passed')})", False))
        lines.append(("", False))
    elif ai_report and val.get("mode") == "error":
        lines.append(("AI Analysis Error", True))
        lines.append(("AI-analiz ne vypolnen. Proverte API-klyuch i dostupnost modeli.", False))
        if val.get("error"):
            for wrapped in textwrap.wrap(str(val["error"]), width=90):
                lines.append((wrapped, False))
        lines.append(("", False))

    ai_by_ref: dict[int, dict] = {}
    if confirmed_ai and ai_report and isinstance(ai_report.get("items"), list):
        for item in ai_report["items"]:
            if isinstance(item, dict) and isinstance(item.get("finding_ref"), int):
                ai_by_ref[item["finding_ref"]] = item

    lines.append((f"Findings ({len(findings)})", True))
    if not findings:
        lines.append(("No security findings detected.", False))
    else:
        for idx, f in enumerate(findings, start=1):
            cat = f.get("category", "?")
            sev = f.get("severity", "?")
            path = f.get("path", "?")
            line = f.get("line") or f.get("startLine") or "-"
            rule = f.get("advisoryId") or f.get("class") or f.get("ruleId") or ""
            header = f"{idx}. [{sev}] {cat} {rule} - {path}:{line}"
            for w in textwrap.wrap(header, width=92):
                lines.append((w, True))
            desc = f.get("description") or f.get("remediation") or ""
            if desc:
                for w in textwrap.wrap(f"   {desc}", width=92):
                    lines.append((w, False))
            ai_item = ai_by_ref.get(idx - 1)
            if ai_item:
                if ai_item.get("explanation"):
                    for w in textwrap.wrap(f"   AI Explanation: {ai_item['explanation']}", width=92):
                        lines.append((w, False))
                if ai_item.get("risk"):
                    for w in textwrap.wrap(f"   Impact / Risk: {ai_item['risk']}", width=92):
                        lines.append((w, False))
                if ai_item.get("priority"):
                    for w in textwrap.wrap(f"   Priority: {ai_item['priority']}", width=92):
                        lines.append((w, False))
                for step in ai_item.get("fix_steps") or []:
                    for w in textwrap.wrap(f"   Fix: {step}", width=92):
                        lines.append((w, False))
    return lines


def render_report_pdf(
    run_id: str,
    status: str,
    findings: list[dict],
    ai_report: dict | None = None,
) -> bytes:
    """Render a valid multi-page PDF 1.4 document as bytes."""
    lines = _build_lines(run_id, status, findings, ai_report)
    lines_per_page = 48
    pages_lines = [lines[i : i + lines_per_page] for i in range(0, max(1, len(lines)), lines_per_page)]

    # Object layout:
    # 1: Catalog, 2: Pages, 3: Font F1 (Helvetica), 4: Font F2 (Helvetica-Bold)
    # Then for each page i: (5 + 2*i) = Page object, (6 + 2*i) = Content stream
    objects: list[bytes] = []
    page_ids: list[int] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")  # placeholder for Pages
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    for idx, page_chunk in enumerate(pages_lines):
        page_obj_num = 5 + idx * 2
        content_obj_num = 6 + idx * 2
        page_ids.append(page_obj_num)

        cmds = ["BT", "50 760 Td", "14 TL"]
        for text, bold in page_chunk:
            font = "/F2 10 Tf" if bold else "/F1 9.5 Tf"
            cmds.append(font)
            cmds.append(f"({_pdf_safe_text(text)}) Tj")
            cmds.append("T*")
        cmds.append("ET")
        stream_bytes = "\n".join(cmds).encode("latin-1", errors="replace")

        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_obj_num} 0 R >>"
        ).encode("latin-1")
        content_obj = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream"
        )
        objects.append(page_dict)
        objects.append(content_obj)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = [0]
    for obj_num, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{obj_num} 0 obj\n".encode("latin-1"))
        out.extend(body)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

    out.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("latin-1")
    )
    return bytes(out)
