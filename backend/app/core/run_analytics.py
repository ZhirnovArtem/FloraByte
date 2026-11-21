"""Cross-run finding deduplication, run comparison, and severity dashboard analytics."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from app.config import get_settings
from app.core.models import Run

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


def load_run_findings(run: Run) -> list[dict]:
    """Load findings for a Run from report.json on disk or summary fallback."""
    summary = run.summary_json or {}
    paths = (summary.get("report") or {}).get("paths") or {}
    candidates = []
    if paths.get("json_path"):
        candidates.append(Path(paths["json_path"]))
    candidates.append(get_settings().runs_dir / run.id / "reports" / "report.json")

    for p in candidates:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                findings = data.get("findings")
                if isinstance(findings, list):
                    return findings
            except Exception:
                pass

    rep = summary.get("report")
    if isinstance(rep, dict) and isinstance(rep.get("findings"), list):
        return list(rep["findings"])
    return []


def finding_fingerprint(finding: dict) -> str:
    """Compute a stable cross-run canonical fingerprint for a finding."""
    category = str(finding.get("category") or "").upper()
    rule_id = str(
        finding.get("advisoryId")
        or finding.get("class")
        or finding.get("ruleId")
        or ""
    )
    path = str(finding.get("path") or "")
    line = str(finding.get("line") or finding.get("startLine") or 0)
    pkg = ""
    if category == "SCA":
        pkg = f"{finding.get('group', '')}:{finding.get('artifact', '')}@{finding.get('version', '')}"
    raw = f"{category}|{rule_id}|{path}|{line}|{pkg}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def build_severity_dashboard(findings: list[dict]) -> dict:
    """Compute severity counts, category counts, and top rules."""
    sev_counts: Counter[str] = Counter()
    cat_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()

    for f in findings:
        sev = str(f.get("severity") or "UNKNOWN").upper()
        cat = str(f.get("category") or "UNKNOWN").upper()
        rule = str(f.get("advisoryId") or f.get("class") or f.get("ruleId") or cat)
        sev_counts[sev] += 1
        cat_counts[cat] += 1
        rule_counts[rule] += 1

    ordered_sev = {k: sev_counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for k, v in sev_counts.items():
        if k not in ordered_sev:
            ordered_sev[k] = v

    return {
        "total": len(findings),
        "by_severity": ordered_sev,
        "by_category": dict(cat_counts),
        "top_rules": [{"rule": r, "count": c} for r, c in rule_counts.most_common(5)],
    }


def _index_by_fingerprint(findings: list[dict]) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    occ: Counter[str] = Counter()
    for f in findings:
        base_fp = finding_fingerprint(f)
        occ[base_fp] += 1
        # Keep identical fingerprints distinguishable if multiple lines/hits share key
        fp = base_fp if occ[base_fp] == 1 else f"{base_fp}-{occ[base_fp]}"
        indexed[fp] = {**f, "fingerprint": fp}
    return indexed


def compare_runs(base_findings: list[dict], target_findings: list[dict]) -> dict:
    """Diff target findings against base findings using canonical fingerprints."""
    base_map = _index_by_fingerprint(base_findings)
    target_map = _index_by_fingerprint(target_findings)

    base_keys = set(base_map.keys())
    target_keys = set(target_map.keys())

    new_items = [target_map[k] for k in sorted(target_keys - base_keys)]
    fixed_items = [base_map[k] for k in sorted(base_keys - target_keys)]
    persisting_items = [target_map[k] for k in sorted(target_keys & base_keys)]

    base_dash = build_severity_dashboard(base_findings)
    target_dash = build_severity_dashboard(target_findings)

    severity_delta = {
        sev: target_dash["by_severity"].get(sev, 0) - base_dash["by_severity"].get(sev, 0)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    return {
        "summary": {
            "base_total": len(base_findings),
            "target_total": len(target_findings),
            "new_count": len(new_items),
            "fixed_count": len(fixed_items),
            "persisting_count": len(persisting_items),
            "delta": len(target_findings) - len(base_findings),
        },
        "severity_delta": severity_delta,
        "base_dashboard": base_dash,
        "target_dashboard": target_dash,
        "new": new_items,
        "fixed": fixed_items,
        "persisting": persisting_items,
    }


def deduplicate_across_runs(current_findings: list[dict], prior_findings: list[dict]) -> dict:
    """Annotate current findings as 'new' vs 'persisting' compared to prior run(s)."""
    prior_fps = {finding_fingerprint(f) for f in prior_findings}
    annotated: list[dict] = []
    new_count = 0
    persisting_count = 0
    seen_current: set[str] = set()

    for f in current_findings:
        fp = finding_fingerprint(f)
        if fp in seen_current:
            continue
        seen_current.add(fp)
        status = "persisting" if fp in prior_fps else "new"
        if status == "new":
            new_count += 1
        else:
            persisting_count += 1
        annotated.append({**f, "fingerprint": fp, "dedup_status": status})

    return {
        "total_unique": len(annotated),
        "new_count": new_count,
        "persisting_count": persisting_count,
        "findings": annotated,
    }
