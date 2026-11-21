"""Validate LLM output: strict schema, finding_ref, CVE/GHSA from input, no leaked secrets, no fallback."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class ExplainItem(BaseModel):
    finding_ref: int
    explanation: str
    risk: str | None = None
    priority: str | None = None
    fix_steps: list[str] = Field(default_factory=list)


class ExplainResponse(BaseModel):
    summary: str = ""
    items: list[ExplainItem] = Field(default_factory=list)


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
TOKENISH = re.compile(r"(?:sk-|ghp_|xox[baprs]-|AIza)[A-Za-z0-9_\-]{10,}")
SOURCE_LOCATION_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<file>(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:kt|kts|java|gradle))(?:[:#](?P<line>\d+))?"
)


def _allowed_advisories(findings: list[dict]) -> set[str]:
    allowed: set[str] = set()
    for f in findings:
        if f.get("advisoryId"):
            allowed.add(str(f["advisoryId"]).upper())
        for a in f.get("aliases") or []:
            allowed.add(str(a).upper())
    return allowed


def load_known_advisories(vuln_db_path: str | Path | None = None) -> set[str]:
    """Load real advisory IDs (CVE/GHSA) from configured vulnerability-database JSON."""
    ids: set[str] = set()
    candidates: list[Path] = []
    if vuln_db_path:
        p = Path(vuln_db_path)
        candidates.append(p)
        if not p.is_absolute():
            repo_root = Path(__file__).resolve().parents[4]
            candidates.extend([repo_root / p, repo_root / "backend" / p])
    for cand in candidates:
        if cand.is_file():
            try:
                raw = json.loads(cand.read_text(encoding="utf-8"))
                items = raw.get("vulnerabilities", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if item.get("id"):
                        ids.add(str(item["id"]).upper())
                    for a in item.get("aliases") or []:
                        ids.add(str(a).upper())
                if ids:
                    return ids
            except Exception:
                pass
    try:
        from security_scanners.sca.db import VulnerabilityDb

        for v in VulnerabilityDb.load_from_resource():
            if v.id:
                ids.add(str(v.id).upper())
    except Exception:
        pass
    return ids


def validate_llm_response(
    raw: str,
    findings: list[dict],
    known_advisories: set[str] | None = None,
) -> tuple[ExplainResponse | None, dict[str, Any]]:
    """Strictly validate model output. Returns (parsed_or_none, validation_meta)."""
    meta: dict[str, Any] = {
        "passed": False,
        "retried": False,
        "dropped_items": 0,
        "dropped_cve": 0,
        "vuln_db_checked": known_advisories is not None,
        "errors": [],
    }
    if not raw or not str(raw).strip():
        meta["errors"].append("empty model response")
        return None, meta

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        meta["errors"].append(f"invalid JSON: {e}")
        return None, meta

    try:
        parsed = ExplainResponse.model_validate(data)
    except ValidationError as e:
        meta["errors"].append(f"schema: {e}")
        return None, meta

    allowed_refs = set(range(len(findings)))
    allowed_adv = _allowed_advisories(findings)
    if known_advisories:
        verified_adv = {a for a in allowed_adv if a in known_advisories}
        if verified_adv:
            allowed_adv = verified_adv
    kept: list[ExplainItem] = []

    for item in parsed.items:
        if item.finding_ref not in allowed_refs:
            meta["dropped_items"] += 1
            meta["errors"].append(f"bad finding_ref={item.finding_ref}")
            continue

        if not str(item.explanation or "").strip():
            meta["dropped_items"] += 1
            meta["errors"].append(f"empty explanation for finding_ref={item.finding_ref}")
            continue

        f = findings[item.finding_ref]
        path = str(f.get("path") or "").replace("\\", "/")
        source_line = f.get("line")
        invalid_location = False
        for location in SOURCE_LOCATION_RE.finditer(item.explanation):
            mentioned = location.group("file")
            if mentioned not in (path, path.rsplit("/", 1)[-1]):
                invalid_location = True
                break
            mentioned_line = location.group("line")
            if mentioned_line and source_line is not None and int(mentioned_line) != source_line:
                invalid_location = True
                break
        if invalid_location:
            meta["dropped_items"] += 1
            meta["errors"].append(f"unexpected file/line for finding_ref={item.finding_ref}")
            continue

        text = item.explanation + " " + (item.risk or "") + " " + " ".join(item.fix_steps)
        for m in CVE_RE.findall(text) + GHSA_RE.findall(text):
            if m.upper() not in allowed_adv:
                meta["dropped_cve"] += 1
                text = text.replace(m, "[removed-id]")
                item.explanation = item.explanation.replace(m, "[removed-id]")
                if item.risk:
                    item.risk = item.risk.replace(m, "[removed-id]")
                item.fix_steps = [s.replace(m, "[removed-id]") for s in item.fix_steps]

        if TOKENISH.search(text):
            meta["dropped_items"] += 1
            meta["errors"].append("possible secret leak in explanation")
            continue

        kept.append(item)

    parsed.items = kept

    for advisory in CVE_RE.findall(parsed.summary) + GHSA_RE.findall(parsed.summary):
        if advisory.upper() not in allowed_adv:
            parsed.summary = parsed.summary.replace(advisory, "[removed-id]")
            meta["dropped_cve"] += 1

    if TOKENISH.search(parsed.summary):
        parsed.summary = ""
        meta["errors"].append("possible secret leak in summary")

    if findings and not parsed.summary.strip():
        meta["errors"].append("empty summary")

    if findings and not kept:
        meta["errors"].append("no valid explanation items returned")

    has_blocking_error = any(
        tag in err
        for err in meta["errors"]
        for tag in (
            "schema",
            "invalid JSON",
            "empty model response",
            "secret leak",
            "empty summary",
            "no valid explanation items",
        )
    )
    meta["passed"] = (len(kept) > 0 or not findings) and not has_blocking_error
    return parsed, meta
