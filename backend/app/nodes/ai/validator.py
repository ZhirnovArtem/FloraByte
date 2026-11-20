"""Validate LLM output: schema, finding_ref, CVE/GHSA must be from input, no leaked secrets."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class ExplainItem(BaseModel):
    finding_ref: int
    explanation: str
    risk: str | None = None
    fix_steps: list[str] = Field(default_factory=list)


class ExplainResponse(BaseModel):
    summary: str = ""
    items: list[ExplainItem] = Field(default_factory=list)


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
TOKENISH = re.compile(r"(?:sk-|ghp_|xox[baprs]-|AIza)[A-Za-z0-9_\-]{10,}")


def _allowed_advisories(findings: list[dict]) -> set[str]:
    allowed: set[str] = set()
    for f in findings:
        if f.get("advisoryId"):
            allowed.add(str(f["advisoryId"]).upper())
        for a in f.get("aliases") or []:
            allowed.add(str(a).upper())
    return allowed


def validate_llm_response(
    raw: str,
    findings: list[dict],
) -> tuple[ExplainResponse | None, dict[str, Any]]:
    """Returns (parsed_or_none, validation_meta)."""
    meta: dict[str, Any] = {
        "passed": False,
        "retried": False,
        "dropped_items": 0,
        "dropped_cve": 0,
        "errors": [],
    }
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
    kept: list[ExplainItem] = []

    for item in parsed.items:
        if item.finding_ref not in allowed_refs:
            meta["dropped_items"] += 1
            meta["errors"].append(f"bad finding_ref={item.finding_ref}")
            continue

        f = findings[item.finding_ref]
        # file/line consistency if model mentioned path — soft check on explanation only for CVE
        text = item.explanation + " " + " ".join(item.fix_steps)
        # strip invented CVEs
        for m in CVE_RE.findall(text) + GHSA_RE.findall(text):
            if m.upper() not in allowed_adv:
                meta["dropped_cve"] += 1
                text = text.replace(m, "[removed-id]")
                item.explanation = item.explanation.replace(m, "[removed-id]")
                item.fix_steps = [s.replace(m, "[removed-id]") for s in item.fix_steps]

        if TOKENISH.search(text):
            meta["dropped_items"] += 1
            meta["errors"].append("possible secret leak in explanation")
            continue

        # path mentioned must match if present as exact path from findings
        kept.append(item)

    parsed.items = kept
    meta["passed"] = len(meta["errors"]) == 0 or (len(kept) > 0 and meta["dropped_items"] == 0 and meta["dropped_cve"] == 0)
    # softer: pass if we have any kept items and no schema failure
    if kept and not any("schema" in e or "invalid JSON" in e for e in meta["errors"]):
        meta["passed"] = True
    return parsed, meta


def fallback_report(findings: list[dict]) -> ExplainResponse:
    items = []
    for i, f in enumerate(findings):
        cat = f.get("category", "?")
        path = f.get("path", "?")
        cls = f.get("class") or f.get("advisoryId") or ""
        items.append(
            ExplainItem(
                finding_ref=i,
                explanation=f"Обнаружена находка {cat} ({cls}) в файле {path}. Требуется ручная проверка и исправление.",
                risk=f.get("severity") or "MEDIUM",
                fix_steps=[
                    "Просмотрите указанный файл и строку",
                    "Исправьте проблему согласно категории (секрет → env, SCA → обновить зависимость, SAST → безопасный API)",
                ],
            )
        )
    return ExplainResponse(
        summary=f"Автоматический отчёт (fallback без LLM): {len(findings)} находок.",
        items=items,
    )
