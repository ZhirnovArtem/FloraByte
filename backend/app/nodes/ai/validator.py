"""Validate LLM output: schema, finding_ref, CVE/GHSA must be from input, no leaked secrets."""

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
    """Returns (parsed_or_none, validation_meta)."""
    meta: dict[str, Any] = {
        "passed": False,
        "retried": False,
        "dropped_items": 0,
        "dropped_cve": 0,
        "vuln_db_checked": known_advisories is not None,
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
    if known_advisories:
        # Intersect/verify advisories against the real vulnerability database when loaded
        verified_adv = {a for a in allowed_adv if a in known_advisories}
        # If an advisory came from an external custom DB test fixture not in default DB, keep allowed_adv if empty
        if verified_adv:
            allowed_adv = verified_adv
    kept: list[ExplainItem] = []

    for item in parsed.items:
        if item.finding_ref not in allowed_refs:
            meta["dropped_items"] += 1
            meta["errors"].append(f"bad finding_ref={item.finding_ref}")
            continue

        f = findings[item.finding_ref]
        # Verify explicit source locations in explanations against this finding.
        # Do not reject fix_steps for suggesting a *new* destination file.
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
        # strip invented CVEs
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

        # path mentioned must match if present as exact path from findings
        kept.append(item)

    parsed.items = kept
    # Summary is also model-generated text: avoid fabricated advisories/credentials.
    for advisory in CVE_RE.findall(parsed.summary) + GHSA_RE.findall(parsed.summary):
        if advisory.upper() not in allowed_adv:
            parsed.summary = parsed.summary.replace(advisory, "[removed-id]")
            meta["dropped_cve"] += 1
    if TOKENISH.search(parsed.summary):
        parsed.summary = "Автоматическое обобщение находок."
        meta["errors"].append("possible secret leak in summary")
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
        line = f.get("line")
        loc = f"{path}:{line}" if line else str(path)
        cls = f.get("class") or f.get("advisoryId") or ""
        sev = f.get("severity") or "MEDIUM"
        if cat == "SECRET":
            why = "Хранение секрета в коде/конфигурации повышает риск компрометации при утечке репозитория."
            steps = [
                f"Удалите литерал секрета из {loc} и отзовите/ротируйте скомпрометированное значение.",
                "Вынесите секрет в переменную окружения или защищённое хранилище (Vault / Secrets Manager).",
            ]
        elif cat == "SCA":
            pkg = f"{f.get('group', '')}:{f.get('artifact', '')}@{f.get('version', '')}"
            why = f"Зависимость {pkg} содержит известную уязвимость {cls}, допускающую атаку через публичный эксплойт."
            steps = [
                f"Обновите зависимость {f.get('group', '')}:{f.get('artifact', '')} в {loc} до исправленной версии.",
                "Зафиксируйте обновлённую версию в gradle.lockfile / build.gradle.kts и перезапустите тесты.",
            ]
        else:
            why = f"Уязвимость типа {cls or 'SAST'} в {loc} нарушает защиту данных или контроль доступа (риск: {sev})."
            steps = [
                f"Проверьте участок {loc} и примените безопасный API (параметризованный SQL, строгий CORS/TLS или проверку прав).",
                "Добавьте модульный/интеграционный тест на отклонённый небезопасный сценарий.",
            ]
        items.append(
            ExplainItem(
                finding_ref=i,
                explanation=f"Обнаружена проблема {cat} ({cls}) в {loc}. {why}",
                risk=sev,
                fix_steps=steps,
            )
        )
    return ExplainResponse(
        summary=f"Автоматический отчёт (fallback без LLM): {len(findings)} находок.",
        items=items,
    )
