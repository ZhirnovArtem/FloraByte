from app.nodes.ai.validator import validate_llm_response, fallback_report
import json


def test_valid_response():
    findings = [{"category": "SECRET", "path": "a.kt", "class": "api-key", "line": 1}]
    raw = json.dumps({
        "summary": "one issue",
        "items": [{"finding_ref": 0, "explanation": "key in code", "risk": "HIGH", "fix_steps": ["use env"]}]
    })
    parsed, meta = validate_llm_response(raw, findings)
    assert parsed is not None
    assert meta["passed"]
    assert len(parsed.items) == 1


def test_bad_ref_dropped():
    findings = [{"category": "SECRET", "path": "a.kt", "class": "api-key", "line": 1}]
    raw = json.dumps({
        "summary": "x",
        "items": [{"finding_ref": 99, "explanation": "nope", "fix_steps": []}]
    })
    parsed, meta = validate_llm_response(raw, findings)
    assert parsed is not None
    assert meta["dropped_items"] >= 1
    assert parsed.items == []


def test_invented_cve_stripped():
    findings = [{"category": "SCA", "path": "build.gradle.kts", "group": "g", "artifact": "a", "version": "1", "advisoryId": "CVE-2022-42889"}]
    raw = json.dumps({
        "summary": "x",
        "items": [{"finding_ref": 0, "explanation": "See CVE-2099-99999 and CVE-2022-42889", "fix_steps": []}]
    })
    parsed, meta = validate_llm_response(raw, findings)
    assert parsed is not None
    assert meta["dropped_cve"] >= 1
    assert "CVE-2099-99999" not in parsed.items[0].explanation
    assert "CVE-2022-42889" in parsed.items[0].explanation or "[removed-id]" in parsed.items[0].explanation


def test_invalid_json():
    parsed, meta = validate_llm_response("not json", [])
    assert parsed is None
    assert meta["passed"] is False


def test_fallback():
    fb = fallback_report([{"category": "SAST", "path": "x.kt", "class": "sql-injection"}])
    assert len(fb.items) == 1
    assert "fallback" in fb.summary.lower() or "Автоматический" in fb.summary


def test_load_known_advisories_and_check(tmp_path):
    from app.nodes.ai.validator import load_known_advisories

    known_default = load_known_advisories()
    assert "CVE-2021-44228" in known_default

    db_file = tmp_path / "vulns.json"
    db_file.write_text(
        json.dumps({"vulnerabilities": [{"id": "GHSA-599f-7c49-w659", "aliases": ["CVE-2022-42889"]}]}),
        encoding="utf-8",
    )
    known = load_known_advisories(db_file)
    assert "CVE-2022-42889" in known
    findings = [{"category": "SCA", "path": "build.gradle.kts", "group": "org.apache.commons", "artifact": "commons-text", "version": "1.9", "advisoryId": "CVE-2022-42889"}]
    raw = json.dumps({
        "summary": "CVE-2099-0001 invented",
        "items": [{"finding_ref": 0, "explanation": "Real CVE-2022-42889", "fix_steps": ["update"]}]
    })
    parsed, meta = validate_llm_response(raw, findings, known_advisories=known)
    assert parsed is not None
    assert meta["vuln_db_checked"] is True
    assert meta["dropped_cve"] == 1
    assert "CVE-2099-0001" not in parsed.summary
