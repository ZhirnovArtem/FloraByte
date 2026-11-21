from __future__ import annotations

import json
from pathlib import Path

from app.nodes.scanners import sast, sca, secrets


def test_secrets_adapter_maps_class_and_masks_bearer(tmp_path: Path):
    (tmp_path / "application.yml").write_text(
        'pickup:\n  callback:\n    authorization: "Bearer cg26_super_secret_token_99999"\n',
        encoding="utf-8",
    )
    (tmp_path / "Cfg.kt").write_text('val legacyPassword = "my-raw-password-123"\n', encoding="utf-8")

    findings = secrets.scan(tmp_path)
    assert len(findings) >= 2
    classes = {f.class_ for f in findings}
    assert "configuration-token" in classes
    assert "password" in classes
    for f in findings:
        assert "cg26_super_secret_token_99999" not in (f.evidence or "")
        assert "my-raw-password-123" not in (f.evidence or "")
        assert "cg26_super_secret_token_99999" not in (f.description or "")


def test_sca_adapter_supports_organisers_db_schema(tmp_path: Path):
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies {\n    implementation("org.apache.commons:commons-text:1.9")\n    implementation("org.apache.commons:commons-lang3:3.20.0")\n}\n',
        encoding="utf-8",
    )
    db_file = tmp_path / "vulnerabilities.json"
    db_file.write_text(
        json.dumps(
            {
                "formatVersion": 1,
                "vulnerabilities": [
                    {
                        "id": "GHSA-599f-7c49-w659",
                        "aliases": ["CVE-2022-42889"],
                        "group": "org.apache.commons",
                        "artifact": "commons-text",
                        "ranges": [{"lower": "1.5", "lowerInclusive": True, "upper": "1.10.0", "upperInclusive": False}],
                        "fixedVersions": ["1.10.0"],
                        "severity": "CRITICAL",
                    },
                    {
                        "id": "GHSA-j288-q9x7-2f5v",
                        "aliases": ["CVE-2025-48924"],
                        "group": "org.apache.commons",
                        "artifact": "commons-lang3",
                        "ranges": [{"lower": "3.0", "lowerInclusive": True, "upper": "3.18.0", "upperInclusive": False}],
                        "fixedVersions": ["3.18.0"],
                        "severity": "MEDIUM",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = sca.scan(tmp_path, {"vuln_db_path": str(db_file)})
    assert len(findings) == 1
    assert findings[0].category == "SCA"
    assert findings[0].group == "org.apache.commons"
    assert findings[0].artifact == "commons-text"
    assert findings[0].version == "1.9"
    assert findings[0].advisoryId == "CVE-2022-42889"


def test_sast_adapter_maps_rule_to_organiser_class(tmp_path: Path):
    src = tmp_path / "src" / "main" / "kotlin"
    src.mkdir(parents=True)
    (src / "Lookup.kt").write_text(
        'fun find(id: String) = jdbcTemplate.query("SELECT * FROM t WHERE id = " + id)\n',
        encoding="utf-8",
    )
    findings = sast.scan(tmp_path)
    assert len(findings) >= 1
    assert any(f.class_ == "sql-injection" and f.category == "SAST" for f in findings)
