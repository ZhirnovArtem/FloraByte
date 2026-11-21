import json
from pathlib import Path

from tools.evaluate import evaluate, match_secret_sast, match_sca


def test_match_secret():
    truth = {"category": "SECRET", "class": "api-key", "path": "a/b.kt", "line": 7, "endLine": 7}
    pred = {"category": "SECRET", "class": "api-key", "path": "a/b.kt", "line": 7}
    assert match_secret_sast(pred, truth)


def test_match_sca():
    truth = {
        "category": "SCA",
        "path": "build.gradle.kts",
        "group": "org.apache.commons",
        "artifact": "commons-text",
        "version": "1.9",
        "advisoryIds": ["CVE-2022-42889", "GHSA-xxx"],
    }
    pred = {
        "category": "SCA",
        "path": "build.gradle.kts",
        "group": "org.apache.commons",
        "artifact": "commons-text",
        "version": "1.9",
        "advisoryId": "CVE-2022-42889",
    }
    assert match_sca(pred, truth)


def test_evaluate_perfect():
    truth = {
        "findings": [
            {"id": "1", "category": "SECRET", "class": "password", "path": "x.kt", "line": 1, "endLine": 1},
        ],
        "controls": [
            {"id": "c1", "category": "SECRET", "class": "api-key", "path": "safe.kt", "line": 9, "reason": "placeholder"},
        ],
    }
    report = {
        "findings": [
            {"category": "SECRET", "class": "password", "path": "x.kt", "line": 1},
        ]
    }
    r = evaluate(report, truth)
    assert r["matched"] == 1
    assert r["missed"] == []
    assert r["control_hits"] == []
    assert r["passed"] is True


def test_evaluate_control_fp():
    truth = {
        "findings": [],
        "controls": [
            {"id": "c1", "category": "SECRET", "class": "api-key", "path": "README.md", "line": 9, "reason": "placeholder"},
        ],
    }
    report = {
        "findings": [
            {"category": "SECRET", "class": "api-key", "path": "README.md", "line": 9},
        ]
    }
    r = evaluate(report, truth)
    assert len(r["control_hits"]) == 1
    assert r["passed"] is False


def test_evaluate_cli_exit_codes_and_mutation(tmp_path):
    from tools.evaluate import main as eval_main
    from tools.mutate_project import mutate_once

    truth_path = tmp_path / "truth.json"
    report_ok = tmp_path / "ok.json"
    report_miss = tmp_path / "miss.json"
    truth_path.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "1", "category": "SECRET", "class": "password", "path": "x.kt", "line": 2, "endLine": 2}
                ],
                "controls": [],
            }
        ),
        encoding="utf-8",
    )
    report_ok.write_text(
        json.dumps({"findings": [{"category": "SECRET", "class": "password", "path": "x.kt", "line": 2}]}),
        encoding="utf-8",
    )
    report_miss.write_text(json.dumps({"findings": []}), encoding="utf-8")

    assert eval_main(["--report", str(report_ok), "--truth", str(truth_path)]) == 0
    assert eval_main(["--report", str(report_miss), "--truth", str(truth_path)]) == 1

    src = tmp_path / "src_proj"
    (src / "src" / "main" / "kotlin").mkdir(parents=True)
    (src / "build.gradle.kts").write_text('dependencies { implementation("org.apache.commons:commons-text:1.9") }\n')
    (src / "src" / "main" / "kotlin" / "App.kt").write_text('fun demo() { val secretVal = "my_secret_123456" }\n')
    dst = tmp_path / "mut_proj"
    notes = mutate_once(src, dst, seed=7)
    assert notes and (dst / "build.gradle.kts").is_file()
