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
