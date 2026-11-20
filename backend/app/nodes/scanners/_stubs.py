"""Stub scanners for development only. Enabled solely when USE_STUB_SCANNERS=1.

NEVER enable in demo / final build by default.
These stubs intentionally do NOT mirror ground-truth (forbidden by brief).
They only produce a minimal non-control finding so the pipeline can be exercised.
"""
from __future__ import annotations

from pathlib import Path

from app.core.models import Finding
from app.core.masking import mask_secret


def stub_secrets_scan(root: Path, params: dict) -> list[Finding]:
    # Minimal synthetic finding — NOT matching ground-truth / controls
    return [
        Finding(
            category="SECRET",
            path="stub/demo-secret.kt",
            **{"class": "api-key"},
            line=1,
            severity="LOW",
            description="Stub secret finding (USE_STUB_SCANNERS=1)",
            evidence=mask_secret("stub-demo-key-xxxx"),
            rule_id="stub.secrets",
        )
    ]


def stub_sca_scan(root: Path, params: dict) -> list[Finding]:
    return [
        Finding(
            category="SCA",
            path="build.gradle.kts",
            group="org.example",
            artifact="stub-lib",
            version="0.0.1",
            advisoryId="GHSA-stub-0000-0000",
            severity="LOW",
            description="Stub SCA finding (USE_STUB_SCANNERS=1)",
            rule_id="stub.sca",
        )
    ]


def stub_sast_scan(root: Path, params: dict) -> list[Finding]:
    return [
        Finding(
            category="SAST",
            path="stub/Demo.kt",
            **{"class": "sql-injection"},
            line=1,
            severity="LOW",
            description="Stub SAST finding (USE_STUB_SCANNERS=1)",
            rule_id="stub.sast",
        )
    ]
