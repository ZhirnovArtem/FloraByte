"""Stub scanners for development only. Enabled solely when USE_STUB_SCANNERS=1.

NEVER enable in demo / final build by default.
"""
from __future__ import annotations

from pathlib import Path
from app.core.models import Finding
from app.core.masking import mask_secret

def stub_secrets_scan(root: Path, params: dict) -> list[Finding]:
    # Minimal non-matching stub so evaluate can still run; real stubs will mirror ground-truth only under flag
    return []

def stub_sca_scan(root: Path, params: dict) -> list[Finding]:
    return []

def stub_sast_scan(root: Path, params: dict) -> list[Finding]:
    return []
