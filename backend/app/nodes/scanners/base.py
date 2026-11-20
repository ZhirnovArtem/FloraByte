"""Scanner interface expected by people 3 & 4.

def scan(root: Path, params: dict) -> list[Finding]:
    ...
Secrets must already be masked via core.masking.mask_secret before return.
"""
from pathlib import Path
from app.core.models import Finding

def scan(root: Path, params: dict) -> list[Finding]:  # type: ignore[empty-body]
    raise NotImplementedError
