"""CI helpers: documented use of POST /api/workflows/{id}/run?wait=true with optional token."""

from __future__ import annotations

import os

from fastapi import APIRouter, Header, HTTPException

router = APIRouter(prefix="/api/ci", tags=["ci"])


@router.get("/status")
def ci_status(x_ci_token: str | None = Header(default=None)):
    """Health for CI. If CI_TOKEN env is set, require matching X-CI-Token header."""
    expected = os.environ.get("CI_TOKEN", "")
    if expected and x_ci_token != expected:
        raise HTTPException(401, "Invalid or missing X-CI-Token")
    return {"ok": True, "phase": "E", "wait_supported": True}
