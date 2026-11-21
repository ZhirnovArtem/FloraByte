"""CI pipeline integration with token-protected, synchronous, severity-gated runs.

This endpoint is intended ONLY for organisation-supplied/safe training projects.
"""
from __future__ import annotations

import os
import secrets
import uuid
from copy import deepcopy

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlmodel import Session

from app.core.db import get_engine
from app.core.models import Run, Workflow
from app.engine.executor import Executor

router = APIRouter(prefix="/api/ci", tags=["ci"])
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _require_ci_token(token: str | None) -> None:
    configured = os.environ.get("CI_TOKEN", "").strip()
    if not configured:
        raise HTTPException(503, "CI_TOKEN is not configured on the server")
    if not token or not secrets.compare_digest(configured, token):
        raise HTTPException(401, "Invalid or missing X-CI-Token")


@router.get("/status")
def ci_status(x_ci_token: str | None = Header(default=None)):
    _require_ci_token(x_ci_token)
    return {"ok": True, "wait_supported": True, "gate_supported": True}


@router.post("/workflows/{workflow_id}/run")
async def run_ci_workflow(
    workflow_id: str,
    upload_id: str | None = None,
    fail_on: str = Query(default="CRITICAL", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    x_ci_token: str | None = Header(default=None),
):
    """Run a stored graph with an optional newly uploaded ZIP; fail on severity threshold.

    Exit-friendly HTTP codes: 200 PASS, 409 security findings >= threshold,
    500 execution failure. CI should use `curl --fail-with-body`.
    """
    _require_ci_token(x_ci_token)
    from app.config import get_settings
    if upload_id:
        try:
            upload_id = str(uuid.UUID(upload_id))
        except ValueError as exc:
            raise HTTPException(400, "upload_id must be UUID") from exc
        if not (get_settings().upload_dir / f"{upload_id}.zip").is_file():
            raise HTTPException(404, "Uploaded ZIP was not found")

    with Session(get_engine()) as session:
        workflow = session.get(Workflow, workflow_id)
        if not workflow:
            raise HTTPException(404, "Workflow not found")
        graph = deepcopy(workflow.graph_json or {})
    if upload_id:
        sources = [n for n in graph.get("nodes", []) if n.get("type") == "source.upload_zip"]
        if not sources:
            raise HTTPException(400, "Workflow has no source.upload_zip node")
        for n in sources:
            n.setdefault("params", {})["upload_id"] = upload_id

    def new_session():
        return Session(get_engine())

    try:
        run_id = await Executor(new_session).run_workflow(workflow_id, graph, trigger="ci", wait=True)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    with Session(get_engine()) as session:
        result = session.get(Run, run_id)
        if not result:
            raise HTTPException(500, "Run result was not persisted")
        report = (result.summary_json or {}).get("report") or {}
        findings = report.get("findings") or []
        bad = [f for f in findings if _RANK.get(str(f.get("severity") or "").upper(), 0) >= _RANK[fail_on]]
        verdict = "FAIL" if result.status != "success" or bad else "PASS"
        data = {
            "run_id": run_id,
            "execution_status": result.status,
            "verdict": verdict,
            "fail_on": fail_on,
            "findings_count": len(findings),
            "blocking_findings": len(bad),
        }
        code = 500 if result.status != "success" else 409 if bad else 200
        return JSONResponse(data, status_code=code)
