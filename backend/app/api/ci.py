"""CI pipeline integration with token-protected, synchronous/async, severity-gated runs.

This endpoint is intended ONLY for organisation-supplied/safe training projects.
"""
from __future__ import annotations

import os
import secrets
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.config import get_settings
from app.core.db import get_engine
from app.core.models import Run, Workflow
from app.engine.executor import Executor

router = APIRouter(prefix="/api/ci", tags=["ci"])
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_WEBHOOK_RATE_LIMIT: dict[str, list[float]] = defaultdict(list)


def _require_ci_token(token: str | None) -> None:
    configured = os.environ.get("CI_TOKEN", "").strip()
    if not configured:
        raise HTTPException(503, "CI_TOKEN is not configured on the server")
    if not token or not secrets.compare_digest(configured, token):
        raise HTTPException(401, "Invalid or missing X-CI-Token")


def _check_webhook_rate_limit(key: str, limit: int = 30, window_sec: int = 60) -> None:
    now = time.monotonic()
    bucket = [ts for ts in _WEBHOOK_RATE_LIMIT[key] if now - ts < window_sec]
    if len(bucket) >= limit:
        raise HTTPException(429, "CI webhook rate limit exceeded")
    bucket.append(now)
    _WEBHOOK_RATE_LIMIT[key] = bucket


def _evaluate_ci_result(run: Run, fail_on: str) -> dict[str, Any]:
    summary = run.summary_json or {}
    report = summary.get("report") or {}
    findings = report.get("findings") or []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = str(f.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1

    threshold = _RANK[fail_on]
    blocking = [f for f in findings if _RANK.get(str(f.get("severity") or "").upper(), 0) >= threshold]

    if run.status in ("pending", "running"):
        verdict = "RUNNING"
        exit_hint = 0
    elif run.status == "failed":
        verdict = "ERROR"
        exit_hint = 2
    elif blocking:
        verdict = "FAIL"
        exit_hint = 1
    elif run.status == "partial" and not findings:
        verdict = "ERROR"
        exit_hint = 2
    else:
        verdict = "PASS"
        exit_hint = 0

    return {
        "run_id": run.id,
        "status": run.status,
        "execution_status": run.status,
        "verdict": verdict,
        "exit_code_hint": exit_hint,
        "fail_on": fail_on,
        "findings_count": len(findings),
        "blocking_findings": len(blocking),
        "severity_counts": counts,
        "warnings_count": counts["MEDIUM"],
        "info_count": counts["LOW"],
        "ci": summary.get("ci"),
        "report_url": f"/api/runs/{run.id}/report.json",
    }


class CiRunRequest(BaseModel):
    workflow_id: str
    repository: str = ""
    commit: str = ""
    branch: str = ""
    upload_id: str | None = None
    git_url: str | None = None
    subdir: str = ""
    fail_on: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "CRITICAL"
    wait: bool = True


class CiWebhookRequest(BaseModel):
    event: str = "push"
    workflow_id: str
    repository: str = ""
    commit: str = ""
    branch: str = ""
    upload_id: str | None = None
    git_url: str | None = None
    subdir: str = ""
    fail_on: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "CRITICAL"
    wait: bool = False


async def _launch_ci_run(
    workflow_id: str,
    *,
    upload_id: str | None = None,
    git_url: str | None = None,
    subdir: str = "",
    fail_on: str = "CRITICAL",
    wait: bool = True,
    ci_meta: dict[str, str] | None = None,
) -> tuple[Run, dict[str, Any]]:
    settings = get_settings()
    if upload_id:
        try:
            upload_id = str(uuid.UUID(upload_id))
        except ValueError as exc:
            raise HTTPException(400, "upload_id must be UUID") from exc
        if not (settings.upload_dir / f"{upload_id}.zip").is_file():
            raise HTTPException(404, "Uploaded ZIP was not found")

    if git_url:
        norm = git_url.strip().rstrip("/").removesuffix(".git")
        allowed = {u.removesuffix(".git") for u in settings.git_allowlist_set()}
        if norm not in allowed:
            raise HTTPException(403, f"git_url is not in GIT_CLONE_ALLOWLIST: {git_url}")

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
            if subdir:
                n["params"]["subdir"] = subdir

    if git_url:
        git_sources = [n for n in graph.get("nodes", []) if n.get("type") == "source.git_clone"]
        if not git_sources:
            raise HTTPException(400, "Workflow has no source.git_clone node")
        for n in git_sources:
            n.setdefault("params", {})["url"] = git_url.strip()
            if subdir:
                n["params"]["subdir"] = subdir

    def new_session():
        return Session(get_engine())

    try:
        run_id = await Executor(new_session).run_workflow(workflow_id, graph, trigger="ci", wait=wait)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    with Session(get_engine()) as session:
        result = session.get(Run, run_id)
        if not result:
            raise HTTPException(500, "Run result was not persisted")
        summary = dict(result.summary_json or {})
        summary["ci"] = {**(ci_meta or {}), "fail_on": fail_on}
        result.summary_json = summary
        session.add(result)
        session.commit()
        session.refresh(result)
        evaluated = _evaluate_ci_result(result, fail_on)
        return result, evaluated


@router.get("/status")
def ci_status(x_ci_token: str | None = Header(default=None)):
    _require_ci_token(x_ci_token)
    return {"ok": True, "wait_supported": True, "gate_supported": True, "webhook_supported": True}


@router.post("/run")
async def run_ci(body: CiRunRequest, x_ci_token: str | None = Header(default=None)):
    _require_ci_token(x_ci_token)
    result, data = await _launch_ci_run(
        body.workflow_id,
        upload_id=body.upload_id,
        git_url=body.git_url,
        subdir=body.subdir,
        fail_on=body.fail_on,
        wait=body.wait,
        ci_meta={"repository": body.repository, "commit": body.commit, "branch": body.branch},
    )
    if not body.wait:
        return JSONResponse(data, status_code=202)
    code = 500 if data["verdict"] == "ERROR" else 409 if data["verdict"] == "FAIL" else 200
    return JSONResponse(data, status_code=code)


@router.get("/runs/{run_id}")
def get_ci_run_status(
    run_id: str,
    fail_on: str = Query(default="CRITICAL", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    x_ci_token: str | None = Header(default=None),
):
    _require_ci_token(x_ci_token)
    with Session(get_engine()) as session:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        data = _evaluate_ci_result(run, fail_on)
        data["node_statuses"] = (run.summary_json or {}).get("node_statuses") or {}
        return data


@router.get("/runs/{run_id}/result")
def get_ci_run_result(
    run_id: str,
    fail_on: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    x_ci_token: str | None = Header(default=None),
):
    _require_ci_token(x_ci_token)
    with Session(get_engine()) as session:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        ci_meta = (run.summary_json or {}).get("ci") or {}
        effective_fail_on = fail_on or str(ci_meta.get("fail_on") or "CRITICAL")
        if effective_fail_on not in _RANK:
            effective_fail_on = "CRITICAL"
        data = _evaluate_ci_result(run, effective_fail_on)
        report = (run.summary_json or {}).get("report") or {}
        data["findings"] = report.get("findings") or []
        data["ai_report"] = run.ai_report_json
        return data


@router.post("/webhook")
async def ci_webhook(body: CiWebhookRequest, x_ci_token: str | None = Header(default=None)):
    _require_ci_token(x_ci_token)
    _check_webhook_rate_limit(body.repository or body.workflow_id)
    _, data = await _launch_ci_run(
        body.workflow_id,
        upload_id=body.upload_id,
        git_url=body.git_url,
        subdir=body.subdir,
        fail_on=body.fail_on,
        wait=body.wait,
        ci_meta={
            "event": body.event,
            "repository": body.repository,
            "commit": body.commit,
            "branch": body.branch,
        },
    )
    status_code = 202 if not body.wait else (500 if data["verdict"] == "ERROR" else 409 if data["verdict"] == "FAIL" else 200)
    return JSONResponse(data, status_code=status_code)


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
    _, data = await _launch_ci_run(workflow_id, upload_id=upload_id, fail_on=fail_on, wait=True)
    code = 500 if data["verdict"] == "ERROR" else 409 if data["verdict"] == "FAIL" else 200
    return JSONResponse(data, status_code=code)
