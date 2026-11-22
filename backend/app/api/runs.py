from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from sqlmodel import Session, select

from app.core.auth import check_owner, get_current_user
from app.core.db import get_session
from app.core.models import Finding, NodeRun, Run, User
from app.core.pdf_export import render_report_pdf
from app.core.run_analytics import (
    build_severity_dashboard,
    compare_runs,
    deduplicate_across_runs,
    load_run_findings,
)
from app.nodes.findings.report_export import render_markdown

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _duration_ms(r: Run) -> int | None:
    if not r.started_at or not r.finished_at:
        return None
    st = r.started_at if r.started_at.tzinfo else r.started_at.replace(tzinfo=timezone.utc)
    fin = r.finished_at if r.finished_at.tzinfo else r.finished_at.replace(tzinfo=timezone.utc)
    return max(0, int((fin - st).total_seconds() * 1000))


def _run_dict(r: Run, node_runs: list[NodeRun] | None = None) -> dict:
    d = {
        "id": r.id,
        "workflow_id": r.workflow_id,
        "status": r.status,
        "trigger": r.trigger,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "duration_ms": _duration_ms(r),
        "summary": r.summary_json,
        "ai_report": r.ai_report_json,
    }
    if node_runs is not None:
        d["nodes"] = [
            {
                "node_id": nr.node_id,
                "status": nr.status,
                "started_at": nr.started_at.isoformat() if nr.started_at else None,
                "finished_at": nr.finished_at.isoformat() if nr.finished_at else None,
                "output_preview": nr.output_preview_json,
                "error": nr.error,
            }
            for nr in node_runs
        ]
    return d


@router.get("")
def list_runs(
    session: Session = Depends(get_session),
    limit: int = 50,
    user: Optional[User] = Depends(get_current_user),
):
    items = list(session.exec(select(Run).limit(500)).all())
    if user is not None:
        items = [r for r in items if r.owner_id in (None, user.id)]
    def _run_sort_key(r: Run):
        dt = r.started_at or r.finished_at
        if dt is None:
            return (0, datetime.min.replace(tzinfo=timezone.utc), r.id)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (1, dt, r.id)

    items.sort(key=_run_sort_key, reverse=True)
    items = items[:limit]
    return {"runs": [_run_dict(r) for r in items]}


@router.get("/compare")
def compare_two_runs(
    base: str = Query(..., description="Baseline run ID"),
    target: str = Query(..., description="Target run ID"),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    base_run = session.get(Run, base)
    target_run = session.get(Run, target)
    if not base_run or not target_run:
        raise HTTPException(404, "Run not found for comparison")
    check_owner(base_run.owner_id, user)
    check_owner(target_run.owner_id, user)

    base_findings = load_run_findings(base_run)
    target_findings = load_run_findings(target_run)
    diff = compare_runs(base_findings, target_findings)
    return {
        "base_run": _run_dict(base_run),
        "target_run": _run_dict(target_run),
        **diff,
    }


@router.get("/{run_id}")
def get_run(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    check_owner(r.owner_id, user)
    nrs = session.exec(select(NodeRun).where(NodeRun.run_id == run_id)).all()
    out = _run_dict(r, list(nrs))
    out["dashboard"] = build_severity_dashboard(load_run_findings(r))
    return out


@router.get("/{run_id}/dedup")
def get_run_dedup(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    check_owner(r.owner_id, user)

    same_wf_runs = list(session.exec(select(Run).where(Run.workflow_id == r.workflow_id)).all())
    if user is not None:
        same_wf_runs = [item for item in same_wf_runs if item.owner_id in (None, user.id)]
    same_wf_runs.sort(key=lambda item: item.started_at or item.finished_at or item.id)

    prior_findings: list[dict] = []
    prior_run_id: str | None = None
    for prev in same_wf_runs:
        if prev.id == r.id:
            break
        prior_run_id = prev.id
        prior_findings.extend(load_run_findings(prev))

    current_findings = load_run_findings(r)
    dedup = deduplicate_across_runs(current_findings, prior_findings)
    return {
        "run_id": r.id,
        "workflow_id": r.workflow_id,
        "baseline_run_id": prior_run_id,
        **dedup,
    }


@router.get("/{run_id}/report.json")
def get_report_json(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    check_owner(r.owner_id, user)
    summary = r.summary_json or {}
    paths = (summary.get("report") or {}).get("paths") or {}
    json_path = paths.get("json_path")
    if json_path and Path(json_path).exists():
        return FileResponse(json_path, media_type="application/json", filename="report.json")
    from app.config import get_settings
    p = get_settings().runs_dir / run_id / "reports" / "report.json"
    if p.exists():
        return FileResponse(p, media_type="application/json", filename="report.json")
    if "report" in summary and isinstance(summary["report"], dict):
        findings = summary["report"].get("findings")
        if findings is not None:
            return JSONResponse({"findings": findings})
    return JSONResponse({"findings": []})


@router.get("/{run_id}/report.md")
def get_report_md(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    check_owner(r.owner_id, user)
    summary = r.summary_json or {}
    paths = (summary.get("report") or {}).get("paths") or {}
    md_path = paths.get("md_path")
    if md_path and Path(md_path).exists():
        return FileResponse(md_path, media_type="text/markdown", filename="report.md")
    from app.config import get_settings
    p = get_settings().runs_dir / run_id / "reports" / "report.md"
    if p.exists():
        return FileResponse(p, media_type="text/markdown", filename="report.md")
    raw_findings = load_run_findings(r)
    if raw_findings or r.ai_report_json:
        parsed_findings = []
        for item in raw_findings:
            try:
                parsed_findings.append(Finding.model_validate(item))
            except Exception:
                pass
        return PlainTextResponse(
            render_markdown(parsed_findings, ai_report=r.ai_report_json),
            media_type="text/markdown",
        )
    return PlainTextResponse("Находок нет.\n")


@router.get("/{run_id}/report.pdf")
def get_report_pdf(
    run_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    check_owner(r.owner_id, user)
    findings = load_run_findings(r)
    pdf_bytes = render_report_pdf(
        run_id=r.id,
        status=r.status,
        findings=findings,
        ai_report=r.ai_report_json,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="report.pdf"'},
    )
