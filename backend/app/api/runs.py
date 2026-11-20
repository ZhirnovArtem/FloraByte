from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from sqlmodel import Session, select

from app.core.db import get_session
from app.core.models import NodeRun, Run
from pathlib import Path

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _run_dict(r: Run, node_runs: list[NodeRun] | None = None) -> dict:
    d = {
        "id": r.id,
        "workflow_id": r.workflow_id,
        "status": r.status,
        "trigger": r.trigger,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
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
def list_runs(session: Session = Depends(get_session), limit: int = 50):
    items = list(session.exec(select(Run).limit(500)).all())
    items.sort(key=lambda r: r.started_at or r.finished_at or r.id, reverse=True)
    items = items[:limit]
    return {"runs": [_run_dict(r) for r in items]}


@router.get("/{run_id}")
def get_run(run_id: str, session: Session = Depends(get_session)):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    nrs = session.exec(select(NodeRun).where(NodeRun.run_id == run_id)).all()
    return _run_dict(r, list(nrs))


@router.get("/{run_id}/report.json")
def get_report_json(run_id: str, session: Session = Depends(get_session)):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    # Look for report in summary or on disk
    summary = r.summary_json or {}
    paths = (summary.get("report") or {}).get("paths") or {}
    json_path = paths.get("json_path")
    if json_path and Path(json_path).exists():
        return FileResponse(json_path, media_type="application/json", filename="report.json")
    # try standard location
    from app.config import get_settings
    p = get_settings().runs_dir / run_id / "reports" / "report.json"
    if p.exists():
        return FileResponse(p, media_type="application/json", filename="report.json")
    # fallback from summary findings
    if "report" in summary and isinstance(summary["report"], dict):
        findings = summary["report"].get("findings")
        if findings is not None:
            return JSONResponse({"findings": findings})
    return JSONResponse({"findings": []})


@router.get("/{run_id}/report.md")
def get_report_md(run_id: str, session: Session = Depends(get_session)):
    r = session.get(Run, run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    summary = r.summary_json or {}
    paths = (summary.get("report") or {}).get("paths") or {}
    md_path = paths.get("md_path")
    if md_path and Path(md_path).exists():
        return FileResponse(md_path, media_type="text/markdown", filename="report.md")
    from app.config import get_settings
    p = get_settings().runs_dir / run_id / "reports" / "report.md"
    if p.exists():
        return FileResponse(p, media_type="text/markdown", filename="report.md")
    return PlainTextResponse("Находок нет.\n")
