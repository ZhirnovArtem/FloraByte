from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.auth import check_owner, get_current_user
from app.core.db import get_session
from app.core.models import User, Workflow
from app.engine.executor import Executor
from app.engine.graph import GraphError, validate_graph
from app.engine.scheduler import (
    get_workflow_scheduled_jobs_count,
    inspect_schedule_graph,
    reload_schedules,
)
from app.nodes.custom_manager import build_effective_registry

router = APIRouter(prefix="/api/workflows", tags=["workflows"])


class WorkflowCreate(BaseModel):
    name: str
    graph: dict[str, Any] = Field(default_factory=dict, alias="graph_json")
    description: str = ""
    is_template: bool = False

    model_config = {"populate_by_name": True}


class WorkflowUpdate(BaseModel):
    name: str | None = None
    graph: dict[str, Any] | None = Field(default=None, alias="graph_json")
    description: str | None = None
    is_template: bool | None = None

    model_config = {"populate_by_name": True}


def _to_dict(w: Workflow) -> dict:
    graph = w.graph_json or {}
    active_schedules, schedule_warnings = inspect_schedule_graph(graph)
    return {
        "id": w.id,
        "name": w.name,
        "graph_json": graph,
        "is_template": w.is_template,
        "description": w.description,
        "scheduled_jobs": get_workflow_scheduled_jobs_count(w.id),
        "schedule_summary": active_schedules,
        "schedule_warnings": schedule_warnings,
        "created_at": w.created_at.isoformat() if w.created_at else None,
        "updated_at": w.updated_at.isoformat() if w.updated_at else None,
    }


@router.get("")
def list_workflows(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    items = session.exec(select(Workflow).where(Workflow.is_template == False)).all()  # noqa: E712
    if user is not None:
        items = [w for w in items if w.owner_id in (None, user.id)]
    return {"workflows": [_to_dict(w) for w in items]}


@router.post("")
def create_workflow(
    body: WorkflowCreate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    graph = body.graph or {}
    if graph.get("nodes"):
        try:
            eff_registry = build_effective_registry(session, owner_id=user.id if user else None, graph=graph)
            validate_graph(graph, eff_registry)
        except GraphError as e:
            raise HTTPException(400, str(e)) from e
    w = Workflow(
        name=body.name,
        graph_json=graph,
        description=body.description,
        is_template=body.is_template,
        owner_id=user.id if user else None,
    )
    session.add(w)
    session.commit()
    session.refresh(w)
    reload_schedules(session)
    return _to_dict(w)


@router.get("/{workflow_id}")
def get_workflow(
    workflow_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    w = session.get(Workflow, workflow_id)
    if not w:
        raise HTTPException(404, "Workflow not found")
    check_owner(w.owner_id, user)
    return _to_dict(w)


@router.put("/{workflow_id}")
def update_workflow(
    workflow_id: str,
    body: WorkflowUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    w = session.get(Workflow, workflow_id)
    if not w:
        raise HTTPException(404, "Workflow not found")
    check_owner(w.owner_id, user)
    if body.name is not None:
        w.name = body.name
    if body.graph is not None:
        try:
            eff_registry = build_effective_registry(session, owner_id=user.id if user else None, graph=body.graph)
            validate_graph(body.graph, eff_registry)
        except GraphError as e:
            raise HTTPException(400, str(e)) from e
        w.graph_json = body.graph
    if body.description is not None:
        w.description = body.description
    if body.is_template is not None:
        w.is_template = body.is_template
    w.updated_at = datetime.now(timezone.utc)
    session.add(w)
    session.commit()
    session.refresh(w)
    reload_schedules(session)
    return _to_dict(w)


@router.delete("/{workflow_id}")
def delete_workflow(
    workflow_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    w = session.get(Workflow, workflow_id)
    if not w:
        raise HTTPException(404, "Workflow not found")
    check_owner(w.owner_id, user)
    session.delete(w)
    session.commit()
    reload_schedules(session)
    return {"ok": True}


@router.post("/{workflow_id}/run")
async def run_workflow(
    workflow_id: str,
    wait: bool = False,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    w = session.get(Workflow, workflow_id)
    if not w:
        raise HTTPException(404, "Workflow not found")
    check_owner(w.owner_id, user)
    if not w.graph_json or not w.graph_json.get("nodes"):
        raise HTTPException(400, "Workflow has empty graph")

    from app.core.db import get_engine
    from sqlmodel import Session as SMSession

    def session_factory():
        return SMSession(get_engine())

    executor = Executor(session_factory)
    try:
        run_id = await executor.run_workflow(
            workflow_id=workflow_id,
            graph=w.graph_json,
            trigger="manual",
            wait=wait,
            owner_id=user.id if user else w.owner_id,
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"run_id": run_id}
