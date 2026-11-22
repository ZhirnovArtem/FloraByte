"""Workflow templates: private/public library, publish from workflow, seed JSON files, and copy."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.auth import check_owner, get_current_user
from app.core.db import get_session
from app.core.masking import redact_text
from app.core.models import User, Workflow
from app.core.template_utils import (
    VALID_TEMPLATE_VISIBILITIES,
    can_delete_template,
    can_edit_template,
    can_view_template,
    mask_author_email,
    sanitize_graph_for_template,
)
from app.engine.graph import GraphError, validate_graph
from app.nodes.custom_manager import build_effective_registry

router = APIRouter(prefix="/api/templates", tags=["templates"])

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"


class PublishTemplateRequest(BaseModel):
    workflow_id: str
    name: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    visibility: str = "private"


class UpdateTemplateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    visibility: str | None = None


def _seed_from_files(session: Session) -> None:
    """Load templates/*.json into DB as system public templates if not already present by name."""
    if not TEMPLATES_DIR.exists():
        return
    existing = {
        w.name: w
        for w in session.exec(select(Workflow).where(Workflow.is_template == True)).all()  # noqa: E712
        if w.owner_id is None
    }
    changed = False
    for path in TEMPLATES_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = data.get("name") or path.stem
        graph = data.get("graph") or data.get("graph_json") or {}
        if name in existing:
            current = existing[name]
            if current.graph_json != graph or current.visibility != "public":
                current.graph_json = graph
                current.description = data.get("description") or ""
                current.visibility = "public"
                current.published_at = current.published_at or current.created_at
                session.add(current)
                changed = True
            continue
        now = datetime.now(timezone.utc)
        w = Workflow(
            name=name,
            description=data.get("description") or "",
            graph_json=graph,
            is_template=True,
            visibility="public",
            owner_id=None,
            published_at=now,
        )
        session.add(w)
        existing[name] = w
        changed = True
    if changed:
        session.commit()


def _owner_email_map(session: Session, items: list[Workflow]) -> dict[str, str]:
    owner_ids = {w.owner_id for w in items if w.owner_id}
    if not owner_ids:
        return {}
    users = session.exec(select(User).where(User.id.in_(owner_ids))).all()
    return {u.id: mask_author_email(u.email) for u in users}


def _template_dict(
    w: Workflow,
    *,
    current_user_id: str | None,
    owner_emails: dict[str, str],
) -> dict:
    is_system = w.owner_id is None
    vis = "public" if is_system else (w.visibility or "private")
    nodes = (w.graph_json or {}).get("nodes") or []
    return {
        "id": w.id,
        "name": w.name,
        "description": w.description,
        "visibility": vis,
        "owner_id": w.owner_id,
        "owner_email": "FloraByte System" if is_system else owner_emails.get(w.owner_id or "", ""),
        "is_system": is_system,
        "is_owner": bool(current_user_id and w.owner_id == current_user_id),
        "published_at": (w.published_at or w.created_at).isoformat() if (w.published_at or w.created_at) else None,
        "nodes_count": len(nodes),
        "source_template_id": w.source_template_id,
        "graph_json": w.graph_json,
    }


@router.get("")
def list_templates(
    scope: Literal["all", "mine", "public"] = Query("all"),
    q: str = Query(""),
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    _seed_from_files(session)
    uid = user.id if user else None
    all_rows = session.exec(select(Workflow).where(Workflow.is_template == True)).all()  # noqa: E712

    visible = [w for w in all_rows if can_view_template(w, uid)]
    if scope == "mine":
        visible = [w for w in visible if uid is not None and w.owner_id == uid]
    elif scope == "public":
        visible = [w for w in visible if w.owner_id is None or (w.visibility or "private") == "public"]

    needle = q.strip().lower()
    if needle:
        visible = [
            w
            for w in visible
            if needle in (w.name or "").lower() or needle in (w.description or "").lower()
        ]

    visible.sort(
        key=lambda w: (
            0 if (uid and w.owner_id == uid) else (1 if w.owner_id is None else 2),
            w.name.lower(),
        )
    )
    owner_emails = _owner_email_map(session, visible)
    return {
        "templates": [
            _template_dict(w, current_user_id=uid, owner_emails=owner_emails)
            for w in visible
        ]
    }


@router.get("/{template_id}")
def get_template(
    template_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    _seed_from_files(session)
    uid = user.id if user else None
    w = session.get(Workflow, template_id)
    if not w or not can_view_template(w, uid):
        raise HTTPException(404, "Template not found")
    owner_emails = _owner_email_map(session, [w])
    return _template_dict(w, current_user_id=uid, owner_emails=owner_emails)


@router.post("/publish")
def publish_template(
    body: PublishTemplateRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    vis = (body.visibility or "private").strip().lower()
    if vis not in VALID_TEMPLATE_VISIBILITIES:
        raise HTTPException(400, f"Недопустимая видимость шаблона: {vis!r} (допустимо: private, public)")

    src = session.get(Workflow, body.workflow_id)
    if not src:
        raise HTTPException(404, "Workflow not found")
    check_owner(src.owner_id, user)

    uid = user.id if user else None
    clean_graph = sanitize_graph_for_template(
        src.graph_json or {},
        strip_recipient_email=(vis == "public"),
    )
    try:
        eff_registry = build_effective_registry(session, owner_id=uid, graph=clean_graph)
        validate_graph(clean_graph, eff_registry)
    except GraphError as e:
        raise HTTPException(400, str(e)) from e

    tpl_name = (body.name if body.name is not None else src.name).strip()
    if not tpl_name:
        raise HTTPException(400, "Название шаблона не может быть пустым")
    tpl_desc = redact_text((body.description if body.description is not None else src.description).strip())

    now = datetime.now(timezone.utc)
    tpl = Workflow(
        id=str(uuid.uuid4()),
        name=tpl_name,
        description=tpl_desc,
        graph_json=clean_graph,
        is_template=True,
        visibility=vis,
        owner_id=uid,
        published_at=now,
        source_template_id=src.id,
        created_at=now,
        updated_at=now,
    )
    session.add(tpl)
    session.commit()
    session.refresh(tpl)
    owner_emails = _owner_email_map(session, [tpl])
    return _template_dict(tpl, current_user_id=uid, owner_emails=owner_emails)


@router.patch("/{template_id}")
def update_template(
    template_id: str,
    body: UpdateTemplateRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    uid = user.id if user else None
    w = session.get(Workflow, template_id)
    if not w or not w.is_template:
        raise HTTPException(404, "Template not found")
    if w.owner_id is None:
        raise HTTPException(403, "Системный шаблон нельзя изменять")
    if not can_view_template(w, uid):
        raise HTTPException(404, "Template not found")
    if not can_edit_template(w, uid):
        raise HTTPException(403, "Нет прав на редактирование этого шаблона")

    if body.visibility is not None:
        vis = body.visibility.strip().lower()
        if vis not in VALID_TEMPLATE_VISIBILITIES:
            raise HTTPException(400, f"Недопустимая видимость шаблона: {vis!r}")
        w.visibility = vis
        w.graph_json = sanitize_graph_for_template(
            w.graph_json or {},
            strip_recipient_email=(vis == "public"),
        )
        if vis == "public" and not w.published_at:
            w.published_at = datetime.now(timezone.utc)

    if body.name is not None:
        cleaned_name = body.name.strip()
        if not cleaned_name:
            raise HTTPException(400, "Название шаблона не может быть пустым")
        w.name = cleaned_name

    if body.description is not None:
        w.description = redact_text(body.description.strip())

    w.updated_at = datetime.now(timezone.utc)
    session.add(w)
    session.commit()
    session.refresh(w)
    owner_emails = _owner_email_map(session, [w])
    return _template_dict(w, current_user_id=uid, owner_emails=owner_emails)


@router.delete("/{template_id}")
def delete_template(
    template_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    uid = user.id if user else None
    w = session.get(Workflow, template_id)
    if not w or not w.is_template:
        raise HTTPException(404, "Template not found")
    if w.owner_id is None:
        raise HTTPException(403, "Системный шаблон нельзя удалить")
    if not can_view_template(w, uid):
        raise HTTPException(404, "Template not found")
    if not can_delete_template(w, uid):
        raise HTTPException(403, "Нет прав на удаление этого шаблона")

    session.delete(w)
    session.commit()
    return {"ok": True}


@router.post("/{template_id}/copy")
def copy_template(
    template_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    _seed_from_files(session)
    uid = user.id if user else None
    w = session.get(Workflow, template_id)
    if not w or not can_view_template(w, uid):
        raise HTTPException(404, "Template not found")

    clean_graph = sanitize_graph_for_template(w.graph_json or {})
    copy = Workflow(
        id=str(uuid.uuid4()),
        name=f"{w.name} (copy)",
        description=redact_text(w.description or ""),
        graph_json=clean_graph,
        is_template=False,
        visibility="private",
        source_template_id=w.id,
        owner_id=uid,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(copy)
    session.commit()
    session.refresh(copy)
    return {
        "id": copy.id,
        "name": copy.name,
        "description": copy.description,
        "graph_json": copy.graph_json,
        "is_template": False,
        "source_template_id": copy.source_template_id,
    }
