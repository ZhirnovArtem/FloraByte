"""Workflow templates: list from DB (is_template) + seed JSON files, copy to user workflow."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.core.db import get_session
from app.core.models import Workflow

router = APIRouter(prefix="/api/templates", tags=["templates"])

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"


def _seed_from_files(session: Session) -> None:
    """Load templates/*.json into DB if not already present by name."""
    if not TEMPLATES_DIR.exists():
        return
    existing = {w.name for w in session.exec(select(Workflow).where(Workflow.is_template == True)).all()}  # noqa: E712
    for path in TEMPLATES_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = data.get("name") or path.stem
        if name in existing:
            continue
        w = Workflow(
            name=name,
            description=data.get("description") or "",
            graph_json=data.get("graph") or data.get("graph_json") or {},
            is_template=True,
        )
        session.add(w)
        existing.add(name)
    session.commit()


@router.get("")
def list_templates(session: Session = Depends(get_session)):
    _seed_from_files(session)
    items = session.exec(select(Workflow).where(Workflow.is_template == True)).all()  # noqa: E712
    return {
        "templates": [
            {
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "graph_json": w.graph_json,
            }
            for w in items
        ]
    }


@router.post("/{template_id}/copy")
def copy_template(template_id: str, session: Session = Depends(get_session)):
    w = session.get(Workflow, template_id)
    if not w or not w.is_template:
        raise HTTPException(404, "Template not found")
    copy = Workflow(
        id=str(uuid.uuid4()),
        name=f"{w.name} (copy)",
        description=w.description,
        graph_json=w.graph_json,
        is_template=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(copy)
    session.commit()
    session.refresh(copy)
    return {
        "id": copy.id,
        "name": copy.name,
        "graph_json": copy.graph_json,
        "is_template": False,
    }
