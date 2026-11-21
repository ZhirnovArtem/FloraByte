"""Custom Nodes API — create, validate, version, publish, duplicate, test-run, and delete user nodes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.auth import get_current_user
from app.core.db import get_session
from app.core.models import CustomNode, CustomNodeVersion, User
from app.nodes.custom_manager import (
    VALID_STATUSES,
    VALID_VISIBILITIES,
    can_edit_custom_node,
    can_view_custom_node,
    custom_node_to_dict,
    ensure_valid_for_activation,
    generate_unique_node_type,
    normalize_params_schema,
    normalize_ports,
    record_custom_node_version,
)
from app.nodes.custom_sandbox import execute_custom_node_sandboxed, validate_custom_node_code

router = APIRouter(prefix="/api/custom-nodes", tags=["custom-nodes"])

DEFAULT_STARTER_CODE = """async def run(ctx, inputs, params):
    findings = inputs.get("findings", [])
    result = {
        "total": len(findings),
        "critical": sum(
            1 for item in findings
            if isinstance(item, dict) and item.get("severity") == "CRITICAL"
        ),
    }
    return {"result": result}
"""


class PortSpecIn(BaseModel):
    name: str
    kind: str = "Any"


class CustomNodeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=500)
    group: str = Field("custom", max_length=40)
    code: str = Field(DEFAULT_STARTER_CODE)
    inputs: list[PortSpecIn] = Field(default_factory=lambda: [PortSpecIn(name="findings", kind="Findings")])
    outputs: list[PortSpecIn] = Field(default_factory=lambda: [PortSpecIn(name="result", kind="Any")])
    params_schema: dict[str, Any] = Field(default_factory=dict)
    status: str = Field("active")
    visibility: str = Field("private")


class CustomNodeUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    group: str | None = Field(None, max_length=40)
    code: str | None = None
    inputs: list[PortSpecIn] | None = None
    outputs: list[PortSpecIn] | None = None
    params_schema: dict[str, Any] | None = None
    status: str | None = None
    visibility: str | None = None


class ValidateCodeRequest(BaseModel):
    code: str = ""


class TestRunRequest(BaseModel):
    code: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    outputs: list[PortSpecIn] | None = None


@router.get("")
def list_custom_nodes(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    uid = user.id if user else None
    rows = session.exec(select(CustomNode)).all()
    visible = [n for n in rows if can_view_custom_node(n, uid)]
    visible.sort(key=lambda n: n.updated_at or n.created_at, reverse=True)
    return {"custom_nodes": [custom_node_to_dict(n, current_user_id=uid) for n in visible]}


@router.post("/validate")
def validate_code(
    body: ValidateCodeRequest,
    user: Optional[User] = Depends(get_current_user),
):
    res = validate_custom_node_code(body.code)
    return {
        "ok": res.ok,
        "errors": res.errors,
        "warnings": res.warnings,
        "is_async": res.is_async,
    }


@router.post("")
def create_custom_node(
    body: CustomNodeCreate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    status = body.status.strip().lower()
    if status not in VALID_STATUSES:
        raise HTTPException(400, f"Некорректный статус '{body.status}'. Допустимые: draft, active, disabled.")
    visibility = body.visibility.strip().lower()
    if visibility not in VALID_VISIBILITIES:
        raise HTTPException(400, f"Некорректная видимость '{body.visibility}'. Допустимые: private, public.")

    try:
        ensure_valid_for_activation(body.code, status)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    uid = user.id if user else None
    inputs_json = normalize_ports([p.model_dump() for p in body.inputs], default_name="in", default_kind="Any")
    outputs_json = normalize_ports([p.model_dump() for p in body.outputs], default_name="result", default_kind="Any")
    params_schema = normalize_params_schema(body.params_schema)

    node = CustomNode(
        owner_id=uid,
        node_type=generate_unique_node_type(session, body.name),
        name=body.name.strip(),
        description=body.description.strip(),
        group=(body.group or "custom").strip() or "custom",
        code=body.code,
        inputs_json=inputs_json,
        outputs_json=outputs_json,
        params_schema_json=params_schema,
        version=1,
        status=status,
        visibility=visibility,
    )
    session.add(node)
    session.flush()
    record_custom_node_version(session, node)
    session.commit()
    session.refresh(node)
    return custom_node_to_dict(node, current_user_id=uid)


@router.get("/{node_id}")
def get_custom_node(
    node_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    node = session.get(CustomNode, node_id)
    if not node:
        raise HTTPException(404, "Пользовательская нода не найдена")
    uid = user.id if user else None
    if not can_view_custom_node(node, uid):
        raise HTTPException(403, "Нет доступа к чужой приватной ноде")
    versions = session.exec(select(CustomNodeVersion).where(CustomNodeVersion.custom_node_id == node.id)).all()
    return custom_node_to_dict(node, current_user_id=uid, versions=list(versions))


@router.put("/{node_id}")
def update_custom_node(
    node_id: str,
    body: CustomNodeUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    node = session.get(CustomNode, node_id)
    if not node:
        raise HTTPException(404, "Пользовательская нода не найдена")
    uid = user.id if user else None
    if not can_edit_custom_node(node, uid):
        raise HTTPException(403, "Нельзя редактировать чужую ноду без прав владельца")

    next_status = body.status.strip().lower() if body.status is not None else node.status
    if next_status not in VALID_STATUSES:
        raise HTTPException(400, f"Некорректный статус '{next_status}'")

    next_vis = body.visibility.strip().lower() if body.visibility is not None else node.visibility
    if next_vis not in VALID_VISIBILITIES:
        raise HTTPException(400, f"Некорректная видимость '{next_vis}'")

    next_code = body.code if body.code is not None else node.code
    try:
        ensure_valid_for_activation(next_code, next_status)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    logic_changed = False
    if body.name is not None and body.name.strip() != node.name:
        node.name = body.name.strip()
        logic_changed = True
    if body.description is not None:
        node.description = body.description.strip()
    if body.group is not None and body.group.strip():
        node.group = body.group.strip()
    if body.code is not None and body.code != node.code:
        node.code = body.code
        logic_changed = True
    if body.inputs is not None:
        node.inputs_json = normalize_ports([p.model_dump() for p in body.inputs], default_name="in", default_kind="Any")
        logic_changed = True
    if body.outputs is not None:
        node.outputs_json = normalize_ports([p.model_dump() for p in body.outputs], default_name="result", default_kind="Any")
        logic_changed = True
    if body.params_schema is not None:
        node.params_schema_json = normalize_params_schema(body.params_schema)
        logic_changed = True

    node.status = next_status
    node.visibility = next_vis
    node.updated_at = datetime.now(timezone.utc)
    if logic_changed:
        node.version += 1
        record_custom_node_version(session, node)

    session.add(node)
    session.commit()
    session.refresh(node)
    versions = session.exec(select(CustomNodeVersion).where(CustomNodeVersion.custom_node_id == node.id)).all()
    return custom_node_to_dict(node, current_user_id=uid, versions=list(versions))


@router.post("/{node_id}/duplicate")
def duplicate_custom_node(
    node_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    src = session.get(CustomNode, node_id)
    if not src:
        raise HTTPException(404, "Пользовательская нода не найдена")
    uid = user.id if user else None
    if not can_view_custom_node(src, uid):
        raise HTTPException(403, "Нет доступа к чужой приватной ноде")

    copy_name = f"{src.name} (копия)"
    dup = CustomNode(
        owner_id=uid,
        node_type=generate_unique_node_type(session, copy_name),
        name=copy_name,
        description=src.description,
        group=src.group,
        code=src.code,
        inputs_json=list(src.inputs_json or []),
        outputs_json=list(src.outputs_json or []),
        params_schema_json=dict(src.params_schema_json or {}),
        version=1,
        status="draft",
        visibility="private",
    )
    session.add(dup)
    session.flush()
    record_custom_node_version(session, dup)
    session.commit()
    session.refresh(dup)
    return custom_node_to_dict(dup, current_user_id=uid)


@router.post("/{node_id}/test-run")
async def test_run_custom_node(
    node_id: str,
    body: TestRunRequest,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    node = session.get(CustomNode, node_id)
    if not node:
        raise HTTPException(404, "Пользовательская нода не найдена")
    uid = user.id if user else None
    if not can_edit_custom_node(node, uid):
        raise HTTPException(403, "Тестовый запуск черновика доступен только владельцу ноды")

    code = body.code if body.code is not None else node.code
    outputs_spec = (
        normalize_ports([p.model_dump() for p in body.outputs], default_name="result", default_kind="Any")
        if body.outputs is not None
        else node.outputs_json
    )
    try:
        out, logs = await execute_custom_node_sandboxed(
            code=code,
            ctx_info={"run_id": "test-run", "node_id": node.id, "custom_node_version": node.version},
            inputs=body.inputs,
            params=body.params,
            outputs_spec=outputs_spec,
        )
        safe_out = {
            k: ([f.to_submission() if hasattr(f, "to_submission") else f for f in v] if isinstance(v, list) else v)
            for k, v in out.items()
        }
        return {"ok": True, "output": safe_out, "logs": logs}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "logs": []}


@router.delete("/{node_id}")
def delete_custom_node(
    node_id: str,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_current_user),
):
    node = session.get(CustomNode, node_id)
    if not node:
        raise HTTPException(404, "Пользовательская нода не найдена")
    uid = user.id if user else None
    if not can_edit_custom_node(node, uid):
        raise HTTPException(403, "Нельзя удалить чужую ноду")
    versions = session.exec(select(CustomNodeVersion).where(CustomNodeVersion.custom_node_id == node.id)).all()
    for v in versions:
        session.delete(v)
    session.delete(node)
    session.commit()
    return {"ok": True}
