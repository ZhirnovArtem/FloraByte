from typing import Optional

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.core.auth import get_optional_user
from app.core.db import get_session
from app.core.models import CustomNode, User
from app.nodes.custom_manager import CustomNodeRuntimeAdapter, can_use_custom_node
from app.nodes.registry import list_node_types

router = APIRouter(prefix="/api", tags=["node-types"])


@router.get("/node-types")
def get_node_types(
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(get_optional_user),
):
    """Return palette metadata for React Flow frontend (standard + active accessible custom nodes)."""
    items = list(list_node_types())
    uid = user.id if user else None
    rows = session.exec(select(CustomNode)).all()
    for row in sorted(rows, key=lambda n: n.name.lower()):
        if not can_use_custom_node(row, uid):
            continue
        adapter = CustomNodeRuntimeAdapter(
            node_id=row.id,
            node_type=row.node_type,
            name=row.name,
            description=row.description,
            group=row.group,
            code=row.code,
            inputs_json=row.inputs_json,
            outputs_json=row.outputs_json,
            params_schema_json=row.params_schema_json,
            version=row.version,
            owner_id=row.owner_id,
            visibility=row.visibility,
        )
        items.append(adapter.describe())
    return {"nodes": items}
