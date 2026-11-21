"""Custom Node Manager — DB-backed user nodes, versioning, access control, and registry integration."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, create_model
from sqlmodel import Session, select

from app.core.models import CustomNode, CustomNodeVersion
from app.nodes.base import NodeContext, Port
from app.nodes.custom_sandbox import execute_custom_node_sandboxed, validate_custom_node_code
from app.nodes.registry import NODE_REGISTRY

VALID_PORT_KINDS = frozenset({"Workspace", "Findings", "Report", "Any", "Boolean"})
VALID_STATUSES = frozenset({"draft", "active", "disabled"})
VALID_VISIBILITIES = frozenset({"private", "public"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _slugify(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", (name or "").strip().lower()).strip("_")
    return cleaned[:28] or "node"


def normalize_ports(ports: list[dict[str, Any]] | None, *, default_name: str, default_kind: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for p in ports or []:
        if not isinstance(p, dict):
            continue
        pname = re.sub(r"[^a-zA-Z0-9_]", "_", str(p.get("name") or "").strip())
        if not pname or pname in seen:
            continue
        pkind = str(p.get("kind") or "Any").strip()
        if pkind not in VALID_PORT_KINDS:
            pkind = "Any"
        seen.add(pname)
        out.append({"name": pname, "kind": pkind})
    if not out:
        out.append({"name": default_name, "kind": default_kind})
    return out


def normalize_params_schema(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"type": "object", "properties": {}}
    props = raw.get("properties")
    if not isinstance(props, dict):
        props = {}
    cleaned_props: dict[str, Any] = {}
    for k, v in props.items():
        if not isinstance(v, dict):
            continue
        key = re.sub(r"[^a-zA-Z0-9_]", "_", str(k).strip())
        if not key:
            continue
        ptype = str(v.get("type") or "string").lower()
        if ptype not in ("string", "integer", "number", "boolean"):
            ptype = "string"
        entry: dict[str, Any] = {"type": ptype}
        if "default" in v:
            entry["default"] = v["default"]
        if v.get("description"):
            entry["description"] = str(v["description"])[:200]
        cleaned_props[key] = entry
    return {"type": "object", "properties": cleaned_props}


def build_params_model(node_id_tag: str, schema: dict[str, Any]) -> type[BaseModel]:
    props = (schema or {}).get("properties") or {}
    fields: dict[str, Any] = {}
    for key, spec in props.items():
        if not isinstance(spec, dict):
            continue
        ptype = spec.get("type", "string")
        py_t: Any = str
        default_val: Any = ""
        if ptype == "integer":
            py_t = int
            default_val = 0
        elif ptype == "number":
            py_t = float
            default_val = 0.0
        elif ptype == "boolean":
            py_t = bool
            default_val = False
        if "default" in spec:
            default_val = spec["default"]
        fields[key] = (py_t, default_val)

    class _BaseCustomParams(BaseModel):
        model_config = ConfigDict(extra="allow")

    return create_model(f"CustomParams_{node_id_tag}", __base__=_BaseCustomParams, **fields)


class CustomNodeRuntimeAdapter:
    """Adapter exposing a DB CustomNode with the same contract as BaseNode subclasses."""

    def __init__(
        self,
        *,
        node_id: str,
        node_type: str,
        name: str,
        description: str,
        group: str,
        code: str,
        inputs_json: list[dict[str, Any]],
        outputs_json: list[dict[str, Any]],
        params_schema_json: dict[str, Any],
        version: int,
        owner_id: str | None,
        visibility: str,
    ) -> None:
        self.custom_node_id = node_id
        self.type = node_type
        self.label = name
        self.description = description
        self.group = group or "custom"
        self.code = code
        self.inputs = [Port(name=p["name"], kind=p["kind"]) for p in (inputs_json or [{"name": "in", "kind": "Any"}])]
        self.outputs = [Port(name=p["name"], kind=p["kind"]) for p in (outputs_json or [{"name": "result", "kind": "Any"}])]
        self.outputs_json = outputs_json or [{"name": "result", "kind": "Any"}]
        self.params_schema_json = normalize_params_schema(params_schema_json)
        self.Params = build_params_model(node_id.replace("-", "_"), self.params_schema_json)
        self.version = version
        self.owner_id = owner_id
        self.visibility = visibility
        self.continue_downstream_on_error = False

    def __call__(self) -> "CustomNodeRuntimeAdapter":
        return self

    def describe(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "label": self.label,
            "description": self.description,
            "group": self.group,
            "inputs": [{"name": p.name, "kind": p.kind} for p in self.inputs],
            "outputs": [{"name": p.name, "kind": p.kind} for p in self.outputs],
            "params_schema": self.params_schema_json,
            "is_custom": True,
            "custom_node_id": self.custom_node_id,
            "version": self.version,
            "visibility": self.visibility,
        }

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        raw_params = params.model_dump() if hasattr(params, "model_dump") else {}
        ctx_info = {
            "run_id": ctx.run_id,
            "node_id": ctx.node_id,
            "custom_node_id": self.custom_node_id,
            "custom_node_version": self.version,
        }
        result, _logs = await execute_custom_node_sandboxed(
            code=self.code,
            ctx_info=ctx_info,
            inputs=inputs,
            params=raw_params,
            outputs_spec=self.outputs_json,
        )
        return result


def can_view_custom_node(node: CustomNode, user_id: str | None) -> bool:
    if user_id is None:
        return True
    if node.owner_id == user_id:
        return True
    return node.visibility == "public" and node.status == "active"


def can_use_custom_node(node: CustomNode, user_id: str | None) -> bool:
    if node.status != "active":
        return False
    return can_view_custom_node(node, user_id)


def can_edit_custom_node(node: CustomNode, user_id: str | None) -> bool:
    if user_id is None:
        return True
    return node.owner_id == user_id


def build_effective_registry(
    session: Session | None,
    *,
    owner_id: str | None = None,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine standard NODE_REGISTRY with accessible active CustomNode records (and pinned versions)."""
    registry: dict[str, Any] = dict(NODE_REGISTRY)
    if session is None:
        return registry

    pinned_versions: dict[str, int] = {}
    if isinstance(graph, dict):
        for n in graph.get("nodes") or []:
            if not isinstance(n, dict):
                continue
            nt = str(n.get("type") or "")
            if not nt.startswith("custom."):
                continue
            p = n.get("params") or {}
            if isinstance(p, dict) and isinstance(p.get("_custom_version"), int):
                pinned_versions[nt] = int(p["_custom_version"])

    rows = session.exec(select(CustomNode)).all()
    for row in rows:
        if not can_use_custom_node(row, owner_id):
            continue
        use_ver = row.version
        name = row.name
        description = row.description
        group = row.group
        code = row.code
        inputs_json = row.inputs_json
        outputs_json = row.outputs_json
        params_schema_json = row.params_schema_json

        pinned = pinned_versions.get(row.node_type)
        if pinned is not None and pinned != row.version:
            ver_row = session.exec(
                select(CustomNodeVersion).where(
                    CustomNodeVersion.custom_node_id == row.id,
                    CustomNodeVersion.version == pinned,
                )
            ).first()
            if ver_row:
                use_ver = ver_row.version
                name = ver_row.name
                description = ver_row.description
                group = ver_row.group
                code = ver_row.code
                inputs_json = ver_row.inputs_json
                outputs_json = ver_row.outputs_json
                params_schema_json = ver_row.params_schema_json

        registry[row.node_type] = CustomNodeRuntimeAdapter(
            node_id=row.id,
            node_type=row.node_type,
            name=name,
            description=description,
            group=group,
            code=code,
            inputs_json=inputs_json,
            outputs_json=outputs_json,
            params_schema_json=params_schema_json,
            version=use_ver,
            owner_id=row.owner_id,
            visibility=row.visibility,
        )
    return registry


def custom_node_to_dict(
    node: CustomNode,
    *,
    current_user_id: str | None = None,
    versions: list[CustomNodeVersion] | None = None,
) -> dict[str, Any]:
    out = {
        "id": node.id,
        "node_type": node.node_type,
        "owner_id": node.owner_id,
        "is_owner": (current_user_id is None or node.owner_id == current_user_id),
        "name": node.name,
        "description": node.description,
        "group": node.group,
        "code": node.code,
        "inputs": node.inputs_json,
        "outputs": node.outputs_json,
        "params_schema": node.params_schema_json,
        "version": node.version,
        "status": node.status,
        "visibility": node.visibility,
        "created_at": node.created_at.isoformat() if node.created_at else None,
        "updated_at": node.updated_at.isoformat() if node.updated_at else None,
    }
    if versions is not None:
        out["versions"] = [
            {
                "id": v.id,
                "version": v.version,
                "name": v.name,
                "description": v.description,
                "group": v.group,
                "code": v.code,
                "inputs": v.inputs_json,
                "outputs": v.outputs_json,
                "params_schema": v.params_schema_json,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in sorted(versions, key=lambda item: item.version, reverse=True)
        ]
    return out


def generate_unique_node_type(session: Session, name: str) -> str:
    slug = _slugify(name)
    for _ in range(10):
        candidate = f"custom.{slug}_{uuid.uuid4().hex[:6]}"
        existing = session.exec(select(CustomNode).where(CustomNode.node_type == candidate)).first()
        if not existing:
            return candidate
    return f"custom.node_{uuid.uuid4().hex[:10]}"


def record_custom_node_version(session: Session, node: CustomNode) -> CustomNodeVersion:
    ver = CustomNodeVersion(
        custom_node_id=node.id,
        version=node.version,
        name=node.name,
        description=node.description,
        group=node.group,
        code=node.code,
        inputs_json=list(node.inputs_json or []),
        outputs_json=list(node.outputs_json or []),
        params_schema_json=dict(node.params_schema_json or {}),
    )
    session.add(ver)
    return ver


def ensure_valid_for_activation(code: str, status: str) -> None:
    if status == "active":
        res = validate_custom_node_code(code)
        if not res.ok:
            raise ValueError("; ".join(res.errors))
