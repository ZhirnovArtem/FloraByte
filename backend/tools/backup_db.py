"""Portable database backup & restore CLI for FloraByte PostgreSQL / SQLite deployments.

Usage:
    python backend/tools/backup_db.py dump --database-url "$DATABASE_URL" --out backup.json
    python backend/tools/backup_db.py restore --database-url "$DATABASE_URL" --in backup.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from sqlmodel import Session, SQLModel, create_engine, select

from app.core.db import _ensure_columns, _normalized_db_url
from app.core.models import (
    Credential,
    CustomNode,
    CustomNodeVersion,
    IntegrationSetting,
    NodeRun,
    Run,
    User,
    Workflow,
)


def _serialize_row(obj: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in obj.model_dump().items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def _parse_dt(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def dump_database(database_url: str, out_path: Path) -> dict[str, int]:
    norm_url = _normalized_db_url(database_url)
    connect_args = {"check_same_thread": False} if norm_url.startswith("sqlite") else {}
    engine = create_engine(norm_url, connect_args=connect_args, pool_pre_ping=True)
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "users": [_serialize_row(r) for r in session.exec(select(User)).all()],
            "workflows": [_serialize_row(r) for r in session.exec(select(Workflow)).all()],
            "runs": [_serialize_row(r) for r in session.exec(select(Run)).all()],
            "node_runs": [_serialize_row(r) for r in session.exec(select(NodeRun)).all()],
            "credentials": [_serialize_row(r) for r in session.exec(select(Credential)).all()],
            "integration_settings": [_serialize_row(r) for r in session.exec(select(IntegrationSetting)).all()],
            "custom_nodes": [_serialize_row(r) for r in session.exec(select(CustomNode)).all()],
            "custom_node_versions": [_serialize_row(r) for r in session.exec(select(CustomNodeVersion)).all()],
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        out_path.chmod(0o600)
    except OSError:
        pass
    return {k: len(v) for k, v in payload.items() if isinstance(v, list)}


def restore_database(database_url: str, in_path: Path) -> dict[str, int]:
    norm_url = _normalized_db_url(database_url)
    connect_args = {"check_same_thread": False} if norm_url.startswith("sqlite") else {}
    engine = create_engine(norm_url, connect_args=connect_args, pool_pre_ping=True)
    SQLModel.metadata.create_all(engine)
    _ensure_columns(engine)

    data = json.loads(in_path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}

    with Session(engine) as session:
        existing_emails = {u.email.lower() for u in session.exec(select(User)).all()}
        existing_user_ids = {u.id for u in session.exec(select(User)).all()}
        n_users = 0
        for row in data.get("users", []):
            email = str(row["email"]).strip().lower()
            if email in existing_emails or row["id"] in existing_user_ids:
                continue
            session.add(
                User(
                    id=row["id"],
                    email=email,
                    password_hash=row["password_hash"],
                    is_active=bool(row.get("is_active", True)),
                    created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                )
            )
            existing_emails.add(email)
            existing_user_ids.add(row["id"])
            n_users += 1
        counts["users"] = n_users

        existing_wfs = {w.id for w in session.exec(select(Workflow)).all()}
        n_wfs = 0
        for row in data.get("workflows", []):
            if row["id"] in existing_wfs:
                continue
            session.add(
                Workflow(
                    id=row["id"],
                    name=row["name"],
                    graph_json=row["graph_json"],
                    is_template=bool(row.get("is_template", False)),
                    visibility=str(row.get("visibility") or ("public" if row.get("is_template") and not row.get("owner_id") else "private")),
                    published_at=_parse_dt(row.get("published_at")),
                    source_template_id=row.get("source_template_id"),
                    description=row.get("description", ""),
                    owner_id=row.get("owner_id"),
                    created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                    updated_at=_parse_dt(row.get("updated_at")) or datetime.now(timezone.utc),
                )
            )
            existing_wfs.add(row["id"])
            n_wfs += 1
        counts["workflows"] = n_wfs

        existing_runs = {r.id for r in session.exec(select(Run)).all()}
        n_runs = 0
        for row in data.get("runs", []):
            if row["id"] in existing_runs:
                continue
            session.add(
                Run(
                    id=row["id"],
                    workflow_id=row["workflow_id"],
                    owner_id=row.get("owner_id"),
                    status=row["status"],
                    trigger=row.get("trigger", "manual"),
                    started_at=_parse_dt(row.get("started_at")),
                    finished_at=_parse_dt(row.get("finished_at")),
                    summary_json=row.get("summary_json"),
                    ai_report_json=row.get("ai_report_json"),
                )
            )
            existing_runs.add(row["id"])
            n_runs += 1
        counts["runs"] = n_runs

        existing_nrs = {r.id for r in session.exec(select(NodeRun)).all()}
        n_nrs = 0
        for row in data.get("node_runs", []):
            if row["id"] in existing_nrs:
                continue
            session.add(
                NodeRun(
                    id=row["id"],
                    run_id=row["run_id"],
                    node_id=row["node_id"],
                    status=row["status"],
                    started_at=_parse_dt(row.get("started_at")),
                    finished_at=_parse_dt(row.get("finished_at")),
                    output_preview_json=row.get("output_preview_json"),
                    error=row.get("error"),
                )
            )
            existing_nrs.add(row["id"])
            n_nrs += 1
        counts["node_runs"] = n_nrs

        existing_creds = {c.id for c in session.exec(select(Credential)).all()}
        n_creds = 0
        for row in data.get("credentials", []):
            if row["id"] in existing_creds:
                continue
            session.add(
                Credential(
                    id=row["id"],
                    name=row["name"],
                    kind=row["kind"],
                    encrypted_value=row["encrypted_value"],
                    owner_id=row.get("owner_id"),
                    created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                )
            )
            existing_creds.add(row["id"])
            n_creds += 1
        counts["credentials"] = n_creds

        existing_integs = {i.kind for i in session.exec(select(IntegrationSetting)).all()}
        n_integs = 0
        for row in data.get("integration_settings", []):
            if row["kind"] in existing_integs:
                continue
            session.add(
                IntegrationSetting(
                    kind=row["kind"],
                    enabled=bool(row.get("enabled", True)),
                    auto_send=bool(row.get("auto_send", True)),
                    config_json=row.get("config_json") or {},
                    encrypted_secret=row.get("encrypted_secret", ""),
                    updated_at=_parse_dt(row.get("updated_at")) or datetime.now(timezone.utc),
                )
            )
            existing_integs.add(row["kind"])
            n_integs += 1
        counts["integration_settings"] = n_integs

        existing_cns = {c.id for c in session.exec(select(CustomNode)).all()}
        n_cns = 0
        for row in data.get("custom_nodes", []):
            if row["id"] in existing_cns:
                continue
            session.add(
                CustomNode(
                    id=row["id"],
                    owner_id=row.get("owner_id"),
                    node_type=row["node_type"],
                    name=row["name"],
                    description=row.get("description", ""),
                    group=row.get("group", "custom"),
                    code=row["code"],
                    inputs_json=row.get("inputs_json") or [],
                    outputs_json=row.get("outputs_json") or [],
                    params_schema_json=row.get("params_schema_json") or {},
                    version=int(row.get("version") or 1),
                    status=row.get("status", "active"),
                    visibility=row.get("visibility", "private"),
                    created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                    updated_at=_parse_dt(row.get("updated_at")) or datetime.now(timezone.utc),
                )
            )
            existing_cns.add(row["id"])
            n_cns += 1
        counts["custom_nodes"] = n_cns

        existing_cnvs = {v.id for v in session.exec(select(CustomNodeVersion)).all()}
        n_cnvs = 0
        for row in data.get("custom_node_versions", []):
            if row["id"] in existing_cnvs:
                continue
            session.add(
                CustomNodeVersion(
                    id=row["id"],
                    custom_node_id=row["custom_node_id"],
                    version=int(row.get("version") or 1),
                    name=row["name"],
                    description=row.get("description", ""),
                    group=row.get("group", "custom"),
                    code=row["code"],
                    inputs_json=row.get("inputs_json") or [],
                    outputs_json=row.get("outputs_json") or [],
                    params_schema_json=row.get("params_schema_json") or {},
                    created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                )
            )
            existing_cnvs.add(row["id"])
            n_cnvs += 1
        counts["custom_node_versions"] = n_cnvs

        session.commit()
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump or restore FloraByte DB as portable JSON.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dump = sub.add_parser("dump")
    p_dump.add_argument("--database-url", default=os.environ.get("DATABASE_URL", "").strip())
    p_dump.add_argument("--out", required=True)

    p_rest = sub.add_parser("restore")
    p_rest.add_argument("--database-url", default=os.environ.get("DATABASE_URL", "").strip())
    p_rest.add_argument("--in", dest="in_file", required=True)

    args = parser.parse_args()
    if not args.database_url:
        print("Error: set --database-url or DATABASE_URL", file=sys.stderr)
        return 2

    if args.cmd == "dump":
        stats = dump_database(args.database_url, Path(args.out))
        print(json.dumps({"dumped": stats, "out": args.out}, indent=2))
    else:
        stats = restore_database(args.database_url, Path(args.in_file))
        print(json.dumps({"restored": stats, "in": args.in_file}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
