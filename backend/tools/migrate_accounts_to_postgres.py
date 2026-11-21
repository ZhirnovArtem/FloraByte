"""Migrate existing accounts (and optional workspace data) from legacy SQLite/JSON into PostgreSQL.

Usage:
    python backend/tools/migrate_accounts_to_postgres.py --target "$DATABASE_URL"
    python backend/tools/migrate_accounts_to_postgres.py --target "$DATABASE_URL" --source backend/ai_security_workflow.db --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from sqlmodel import Session, SQLModel, create_engine, select

from app.core.accounts_db import extract_legacy_accounts_from_sqlite
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
from app.core.user_store import extract_legacy_accounts_from_json


def _parse_dt(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str) and val.strip():
        s = val.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _parse_json(val: Any, default: Any) -> Any:
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except ValueError:
            return default
    return default


def discover_legacy_sources(repo_root: Path) -> list[Path]:
    candidates = [
        repo_root / "ai_security_workflow.db",
        repo_root / "backend" / "ai_security_workflow.db",
        repo_root / "database.db",
        repo_root / "backend" / "database.db",
        repo_root / "backend" / "data" / "users.json",
    ]
    return [p for p in candidates if p.exists()]


def migrate_sources(
    *,
    target_url: str,
    sources: list[Path],
    dry_run: bool = False,
    accounts_only: bool = False,
) -> dict[str, int]:
    norm_url = _normalized_db_url(target_url)
    connect_args = {"check_same_thread": False} if norm_url.startswith("sqlite") else {}
    engine = create_engine(norm_url, connect_args=connect_args, pool_pre_ping=True)

    SQLModel.metadata.create_all(engine)
    _ensure_columns(engine)

    stats = {
        "accounts_discovered": 0,
        "accounts_inserted": 0,
        "accounts_skipped": 0,
        "workflows_inserted": 0,
        "runs_inserted": 0,
        "node_runs_inserted": 0,
        "credentials_inserted": 0,
        "integrations_inserted": 0,
        "custom_nodes_inserted": 0,
        "custom_node_versions_inserted": 0,
    }

    extracted_accounts: dict[str, dict[str, Any]] = {}
    sqlite_sources: list[Path] = []
    for src in sources:
        if src.suffix == ".json":
            for rec in extract_legacy_accounts_from_json(src):
                extracted_accounts.setdefault(rec["email"], rec)
        elif src.exists():
            sqlite_sources.append(src)
            for rec in extract_legacy_accounts_from_sqlite(src):
                extracted_accounts.setdefault(rec["email"], rec)

    stats["accounts_discovered"] = len(extracted_accounts)

    with Session(engine) as session:
        existing_emails = {
            u.email.strip().lower(): u for u in session.exec(select(User)).all()
        }
        existing_ids = {u.id for u in existing_emails.values()}

        for email, rec in extracted_accounts.items():
            if email in existing_emails or (rec["id"] and rec["id"] in existing_ids):
                stats["accounts_skipped"] += 1
                continue
            user = User(
                email=email,
                password_hash=rec["password_hash"],
                is_active=bool(rec.get("is_active", True)),
                created_at=_parse_dt(rec.get("created_at")),
            )
            if rec.get("id"):
                user.id = str(rec["id"])
            if not dry_run:
                session.add(user)
            existing_emails[email] = user
            existing_ids.add(user.id)
            stats["accounts_inserted"] += 1

        if not accounts_only:
            existing_wf_ids = {w.id for w in session.exec(select(Workflow)).all()}
            existing_run_ids = {r.id for r in session.exec(select(Run)).all()}
            existing_nr_ids = {nr.id for nr in session.exec(select(NodeRun)).all()}
            existing_cred_ids = {c.id for c in session.exec(select(Credential)).all()}
            existing_integ_kinds = {i.kind for i in session.exec(select(IntegrationSetting)).all()}
            existing_cn_ids = {c.id for c in session.exec(select(CustomNode)).all()}
            existing_cn_types = {c.node_type for c in session.exec(select(CustomNode)).all()}
            existing_cnv_ids = {v.id for v in session.exec(select(CustomNodeVersion)).all()}

            for db_path in sqlite_sources:
                with sqlite3.connect(str(db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    tables = {
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    }

                    if "workflows" in tables:
                        for row in conn.execute("SELECT * FROM workflows").fetchall():
                            d = dict(row)
                            wid = str(d["id"])
                            if wid in existing_wf_ids:
                                continue
                            wf = Workflow(
                                id=wid,
                                name=str(d.get("name") or "Workflow"),
                                graph_json=_parse_json(d.get("graph_json"), {}),
                                schedule_cron=d.get("schedule_cron"),
                                is_template=bool(d.get("is_template", False)),
                                description=str(d.get("description") or ""),
                                owner_id=d.get("owner_id"),
                                created_at=_parse_dt(d.get("created_at")),
                                updated_at=_parse_dt(d.get("updated_at")),
                            )
                            if not dry_run:
                                session.add(wf)
                            existing_wf_ids.add(wid)
                            stats["workflows_inserted"] += 1

                    if "runs" in tables:
                        for row in conn.execute("SELECT * FROM runs").fetchall():
                            d = dict(row)
                            rid = str(d["id"])
                            if rid in existing_run_ids:
                                continue
                            run = Run(
                                id=rid,
                                workflow_id=str(d["workflow_id"]),
                                owner_id=d.get("owner_id"),
                                status=str(d.get("status") or "pending"),
                                trigger=str(d.get("trigger") or "manual"),
                                started_at=_parse_dt(d["started_at"]) if d.get("started_at") else None,
                                finished_at=_parse_dt(d["finished_at"]) if d.get("finished_at") else None,
                                summary_json=_parse_json(d.get("summary_json"), None),
                                ai_report_json=_parse_json(d.get("ai_report_json"), None),
                            )
                            if not dry_run:
                                session.add(run)
                            existing_run_ids.add(rid)
                            stats["runs_inserted"] += 1

                    if "node_runs" in tables:
                        for row in conn.execute("SELECT * FROM node_runs").fetchall():
                            d = dict(row)
                            nrid = str(d["id"])
                            if nrid in existing_nr_ids:
                                continue
                            nr = NodeRun(
                                id=nrid,
                                run_id=str(d["run_id"]),
                                node_id=str(d["node_id"]),
                                status=str(d.get("status") or "pending"),
                                started_at=_parse_dt(d["started_at"]) if d.get("started_at") else None,
                                finished_at=_parse_dt(d["finished_at"]) if d.get("finished_at") else None,
                                output_preview_json=_parse_json(d.get("output_preview_json"), None),
                                error=d.get("error"),
                            )
                            if not dry_run:
                                session.add(nr)
                            existing_nr_ids.add(nrid)
                            stats["node_runs_inserted"] += 1

                    if "credentials" in tables:
                        for row in conn.execute("SELECT * FROM credentials").fetchall():
                            d = dict(row)
                            cid = str(d["id"])
                            if cid in existing_cred_ids:
                                continue
                            cred = Credential(
                                id=cid,
                                name=str(d["name"]),
                                kind=str(d["kind"]),
                                encrypted_value=str(d["encrypted_value"]),
                                owner_id=d.get("owner_id"),
                                created_at=_parse_dt(d.get("created_at")),
                            )
                            if not dry_run:
                                session.add(cred)
                            existing_cred_ids.add(cid)
                            stats["credentials_inserted"] += 1

                    if "integration_settings" in tables:
                        for row in conn.execute("SELECT * FROM integration_settings").fetchall():
                            d = dict(row)
                            kind = str(d["kind"])
                            if kind in existing_integ_kinds:
                                continue
                            integ = IntegrationSetting(
                                kind=kind,
                                enabled=bool(d.get("enabled", True)),
                                auto_send=bool(d.get("auto_send", True)),
                                config_json=_parse_json(d.get("config_json"), {}),
                                encrypted_secret=str(d.get("encrypted_secret") or ""),
                                updated_at=_parse_dt(d.get("updated_at")),
                            )
                            if not dry_run:
                                session.add(integ)
                            existing_integ_kinds.add(kind)
                            stats["integrations_inserted"] += 1

                    if "custom_nodes" in tables:
                        for row in conn.execute("SELECT * FROM custom_nodes").fetchall():
                            d = dict(row)
                            cnid = str(d["id"])
                            cntype = str(d["node_type"])
                            if cnid in existing_cn_ids or cntype in existing_cn_types:
                                continue
                            cn = CustomNode(
                                id=cnid,
                                owner_id=d.get("owner_id"),
                                node_type=cntype,
                                name=str(d["name"]),
                                description=str(d.get("description") or ""),
                                group=str(d.get("group") or "custom"),
                                code=str(d["code"]),
                                inputs_json=_parse_json(d.get("inputs_json"), []),
                                outputs_json=_parse_json(d.get("outputs_json"), []),
                                params_schema_json=_parse_json(d.get("params_schema_json"), {}),
                                version=int(d.get("version") or 1),
                                status=str(d.get("status") or "active"),
                                visibility=str(d.get("visibility") or "private"),
                                created_at=_parse_dt(d.get("created_at")),
                                updated_at=_parse_dt(d.get("updated_at")),
                            )
                            if not dry_run:
                                session.add(cn)
                            existing_cn_ids.add(cnid)
                            existing_cn_types.add(cntype)
                            stats["custom_nodes_inserted"] += 1

                    if "custom_node_versions" in tables:
                        for row in conn.execute("SELECT * FROM custom_node_versions").fetchall():
                            d = dict(row)
                            cnvid = str(d["id"])
                            if cnvid in existing_cnv_ids:
                                continue
                            cnv = CustomNodeVersion(
                                id=cnvid,
                                custom_node_id=str(d["custom_node_id"]),
                                version=int(d.get("version") or 1),
                                name=str(d["name"]),
                                description=str(d.get("description") or ""),
                                group=str(d.get("group") or "custom"),
                                code=str(d["code"]),
                                inputs_json=_parse_json(d.get("inputs_json"), []),
                                outputs_json=_parse_json(d.get("outputs_json"), []),
                                params_schema_json=_parse_json(d.get("params_schema_json"), {}),
                                created_at=_parse_dt(d.get("created_at")),
                            )
                            if not dry_run:
                                session.add(cnv)
                            existing_cnv_ids.add(cnvid)
                            stats["custom_node_versions_inserted"] += 1

        if not dry_run:
            session.commit()

    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate legacy SQLite/JSON accounts into PostgreSQL.")
    parser.add_argument(
        "--target",
        default=os.environ.get("DATABASE_URL", "").strip(),
        help="Target database URL (defaults to DATABASE_URL env var)",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Legacy SQLite/JSON path (can be passed multiple times; auto-discovers if omitted)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Inspect without writing changes")
    parser.add_argument("--accounts-only", action="store_true", help="Migrate only accounts table")
    args = parser.parse_args()

    if not args.target:
        print("Error: specify --target or set DATABASE_URL", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[2]
    sources = [Path(s) for s in args.source] if args.source else discover_legacy_sources(repo_root)
    if not sources:
        print("No legacy SQLite/JSON files found.")
        return 0

    stats = migrate_sources(
        target_url=args.target,
        sources=sources,
        dry_run=args.dry_run,
        accounts_only=args.accounts_only,
    )
    print(json.dumps({"dry_run": args.dry_run, "sources": [str(s) for s in sources], "stats": stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
