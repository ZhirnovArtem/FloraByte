"""Workflow executor: topological run, branching, timeouts, partial failure."""

from __future__ import annotations

import asyncio
import logging
import shutil
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sqlmodel import Session, select

from app.config import get_settings
from app.core.models import NodeRun, Run
from app.core.masking import redact_text
from app.engine.events import event_bus
from app.engine.graph import (
    GraphError,
    incoming_edges,
    outgoing_edges,
    topological_order,
    validate_graph,
)
from app.nodes.base import NodeContext
from app.nodes.registry import NODE_REGISTRY, get_node_class

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _preview(output: dict[str, Any] | None) -> dict[str, Any] | None:
    if not output:
        return None
    preview: dict[str, Any] = {}
    for key, val in output.items():
        if key == "findings" and isinstance(val, list):
            by_sev: dict[str, int] = {}
            for f in val:
                sev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None) or "UNKNOWN"
                by_sev[str(sev)] = by_sev.get(str(sev), 0) + 1
            preview[key] = {"kind": "Findings", "count": len(val), "by_severity": by_sev}
        elif key == "workspace":
            preview[key] = {"kind": "Workspace", "path": str(val) if val else None}
        elif key == "report":
            if isinstance(val, dict):
                findings = val.get("findings") or val.get("report_json", {}).get("findings") or []
                preview[key] = {"kind": "Report", "findings_count": len(findings) if isinstance(findings, list) else 0}
            else:
                preview[key] = {"kind": "Report"}
        else:
            preview[key] = {"kind": type(val).__name__}
    return preview


class Executor:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    async def run_workflow(
        self,
        workflow_id: str,
        graph: dict[str, Any],
        trigger: str = "manual",
        wait: bool = False,
    ) -> str:
        settings = get_settings()
        try:
            validate_graph(graph, NODE_REGISTRY)
        except GraphError as e:
            raise ValueError(str(e)) from e

        run_id = None
        with self.session_factory() as session:
            run = Run(workflow_id=workflow_id, status="pending", trigger=trigger)
            session.add(run)
            session.commit()
            session.refresh(run)
            run_id = run.id

            # pre-create node_runs
            for n in graph.get("nodes", []):
                session.add(NodeRun(run_id=run_id, node_id=n["id"], status="pending"))
            session.commit()

        workspace = settings.runs_dir / run_id
        workspace.mkdir(parents=True, exist_ok=True)

        await event_bus.emit(run_id, {"event": "run_started", "workflow_id": workflow_id, "trigger": trigger})

        async def _execute():
            try:
                await self._execute_graph(run_id, graph, workspace)
            except Exception as e:
                logger.exception("Run %s failed: %s", run_id, e)
                with self.session_factory() as session:
                    run = session.get(Run, run_id)
                    if run:
                        run.status = "failed"
                        run.finished_at = _utcnow()
                        run.summary_json = {"error": redact_text(str(e))}
                        session.add(run)
                        session.commit()
                await event_bus.emit(run_id, {"event": "run_finished", "status": "failed", "error": str(e)})
            finally:
                # Keep reports/ for API download; remove the rest of workspace on success
                reports = workspace / "reports"
                keep_failed = False
                with self.session_factory() as session:
                    run = session.get(Run, run_id)
                    if run and run.status == "failed":
                        keep_failed = True
                if not keep_failed:
                    for child in list(workspace.iterdir()) if workspace.exists() else []:
                        if child.name == "reports":
                            continue
                        if child.is_dir():
                            shutil.rmtree(child, ignore_errors=True)
                        else:
                            child.unlink(missing_ok=True)

        if wait:
            await _execute()
        else:
            asyncio.create_task(_execute())

        return run_id

    async def _execute_graph(self, run_id: str, graph: dict[str, Any], workspace_root: Path) -> None:
        settings = get_settings()
        order = topological_order(graph)
        nodes = {n["id"]: n for n in graph.get("nodes", [])}

        # outputs[node_id][port] = value
        outputs: dict[str, dict[str, Any]] = {}
        # which output ports were activated (for branching)
        active_ports: dict[str, set[str]] = {}
        node_status: dict[str, str] = {nid: "pending" for nid in nodes}

        # For skipped propagation: edge is active if source succeeded AND sourceHandle is in active ports
        def edge_active(e: dict) -> bool:
            src = e["source"]
            if node_status.get(src) != "success":
                return False
            ports = active_ports.get(src)
            if not ports:
                # success with no recorded ports → consider active
                return True
            handle = e.get("sourceHandle")
            if handle is None or handle == "":
                # no specific handle on edge → any output activates downstream
                return True
            return handle in ports or "out" in ports

        for node_id in order:
            node = nodes[node_id]
            in_edges = incoming_edges(graph, node_id)

            # Determine if skipped
            if in_edges:
                active_ins = [e for e in in_edges if edge_active(e)]
                if not active_ins:
                    node_status[node_id] = "skipped"
                    await self._mark_node(run_id, node_id, "skipped")
                    await event_bus.emit(
                        run_id,
                        {"event": "node_skipped", "node_id": node_id, "status": "skipped"},
                    )
                    continue

            # Gather inputs
            inputs: dict[str, Any] = {}
            for e in in_edges:
                if not edge_active(e):
                    continue
                src_out = outputs.get(e["source"], {})
                handle = e.get("sourceHandle")
                tgt_handle = e.get("targetHandle") or "in"
                # Prefer exact port; fallback to first value
                if handle and handle in src_out:
                    inputs[tgt_handle] = src_out[handle]
                elif src_out:
                    # map common port names onto target handle
                    if tgt_handle in src_out:
                        inputs[tgt_handle] = src_out[tgt_handle]
                    else:
                        inputs[tgt_handle] = next(iter(src_out.values()))
                    # also expose original port names
                    for k, v in src_out.items():
                        inputs.setdefault(k, v)

            # Also pass common aliases
            if "workspace" not in inputs:
                for v in inputs.values():
                    if isinstance(v, (str, Path)) and Path(str(v)).exists():
                        inputs["workspace"] = Path(str(v))
                        break
            if "findings" not in inputs:
                for v in inputs.values():
                    if isinstance(v, list):
                        inputs["findings"] = v
                        break

            node_status[node_id] = "running"
            started = _utcnow()
            await self._mark_node(run_id, node_id, "running", started_at=started)
            await event_bus.emit(run_id, {"event": "node_started", "node_id": node_id, "status": "running"})

            try:
                cls = get_node_class(node["type"])
                instance = cls()
                params_data = node.get("params") or node.get("data", {}).get("params") or {}
                params = cls.Params.model_validate(params_data)

                ctx = NodeContext(
                    run_id=run_id,
                    node_id=node_id,
                    workspace=workspace_root,
                    settings=settings,
                )

                timeout = settings.node_timeout_sec
                result = await asyncio.wait_for(
                    instance.run(ctx, inputs, params),
                    timeout=timeout,
                )
                if not isinstance(result, dict):
                    result = {"out": result}

                outputs[node_id] = result
                # If node returns keys that match its declared output ports → those are active
                declared = {p.name for p in cls.outputs}
                if declared:
                    active_ports[node_id] = set(result.keys()) & declared or set(result.keys())
                else:
                    active_ports[node_id] = set(result.keys())

                finished = _utcnow()
                duration_ms = int((finished - started).total_seconds() * 1000)
                preview = _preview(result)
                node_status[node_id] = "success"
                await self._mark_node(
                    run_id, node_id, "success",
                    started_at=started, finished_at=finished,
                    output_preview=preview,
                )
                await event_bus.emit(
                    run_id,
                    {
                        "event": "node_finished",
                        "node_id": node_id,
                        "status": "success",
                        "started_at": started.isoformat(),
                        "finished_at": finished.isoformat(),
                        "duration_ms": duration_ms,
                        "output_preview": preview,
                        "error": None,
                    },
                )
            except Exception as e:
                finished = _utcnow()
                err = redact_text(f"{type(e).__name__}: {e}")
                logger.warning("Node %s failed: %s\n%s", node_id, err, traceback.format_exc())
                node_status[node_id] = "failed"
                await self._mark_node(
                    run_id, node_id, "failed",
                    started_at=started, finished_at=finished, error=err,
                )
                await event_bus.emit(
                    run_id,
                    {
                        "event": "node_failed",
                        "node_id": node_id,
                        "status": "failed",
                        "error": err,
                    },
                )
                # dependents will be skipped because edge_active checks success

        # Final status
        statuses = set(node_status.values())
        if "failed" in statuses and "success" in statuses:
            final = "partial"
        elif "failed" in statuses:
            final = "failed"
        else:
            final = "success"

        # Collect summary findings if any export produced report, and ai_report if ai.explain ran
        summary: dict[str, Any] = {"node_statuses": node_status}
        ai_report: dict[str, Any] | None = None
        for out in outputs.values():
            if "report" in out and isinstance(out["report"], dict):
                rep = out["report"]
                if "items" in rep and "validation" in rep:
                    ai_report = {
                        "summary": rep.get("summary", ""),
                        "items": rep.get("items", []),
                        "validation": rep.get("validation", {}),
                    }
                if "json_path" in rep or "report_json" in rep or "report" not in summary:
                    findings_list = rep.get("findings") or (rep.get("report_json") or {}).get("findings") or []
                    existing_paths = (summary.get("report") or {}).get("paths") or {}
                    new_paths = {
                        "json_path": rep.get("json_path") or existing_paths.get("json_path"),
                        "md_path": rep.get("md_path") or existing_paths.get("md_path"),
                    }
                    summary["report"] = {
                        "findings_count": len(findings_list),
                        "findings": findings_list,
                        "paths": new_paths,
                    }

        with self.session_factory() as session:
            run = session.get(Run, run_id)
            if run:
                run.status = final
                run.started_at = run.started_at or _utcnow()
                run.finished_at = _utcnow()
                run.summary_json = summary
                if ai_report is not None:
                    run.ai_report_json = ai_report
                session.add(run)
                session.commit()

        await event_bus.emit(run_id, {"event": "run_finished", "status": final, "summary": summary})

    async def _mark_node(
        self,
        run_id: str,
        node_id: str,
        status: str,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        output_preview: dict | None = None,
        error: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            nr = session.exec(
                select(NodeRun).where(NodeRun.run_id == run_id, NodeRun.node_id == node_id)
            ).first()
            if not nr:
                nr = NodeRun(run_id=run_id, node_id=node_id)
            nr.status = status
            if started_at:
                nr.started_at = started_at
            if finished_at:
                nr.finished_at = finished_at
            if output_preview is not None:
                nr.output_preview_json = output_preview
            if error is not None:
                nr.error = error
            session.add(nr)
            session.commit()
