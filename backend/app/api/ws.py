from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select

from app.config import get_settings
from app.core.auth import SESSION_COOKIE_NAME, resolve_session_from_token
from app.core.db import get_engine
from app.core.models import NodeRun, Run
from app.engine.events import event_bus

router = APIRouter(tags=["ws"])


def _replay_events_from_db(run_id: str) -> list[dict[str, Any]]:
    """Reconstruct run/node events from persisted DB rows if in-memory history is empty."""
    with Session(get_engine()) as session:
        run = session.get(Run, run_id)
        if not run:
            return []
        events: list[dict[str, Any]] = [
            {
                "event": "run_started",
                "run_id": run_id,
                "workflow_id": run.workflow_id,
                "trigger": run.trigger,
                "ts": run.started_at.isoformat() if run.started_at else None,
            }
        ]
        node_runs = session.exec(select(NodeRun).where(NodeRun.run_id == run_id)).all()
        for nr in node_runs:
            if nr.status == "pending":
                continue
            if nr.status == "skipped":
                events.append({"event": "node_skipped", "run_id": run_id, "node_id": nr.node_id, "status": "skipped"})
                continue
            events.append(
                {
                    "event": "node_started",
                    "run_id": run_id,
                    "node_id": nr.node_id,
                    "status": "running",
                    "ts": nr.started_at.isoformat() if nr.started_at else None,
                }
            )
            if nr.status == "success":
                duration_ms = None
                if nr.started_at and nr.finished_at:
                    duration_ms = int((nr.finished_at - nr.started_at).total_seconds() * 1000)
                events.append(
                    {
                        "event": "node_finished",
                        "run_id": run_id,
                        "node_id": nr.node_id,
                        "status": "success",
                        "started_at": nr.started_at.isoformat() if nr.started_at else None,
                        "finished_at": nr.finished_at.isoformat() if nr.finished_at else None,
                        "duration_ms": duration_ms,
                        "output_preview": nr.output_preview_json,
                        "error": None,
                    }
                )
            elif nr.status == "failed":
                events.append(
                    {
                        "event": "node_failed",
                        "run_id": run_id,
                        "node_id": nr.node_id,
                        "status": "failed",
                        "error": nr.error,
                    }
                )
        if run.status in ("success", "failed", "partial"):
            events.append(
                {
                    "event": "run_finished",
                    "run_id": run_id,
                    "status": run.status,
                    "summary": run.summary_json,
                    "ts": run.finished_at.isoformat() if run.finished_at else None,
                }
            )
        return events


@router.websocket("/ws/runs/{run_id}")
async def ws_run_events(websocket: WebSocket, run_id: str):
    settings = get_settings()
    expected = settings.workflow_access_token
    offered = websocket.scope.get("subprotocols") or []
    raw_cookie = websocket.cookies.get(SESSION_COOKIE_NAME, "")

    authed_user = None
    service_auth = False

    if raw_cookie:
        with Session(get_engine()) as session:
            resolved = resolve_session_from_token(session, raw_cookie)
        if resolved:
            _, authed_user = resolved

    if not authed_user and expected:
        if any(p.startswith("auth.") and secrets.compare_digest(p[5:], expected) for p in offered):
            service_auth = True

    if not authed_user and not service_auth:
        if settings.auth_required or expected:
            await websocket.close(code=1008)
            return

    if authed_user is not None:
        with Session(get_engine()) as session:
            run = session.get(Run, run_id)
            if run and run.owner_id is not None and run.owner_id != authed_user.id:
                await websocket.close(code=1008)
                return

    if service_auth:
        await websocket.accept(subprotocol="florabyte" if "florabyte" in offered else None)
    else:
        await websocket.accept()

    fallback_events = _replay_events_from_db(run_id) if not event_bus.history(run_id) else None
    q = await event_bus.subscribe(run_id, fallback_events=fallback_events)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event, ensure_ascii=False, default=str))
            except asyncio.TimeoutError:
                # keepalive ping
                try:
                    await websocket.send_text(json.dumps({"event": "ping"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await event_bus.unsubscribe(run_id, q)
