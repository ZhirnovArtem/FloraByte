from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.engine.events import event_bus

router = APIRouter(tags=["ws"])


@router.websocket("/ws/runs/{run_id}")
async def ws_run_events(websocket: WebSocket, run_id: str):
    await websocket.accept()
    q = await event_bus.subscribe(run_id)
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
