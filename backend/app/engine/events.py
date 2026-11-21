"""In-memory event bus for run progress (WebSocket + DB persistence)."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.core.masking import redact_payload


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventBus:
    """Per-run event history + live subscribers."""

    def __init__(self) -> None:
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def emit(self, run_id: str, event: dict[str, Any]) -> None:
        safe_event = redact_payload({**event, "run_id": run_id, "ts": event.get("ts") or _utcnow()})
        async with self._lock:
            self._history[run_id].append(safe_event)
            for q in list(self._subs.get(run_id, [])):
                try:
                    q.put_nowait(safe_event)
                except asyncio.QueueFull:
                    pass

    def history(self, run_id: str) -> list[dict[str, Any]]:
        return list(self._history.get(run_id, []))

    async def subscribe(self, run_id: str, fallback_events: list[dict[str, Any]] | None = None) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subs[run_id].append(q)
            history = self._history.get(run_id, [])
            if not history and fallback_events:
                history = list(fallback_events)
            # replay history
            for ev in history:
                try:
                    q.put_nowait(ev)
                except asyncio.QueueFull:
                    break
        return q

    async def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subs.get(run_id, [])
            if q in subs:
                subs.remove(q)

    def clear(self, run_id: str) -> None:
        self._history.pop(run_id, None)
        self._subs.pop(run_id, None)


event_bus = EventBus()
