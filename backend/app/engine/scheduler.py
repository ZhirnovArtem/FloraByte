"""APScheduler integration — restore schedule triggers from DB on startup."""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from app.core.models import Workflow

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()
_run_callback: Callable[[str, dict], Awaitable[str]] | None = None


def set_run_callback(cb: Callable[[str, dict], Awaitable[str]]) -> None:
    global _run_callback
    _run_callback = cb


def _extract_schedule_params(graph: dict) -> list[tuple[str, dict]]:
    """Return list of (node_id, params) for trigger.schedule nodes."""
    out = []
    for n in graph.get("nodes") or []:
        if n.get("type") == "trigger.schedule":
            params = n.get("params") or {}
            out.append((n["id"], params))
    return out


async def _fire(workflow_id: str, graph: dict) -> None:
    if not _run_callback:
        logger.warning("No run callback set for scheduler")
        return
    try:
        run_id = await _run_callback(workflow_id, graph)
        logger.info("Scheduled run started: workflow=%s run=%s", workflow_id, run_id)
    except Exception:
        logger.exception("Scheduled run failed for workflow %s", workflow_id)


def reload_schedules(session: Session) -> int:
    """Load all workflows with schedule triggers and register jobs."""
    # remove existing jobs
    for job in list(scheduler.get_jobs()):
        if str(job.id).startswith("wf_"):
            job.remove()

    count = 0
    workflows = session.exec(select(Workflow)).all()
    for w in workflows:
        graph = w.graph_json or {}
        for node_id, params in _extract_schedule_params(graph):
            job_id = f"wf_{w.id}_{node_id}"
            cron = (params.get("cron") or "").strip()
            interval = params.get("interval_seconds")
            trigger = None
            if cron:
                try:
                    trigger = CronTrigger.from_crontab(cron)
                except Exception as e:
                    logger.warning("Bad cron %r for %s: %s", cron, job_id, e)
                    continue
            elif interval and int(interval) > 0:
                trigger = IntervalTrigger(seconds=int(interval))
            else:
                continue
            scheduler.add_job(
                _fire,
                trigger=trigger,
                id=job_id,
                replace_existing=True,
                kwargs={"workflow_id": w.id, "graph": graph},
            )
            count += 1
            logger.info("Scheduled job %s", job_id)
    return count


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
        logger.info("APScheduler started")
