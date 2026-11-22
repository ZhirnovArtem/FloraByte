"""APScheduler integration — restore schedule triggers from DB on startup."""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from app.core.models import Workflow

logger = logging.getLogger(__name__)

MIN_INTERVAL_SECONDS = 30

scheduler = AsyncIOScheduler()
_run_callback: Callable[[str, dict, str | None], Awaitable[str]] | None = None


def set_run_callback(cb: Callable[[str, dict, str | None], Awaitable[str]]) -> None:
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


def _parse_interval(raw: Any) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def inspect_schedule_graph(graph: dict) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (active_entries, warnings) for trigger.schedule nodes in a graph."""
    sched_nodes = _extract_schedule_params(graph)
    if not sched_nodes:
        return [], []

    active: list[dict[str, Any]] = []
    warnings: list[str] = []

    has_upload_zip = any(
        n.get("type") == "source.upload_zip" for n in (graph.get("nodes") or [])
    )
    if has_upload_zip:
        warnings.append(
            "В сценарии с расписанием (Schedule) используется Upload ZIP: "
            "временный архив может отсутствовать при автозапуске или после рестарта сервера. "
            "Для периодических проверок рекомендуется source.git_clone."
        )

    for node_id, params in sched_nodes:
        cron = str(params.get("cron") or "").strip()
        interval = _parse_interval(params.get("interval_seconds"))

        if cron:
            try:
                CronTrigger.from_crontab(cron)
            except Exception as e:
                warnings.append(
                    f"Блок Schedule ({node_id}): некорректное cron-выражение {cron!r} ({e}) — задача не зарегистрирована."
                )
                continue
            active.append({"node_id": node_id, "cron": cron, "interval_seconds": None})
        elif interval is not None and interval > 0:
            effective = interval
            if interval < MIN_INTERVAL_SECONDS:
                effective = MIN_INTERVAL_SECONDS
                warnings.append(
                    f"Блок Schedule ({node_id}): интервал {interval}с меньше минимума ({MIN_INTERVAL_SECONDS}с); "
                    f"установлен безопасный интервал {MIN_INTERVAL_SECONDS}с."
                )
            active.append({"node_id": node_id, "cron": "", "interval_seconds": effective})
        else:
            warnings.append(
                f"Блок Schedule ({node_id}) не активен: задайте interval_seconds >= {MIN_INTERVAL_SECONDS} "
                f"(или cron) и сохраните сценарий, иначе задача расписания не создаётся."
            )

    return active, warnings


def get_workflow_scheduled_jobs_count(workflow_id: str) -> int:
    prefix = f"wf_{workflow_id}_"
    return sum(1 for job in scheduler.get_jobs() if str(job.id).startswith(prefix))


async def _fire(workflow_id: str, graph: dict, owner_id: str | None = None) -> None:
    if not _run_callback:
        logger.warning("No run callback set for scheduler (workflow=%s)", workflow_id)
        return
    try:
        run_id = await _run_callback(workflow_id, graph, owner_id)
        logger.info(
            "Scheduled run started: workflow=%s owner=%s run=%s",
            workflow_id,
            owner_id or "-",
            run_id,
        )
    except Exception as exc:
        logger.exception(
            "Scheduled run failed for workflow=%s owner=%s: %s",
            workflow_id,
            owner_id or "-",
            exc,
        )


def reload_schedules(session: Session) -> int:
    """Load all workflows with schedule triggers and register jobs."""
    for job in list(scheduler.get_jobs()):
        if str(job.id).startswith("wf_"):
            job.remove()

    count = 0
    workflows = session.exec(select(Workflow)).all()
    for w in workflows:
        if w.is_template:
            continue
        graph = w.graph_json or {}
        active_entries, _ = inspect_schedule_graph(graph)
        for entry in active_entries:
            node_id = entry["node_id"]
            job_id = f"wf_{w.id}_{node_id}"
            cron = entry.get("cron") or ""
            interval = entry.get("interval_seconds")
            if cron:
                trigger = CronTrigger.from_crontab(cron)
            elif interval and int(interval) > 0:
                trigger = IntervalTrigger(seconds=int(interval))
            else:
                continue
            scheduler.add_job(
                _fire,
                trigger=trigger,
                id=job_id,
                replace_existing=True,
                kwargs={"workflow_id": w.id, "graph": graph, "owner_id": w.owner_id},
            )
            count += 1
            logger.info(
                "Scheduled job %s (workflow=%s owner=%s cron=%r interval=%s)",
                job_id,
                w.id,
                w.owner_id or "-",
                cron or None,
                interval,
            )
    return count


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
        logger.info("APScheduler started")
