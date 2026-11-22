"""APScheduler integration — restore schedule triggers from DB on startup."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import func
from sqlmodel import Session, select

from app.core.db import get_engine
from app.core.models import Run, Workflow

logger = logging.getLogger(__name__)

MIN_INTERVAL_SECONDS = 30

scheduler = AsyncIOScheduler()
_run_callback: Callable[[str, dict, str | None], Awaitable[str]] | None = None
_fire_lock = asyncio.Lock()


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


def _parse_int(raw: Any) -> int | None:
    if raw is None or raw == "" or isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def count_schedule_runs(session: Session, workflow_id: str) -> int:
    """Count total scheduled runs stored in DB for this workflow."""
    stmt = (
        select(func.count())
        .select_from(Run)
        .where(Run.workflow_id == workflow_id, Run.trigger == "schedule")
    )
    res = session.exec(stmt).one()
    return int(res or 0)


def _extract_max_runs_from_graph(graph: dict) -> int | None:
    """Return positive max_runs if configured on any trigger.schedule node in graph."""
    limits: list[int] = []
    for _, params in _extract_schedule_params(graph):
        val = _parse_int(params.get("max_runs"))
        if val is not None and val > 0:
            limits.append(val)
    return min(limits) if limits else None


def _remove_workflow_jobs(workflow_id: str, job_id: str | None = None) -> None:
    if job_id:
        job = scheduler.get_job(job_id)
        if job is not None:
            job.remove()
        return
    prefix = f"wf_{workflow_id}_"
    for job in list(scheduler.get_jobs()):
        if str(job.id).startswith(prefix):
            job.remove()


def inspect_schedule_graph(
    graph: dict,
    used_runs: int | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
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
        interval = _parse_int(params.get("interval_seconds"))
        raw_max_runs = _parse_int(params.get("max_runs"))
        if raw_max_runs is not None and raw_max_runs < 0:
            warnings.append(
                f"Блок Schedule ({node_id}): max_runs ({raw_max_runs}) не может быть отрицательным — лимит не применяется."
            )
            max_runs: int | None = None
        elif raw_max_runs is not None and raw_max_runs > 0:
            max_runs = raw_max_runs
        else:
            max_runs = None

        limit_reached = bool(max_runs is not None and used_runs is not None and used_runs >= max_runs)

        if cron:
            try:
                CronTrigger.from_crontab(cron)
            except Exception as e:
                warnings.append(
                    f"Блок Schedule ({node_id}): некорректное cron-выражение {cron!r} ({e}) — задача не зарегистрирована."
                )
                continue
            if limit_reached:
                warnings.append(
                    f"Блок Schedule ({node_id}) остановлен: достигнут лимит запусков ({used_runs}/{max_runs}). "
                    f"Увеличьте max_runs или оставьте пустым для продолжения."
                )
            active.append(
                {
                    "node_id": node_id,
                    "cron": cron,
                    "interval_seconds": None,
                    "max_runs": max_runs,
                    "runs_used": used_runs,
                    "limit_reached": limit_reached,
                }
            )
        elif interval is not None and interval > 0:
            effective = interval
            if interval < MIN_INTERVAL_SECONDS:
                effective = MIN_INTERVAL_SECONDS
                warnings.append(
                    f"Блок Schedule ({node_id}): интервал {interval}с меньше минимума ({MIN_INTERVAL_SECONDS}с); "
                    f"установлен безопасный интервал {MIN_INTERVAL_SECONDS}с."
                )
            if limit_reached:
                warnings.append(
                    f"Блок Schedule ({node_id}) остановлен: достигнут лимит запусков ({used_runs}/{max_runs}). "
                    f"Увеличьте max_runs или оставьте пустым для продолжения."
                )
            active.append(
                {
                    "node_id": node_id,
                    "cron": "",
                    "interval_seconds": effective,
                    "max_runs": max_runs,
                    "runs_used": used_runs,
                    "limit_reached": limit_reached,
                }
            )
        else:
            warnings.append(
                f"Блок Schedule ({node_id}) не активен: задайте interval_seconds >= {MIN_INTERVAL_SECONDS} "
                f"(или cron) и сохраните сценарий, иначе задача расписания не создаётся."
            )

    return active, warnings


def get_workflow_scheduled_jobs_count(workflow_id: str) -> int:
    prefix = f"wf_{workflow_id}_"
    return sum(1 for job in scheduler.get_jobs() if str(job.id).startswith(prefix))


async def _fire(
    workflow_id: str,
    graph: dict,
    owner_id: str | None = None,
    job_id: str | None = None,
    max_runs: int | None = None,
) -> None:
    if not _run_callback:
        logger.warning("No run callback set for scheduler (workflow=%s)", workflow_id)
        return

    effective_max = max_runs if (max_runs is not None and max_runs > 0) else _extract_max_runs_from_graph(graph)

    async with _fire_lock:
        if effective_max is not None:
            with Session(get_engine()) as session:
                used_before = count_schedule_runs(session, workflow_id)
            if used_before >= effective_max:
                logger.info(
                    "Schedule max_runs already reached (%d/%d) for workflow=%s; removing job and skipping run",
                    used_before,
                    effective_max,
                    workflow_id,
                )
                _remove_workflow_jobs(workflow_id, job_id)
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
            return

        if effective_max is not None:
            with Session(get_engine()) as session:
                used_after = count_schedule_runs(session, workflow_id)
            if used_after >= effective_max:
                logger.info(
                    "Schedule max_runs reached (%d/%d) for workflow=%s; stopping scheduled job",
                    used_after,
                    effective_max,
                    workflow_id,
                )
                _remove_workflow_jobs(workflow_id, job_id)


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
        if not _extract_schedule_params(graph):
            continue
        used_runs = count_schedule_runs(session, w.id)
        active_entries, _ = inspect_schedule_graph(graph, used_runs=used_runs)
        for entry in active_entries:
            if entry.get("limit_reached"):
                logger.info(
                    "Skipping schedule job for workflow=%s node=%s: max_runs limit reached (%s/%s)",
                    w.id,
                    entry["node_id"],
                    entry.get("runs_used"),
                    entry.get("max_runs"),
                )
                continue
            node_id = entry["node_id"]
            job_id = f"wf_{w.id}_{node_id}"
            cron = entry.get("cron") or ""
            interval = entry.get("interval_seconds")
            max_runs = entry.get("max_runs")
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
                kwargs={
                    "workflow_id": w.id,
                    "graph": graph,
                    "owner_id": w.owner_id,
                    "job_id": job_id,
                    "max_runs": max_runs,
                },
            )
            count += 1
            logger.info(
                "Scheduled job %s (workflow=%s owner=%s cron=%r interval=%s max_runs=%s)",
                job_id,
                w.id,
                w.owner_id or "-",
                cron or None,
                interval,
                max_runs,
            )
    return count


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
        logger.info("APScheduler started")
