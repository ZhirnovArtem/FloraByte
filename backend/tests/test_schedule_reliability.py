"""Tests for schedule execution reliability: owner_id propagation, warnings, failed_nodes, and restart reload."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session

import app.core.db as db_mod
from app.config import get_settings
from app.engine import scheduler as sched_mod
from app.main import app
from tests.conftest import authenticate_client


@pytest.fixture()
def sched_client(tmp_path, monkeypatch):
    db_file = tmp_path / "sched.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    db_mod._engine = None
    SQLModel.metadata.drop_all(db_mod.get_engine())
    db_mod.init_db()
    with TestClient(app) as client:
        auth = authenticate_client(client, email="sched.owner@example.com")
        yield client, auth["user"]["id"], tmp_path
    for job in list(sched_mod.scheduler.get_jobs()):
        if str(job.id).startswith("wf_"):
            job.remove()
    db_mod._engine = None
    get_settings.cache_clear()


def test_schedule_save_validation_warnings_and_clamping(sched_client):
    client, _, _ = sched_client

    # 3.6: interval_seconds=0 and empty cron -> 0 jobs + clear warning
    res_zero = client.post(
        "/api/workflows",
        json={
            "name": "sched-zero",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 0}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
                ],
                "edges": [{"id": "e1", "source": "t1", "target": "s1"}],
            },
        },
    )
    assert res_zero.status_code == 200, res_zero.text
    wf_zero = res_zero.json()
    assert wf_zero["scheduled_jobs"] == 0
    assert any("не активен" in w for w in wf_zero["schedule_warnings"])

    # interval_seconds=10 (< 30) -> clamped to 30s + warning
    res_fast = client.put(
        f"/api/workflows/{wf_zero['id']}",
        json={
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 10}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
                ],
                "edges": [{"id": "e1", "source": "t1", "target": "s1"}],
            },
        },
    )
    assert res_fast.status_code == 200
    wf_fast = res_fast.json()
    assert wf_fast["scheduled_jobs"] == 1
    assert wf_fast["schedule_summary"][0]["interval_seconds"] == 30
    assert any("30с" in w for w in wf_fast["schedule_warnings"])

    # 3.7: upload_zip + trigger.schedule warns user to switch to git_clone
    res_zip_warn = client.post(
        "/api/workflows",
        json={
            "name": "sched-zip-warn",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": "00000000-0000-0000-0000-000000000001"}},
                ],
                "edges": [{"id": "e1", "source": "t1", "target": "s1"}],
            },
        },
    )
    assert res_zip_warn.status_code == 200
    assert any("git_clone" in w for w in res_zip_warn.json()["schedule_warnings"])


def test_schedule_run_propagates_owner_id_and_sends_email_and_survives_reload(sched_client):
    client, user_id, _ = sched_client

    # Save per-user Email integration (Resend)
    save_em = client.put(
        "/api/integrations/email",
        json={
            "transport": "resend",
            "from_email": "onboarding@resend.dev",
            "default_to": "owner-alerts@company.com",
            "secret": "re_sched_owner_secret_12345",
            "enabled": True,
        },
    )
    assert save_em.status_code == 200

    # Save scheduled workflow using source.git_clone -> scanner.secrets -> findings.export -> notify.email
    wf_res = client.post(
        "/api/workflows",
        json={
            "name": "sched-git-email",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                    {"id": "em1", "type": "notify.email", "params": {"dry_run": False}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "target": "e1", "targetHandle": "findings"},
                    {"id": "ed4", "source": "e1", "sourceHandle": "report", "target": "em1", "targetHandle": "report"},
                ],
            },
        },
    )
    assert wf_res.status_code == 200
    wf = wf_res.json()
    assert wf["scheduled_jobs"] == 1
    assert wf["schedule_warnings"] == []

    # Simulate backend restart: clear scheduler jobs and reload from DB
    for job in list(sched_mod.scheduler.get_jobs()):
        if str(job.id).startswith("wf_"):
            job.remove()
    assert sched_mod.get_workflow_scheduled_jobs_count(wf["id"]) == 0
    with Session(db_mod.get_engine()) as session:
        reloaded = sched_mod.reload_schedules(session)
    assert reloaded >= 1
    job = sched_mod.scheduler.get_job(f"wf_{wf['id']}_t1")
    assert job is not None
    assert job.kwargs["owner_id"] == user_id

    # Mock git_clone and Resend HTTPS POST, then fire the scheduler job directly
    sent_emails = []

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_exec(*cmd, **kwargs):
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "settings.gradle.kts").write_text('rootProject.name = "demo"\n', encoding="utf-8")
        return FakeProc()

    class FakeResp:
        status_code = 200
        text = '{"id": "email_sched_1"}'

        def json(self):
            return {"id": "email_sched_1"}

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent_emails.append(json)
            return FakeResp()

    async def _fire_and_wait():
        await sched_mod._fire(**job.kwargs)
        # Wait briefly for background asyncio task spawned with wait=False
        for _ in range(40):
            runs = client.get("/api/runs").json()["runs"]
            sched_runs = [r for r in runs if r["workflow_id"] == wf["id"] and r["trigger"] == "schedule"]
            if sched_runs and sched_runs[0]["status"] in ("success", "partial", "failed"):
                return sched_runs[0]
            await asyncio.sleep(0.1)
        raise AssertionError("Scheduled run did not finish in time")

    with (
        patch("app.nodes.source.git_clone.asyncio.create_subprocess_exec", side_effect=fake_exec),
        patch("app.nodes.notify.email.httpx.AsyncClient", FakeAsyncClient),
    ):
        run_info = asyncio.run(_fire_and_wait())

    assert run_info["trigger"] == "schedule"
    assert run_info["status"] == "success", run_info
    assert run_info["summary"]["failed_nodes"] == []
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == ["owner-alerts@company.com"]


def test_schedule_missing_upload_zip_records_failed_nodes_in_summary(sched_client):
    client, _, _ = sched_client
    wf_res = client.post(
        "/api/workflows",
        json={
            "name": "sched-missing-zip",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": "00000000-0000-0000-0000-000000000099"}},
                ],
                "edges": [{"id": "e1", "source": "t1", "target": "s1"}],
            },
        },
    )
    assert wf_res.status_code == 200
    wf = wf_res.json()
    job = sched_mod.scheduler.get_job(f"wf_{wf['id']}_t1")
    assert job is not None

    async def _fire_and_wait():
        await sched_mod._fire(**job.kwargs)
        for _ in range(40):
            runs = client.get("/api/runs").json()["runs"]
            sched_runs = [r for r in runs if r["workflow_id"] == wf["id"] and r["trigger"] == "schedule"]
            if sched_runs and sched_runs[0]["status"] in ("success", "partial", "failed"):
                return sched_runs[0]
            await asyncio.sleep(0.1)
        raise AssertionError("Scheduled run did not finish in time")

    run_info = asyncio.run(_fire_and_wait())
    assert run_info["status"] == "partial"
    failed_nodes = run_info["summary"]["failed_nodes"]
    assert len(failed_nodes) == 1
    assert failed_nodes[0]["node_id"] == "s1"
    assert "git_clone" in failed_nodes[0]["error"]


def test_delete_workflow_stops_schedule_even_with_existing_runs(sched_client):
    client, _, _ = sched_client
    wf_res = client.post(
        "/api/workflows",
        json={
            "name": "sched-to-delete",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
                ],
                "edges": [{"id": "e1", "source": "t1", "target": "s1"}],
            },
        },
    )
    assert wf_res.status_code == 200
    wf_id = wf_res.json()["id"]
    assert sched_mod.scheduler.get_job(f"wf_{wf_id}_t1") is not None

    # Create a run linked to this workflow first
    run_res = client.post(f"/api/workflows/{wf_id}/run?wait=true")
    assert run_res.status_code == 200

    # Delete workflow -> must succeed, remove from /api/workflows, and unschedule job
    del_res = client.delete(f"/api/workflows/{wf_id}")
    assert del_res.status_code == 200
    assert del_res.json() == {"ok": True}
    assert sched_mod.scheduler.get_job(f"wf_{wf_id}_t1") is None
    assert wf_id not in [w["id"] for w in client.get("/api/workflows").json()["workflows"]]
    assert client.get(f"/api/workflows/{wf_id}").status_code == 404


def test_schedule_max_runs_limits_email_reports_and_survives_reload(sched_client):
    client, _, _ = sched_client

    save_em = client.put(
        "/api/integrations/email",
        json={
            "transport": "resend",
            "from_email": "onboarding@resend.dev",
            "default_to": "limited-reports@company.com",
            "secret": "re_sched_limit_secret_12345",
            "enabled": True,
        },
    )
    assert save_em.status_code == 200

    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60, "max_runs": 2}},
            {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
            {"id": "em1", "type": "notify.email", "params": {"dry_run": False}},
        ],
        "edges": [
            {"id": "ed1", "source": "t1", "target": "s1"},
            {"id": "ed2", "source": "s1", "target": "sc1"},
            {"id": "ed3", "source": "sc1", "target": "e1", "targetHandle": "findings"},
            {"id": "ed4", "source": "e1", "sourceHandle": "report", "target": "em1", "targetHandle": "report"},
        ],
    }

    wf_res = client.post("/api/workflows", json={"name": "sched-max-2", "graph_json": graph})
    assert wf_res.status_code == 200
    wf = wf_res.json()
    wf_id = wf["id"]
    assert wf["scheduled_jobs"] == 1
    assert wf["schedule_runs_used"] == 0
    assert wf["schedule_summary"][0]["max_runs"] == 2
    assert wf["schedule_summary"][0]["limit_reached"] is False

    sent_emails = []

    async def fake_resend(api_key, from_addr, to_addr, subject, body):
        sent_emails.append({"to": to_addr, "subject": subject})
        return f"msg-{len(sent_emails)}"

    # Manual run must NOT consume schedule max_runs quota
    with patch("app.nodes.notify.email._send_resend_async", side_effect=fake_resend):
        manual_res = client.post(f"/api/workflows/{wf_id}/run?wait=true")
        assert manual_res.status_code == 200
    assert len(sent_emails) == 1
    sent_emails.clear()

    job_id = f"wf_{wf_id}_t1"

    async def _run_and_wait_nth(expected_sched_count: int):
        job = sched_mod.scheduler.get_job(job_id)
        assert job is not None
        await sched_mod._fire(**job.kwargs)
        for _ in range(40):
            runs = client.get("/api/runs").json()["runs"]
            sched_runs = [r for r in runs if r["workflow_id"] == wf_id and r["trigger"] == "schedule"]
            if len(sched_runs) >= expected_sched_count and all(
                r["status"] in ("success", "partial", "failed") for r in sched_runs
            ):
                return sched_runs
            await asyncio.sleep(0.1)
        raise AssertionError("Scheduled run did not finish in time")

    with patch("app.nodes.notify.email._send_resend_async", side_effect=fake_resend):
        # Run 1 of 2 -> email sent, job remains scheduled
        asyncio.run(_run_and_wait_nth(1))
        assert len(sent_emails) == 1
        assert sched_mod.scheduler.get_job(job_id) is not None

        # Run 2 of 2 -> email sent, job automatically removed upon reaching max_runs=2
        asyncio.run(_run_and_wait_nth(2))
        assert len(sent_emails) == 2
        assert sched_mod.scheduler.get_job(job_id) is None

        # Extra defensive _fire call must NOT start a 3rd scheduled run or send a 3rd email
        asyncio.run(sched_mod._fire(workflow_id=wf_id, graph=graph, job_id=job_id, max_runs=2))
        assert len(sent_emails) == 2

    # Simulate server restart / reload_schedules -> must NOT re-add job
    with Session(db_mod.get_engine()) as session:
        assert sched_mod.reload_schedules(session) == 0
    assert sched_mod.scheduler.get_job(job_id) is None

    wf_after = client.get(f"/api/workflows/{wf_id}").json()
    assert wf_after["scheduled_jobs"] == 0
    assert wf_after["schedule_runs_used"] == 2
    assert wf_after["schedule_summary"][0]["limit_reached"] is True
    assert any("лимит запусков" in w for w in wf_after["schedule_warnings"])

    # Raising max_runs from 2 to 3 resumes the schedule for 1 more run
    graph["nodes"][0]["params"]["max_runs"] = 3
    upd_res = client.put(f"/api/workflows/{wf_id}", json={"graph_json": graph})
    assert upd_res.status_code == 200
    assert upd_res.json()["scheduled_jobs"] == 1
    assert upd_res.json()["schedule_summary"][0]["limit_reached"] is False


