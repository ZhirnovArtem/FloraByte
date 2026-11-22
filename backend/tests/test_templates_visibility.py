"""Tests for private/public workflow templates library, ACLs, secret sanitization, and scheduler isolation."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session

import app.core.db as db_mod
from app.config import get_settings
from app.core.auth import login_limiter, register_limiter
from app.engine import scheduler as sched_mod
from app.main import app
from tests.conftest import authenticate_client


@pytest.fixture()
def tpl_clients(tmp_path, monkeypatch):
    db_file = tmp_path / "templates_vis.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    login_limiter._hits.clear()
    register_limiter._hits.clear()
    db_mod._engine = None
    SQLModel.metadata.drop_all(db_mod.get_engine())
    db_mod.init_db()

    with TestClient(app) as client_a, TestClient(app) as client_b:
        auth_a = authenticate_client(client_a, email="author.a@example.com")
        auth_b = authenticate_client(client_b, email="reader.b@example.com")
        yield client_a, auth_a["user"]["id"], client_b, auth_b["user"]["id"]

    for job in list(sched_mod.scheduler.get_jobs()):
        if str(job.id).startswith("wf_"):
            job.remove()
    db_mod._engine = None
    get_settings.cache_clear()


def test_seed_templates_are_system_public_and_immutable(tpl_clients):
    client_a, _, _, _ = tpl_clients
    res = client_a.get("/api/templates")
    assert res.status_code == 200
    tpls = res.json()["templates"]
    assert len(tpls) >= 5
    sys_tpl = next(t for t in tpls if t["is_system"])
    assert sys_tpl["visibility"] == "public"
    assert sys_tpl["owner_id"] is None
    assert sys_tpl["is_owner"] is False

    assert client_a.patch(f"/api/templates/{sys_tpl['id']}", json={"visibility": "private"}).status_code == 403
    assert client_a.delete(f"/api/templates/{sys_tpl['id']}").status_code == 403


def test_private_public_visibility_acl_copy_and_scheduler_isolation(tpl_clients):
    client_a, user_a_id, client_b, user_b_id = tpl_clients

    # User A creates a scheduled workflow (which should register 1 scheduler job, NOT duplicated by template)
    wf_res = client_a.post(
        "/api/workflows",
        json={
            "name": "Audit Pipeline A",
            "description": "Checks git repo",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.schedule", "params": {"cron": "", "interval_seconds": 60}},
                    {"id": "s1", "type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training"}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                    {"id": "tg1", "type": "notify.telegram", "params": {"credential_id": "cred-secret-123", "chat_id": "999111"}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "target": "e1", "targetHandle": "findings"},
                    {"id": "ed4", "source": "e1", "sourceHandle": "report", "target": "tg1", "targetHandle": "report"},
                ],
            },
        },
    )
    assert wf_res.status_code == 200, wf_res.text
    wf_a_id = wf_res.json()["id"]
    assert wf_res.json()["scheduled_jobs"] == 1

    # 1. User A publishes workflow as PRIVATE template
    pub_res = client_a.post(
        "/api/templates/publish",
        json={
            "workflow_id": wf_a_id,
            "name": "Private Template A",
            "description": "Only for A",
            "visibility": "private",
        },
    )
    assert pub_res.status_code == 200, pub_res.text
    tpl = pub_res.json()
    tpl_id = tpl["id"]
    assert tpl_id != wf_a_id
    assert tpl["visibility"] == "private"
    assert tpl["owner_id"] == user_a_id
    assert tpl["is_owner"] is True
    assert tpl["is_system"] is False
    assert tpl["nodes_count"] == 5

    # Original workflow remains in A's workflows; template is NOT in /api/workflows and NOT in scheduler
    a_wfs = client_a.get("/api/workflows").json()["workflows"]
    assert [w["id"] for w in a_wfs] == [wf_a_id]
    with Session(db_mod.get_engine()) as session:
        assert sched_mod.reload_schedules(session) == 1  # only wf_a_id, NOT tpl_id

    # Sanitization stripped credential_id on publish
    tg_node = next(n for n in tpl["graph_json"]["nodes"] if n["type"] == "notify.telegram")
    assert tg_node["params"]["credential_id"] == ""

    # User A sees it in all & mine; NOT in public
    assert tpl_id in [t["id"] for t in client_a.get("/api/templates?scope=mine").json()["templates"]]
    assert tpl_id not in [t["id"] for t in client_a.get("/api/templates?scope=public").json()["templates"]]

    # 2. User B CANNOT see or enumerate User A's PRIVATE template (404)
    assert tpl_id not in [t["id"] for t in client_b.get("/api/templates").json()["templates"]]
    assert client_b.get(f"/api/templates/{tpl_id}").status_code == 404
    assert client_b.post(f"/api/templates/{tpl_id}/copy").status_code == 404
    assert client_b.patch(f"/api/templates/{tpl_id}", json={"visibility": "public"}).status_code == 404
    assert client_b.delete(f"/api/templates/{tpl_id}").status_code == 404

    # 3. User A switches template to PUBLIC via PATCH
    patch_res = client_a.patch(f"/api/templates/{tpl_id}", json={"visibility": "public"})
    assert patch_res.status_code == 200
    assert patch_res.json()["visibility"] == "public"
    tg_public = next(n for n in patch_res.json()["graph_json"]["nodes"] if n["type"] == "notify.telegram")
    assert tg_public["params"]["chat_id"] == ""

    # User B still cannot edit or delete A's PUBLIC template (403)
    assert client_b.patch(f"/api/templates/{tpl_id}", json={"name": "Hijacked"}).status_code == 403
    assert client_b.delete(f"/api/templates/{tpl_id}").status_code == 403

    # User B sees it in all & public (NOT in mine) and can copy it
    b_all = client_b.get("/api/templates").json()["templates"]
    b_entry = next(t for t in b_all if t["id"] == tpl_id)
    assert b_entry["owner_email"] == "a***a@example.com"
    assert tpl_id in [t["id"] for t in client_b.get("/api/templates?scope=public").json()["templates"]]
    assert tpl_id not in [t["id"] for t in client_b.get("/api/templates?scope=mine").json()["templates"]]

    copy_res = client_b.post(f"/api/templates/{tpl_id}/copy")
    assert copy_res.status_code == 200, copy_res.text
    copied = copy_res.json()
    assert copied["is_template"] is False
    assert copied["name"] == "Private Template A (copy)"
    assert copied["source_template_id"] == tpl_id
    # Copied workflow belongs to User B and appears in User B's workflows
    b_wfs = client_b.get("/api/workflows").json()["workflows"]
    assert any(w["id"] == copied["id"] for w in b_wfs)
    assert user_b_id != user_a_id

    # Search filter works
    q_res = client_b.get("/api/templates?q=Private+Template+A").json()["templates"]
    assert [t["id"] for t in q_res] == [tpl_id]

    # User A deletes their template cleanly
    del_res = client_a.delete(f"/api/templates/{tpl_id}")
    assert del_res.status_code == 200
    assert client_a.get(f"/api/templates/{tpl_id}").status_code == 404


def test_sanitize_strips_upload_id_webhook_headers_and_tokens():
    from app.core.template_utils import sanitize_graph_for_template

    dirty = {
        "nodes": [
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": "11111111-1111-1111-1111-111111111111"}},
            {
                "id": "w1",
                "type": "notify.webhook",
                "params": {
                    "url": "https://user:pass@hooks.example.com/hook?token=secret123&env=prod",
                    "headers_json": json.dumps({"Authorization": "Bearer super-secret", "X-Env": "ci"}),
                    "credential_id": "cred-wh-1",
                },
            },
            {"id": "em1", "type": "notify.email", "params": {"to_email": "private@corp.com", "credential_id": "cred-em"}},
        ],
        "edges": [],
    }
    clean = sanitize_graph_for_template(dirty, strip_recipient_email=True)
    n_zip, n_wh, n_em = clean["nodes"]
    assert n_zip["params"]["upload_id"] == ""
    assert n_wh["params"]["credential_id"] == ""
    assert "pass@" not in n_wh["params"]["url"]
    assert "secret123" not in n_wh["params"]["url"]
    assert "super-secret" not in n_wh["params"]["headers_json"]
    assert "X-Env" in n_wh["params"]["headers_json"]
    assert n_em["params"]["to_email"] == ""
    assert n_em["params"]["credential_id"] == ""
