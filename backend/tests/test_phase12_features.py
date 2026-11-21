"""Phase 12 tests: Templates library, AI workflow generator, Run comparison, Deduplication, PDF export."""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

import app.core.db as db_mod
from app.config import get_settings
from app.main import app
from tests.conftest import authenticate_client


@pytest.fixture()
def p12_client(tmp_path, monkeypatch):
    db_file = tmp_path / "phase12.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
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
        authenticate_client(client)
        yield client
    db_mod._engine = None
    get_settings.cache_clear()


def _zip_files(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    return buf.getvalue()


def test_templates_library_contains_five_valid_templates(p12_client):
    res = p12_client.get("/api/templates")
    assert res.status_code == 200
    tpls = res.json()["templates"]
    names = {t["name"] for t in tpls}
    assert {
        "Full Security Scan",
        "Quick Secrets Scan",
        "SAST + SCA Quality Gate",
        "Git Repository Full Audit",
        "Scheduled Nightly Scan",
    }.issubset(names)

    valid_types = {n["type"] for n in p12_client.get("/api/node-types").json()["nodes"]}
    for t in tpls:
        for node in t["graph_json"]["nodes"]:
            assert node["type"] in valid_types


def test_ai_workflow_generator_variants(p12_client):
    valid_types = {n["type"] for n in p12_client.get("/api/node-types").json()["nodes"]}

    r1 = p12_client.post("/api/ai/generate-workflow", json={"prompt": "проверь git репозиторий на секреты и отправь в telegram"})
    assert r1.status_code == 200
    g1 = r1.json()["graph"]
    types1 = {n["type"] for n in g1["nodes"]}
    assert "source.git_clone" in types1
    assert "scanner.secrets" in types1
    assert "notify.telegram" in types1
    assert types1.issubset(valid_types)

    r2 = p12_client.post("/api/ai/generate-workflow", json={"prompt": "cron nightly sca sast with ai explain and webhook"})
    assert r2.status_code == 200
    g2 = r2.json()["graph"]
    types2 = {n["type"] for n in g2["nodes"]}
    assert "trigger.schedule" in types2
    assert "scanner.sca" in types2
    assert "scanner.sast" in types2
    assert "ai.explain" in types2
    assert "notify.webhook" in types2


def test_cross_run_dedup_comparison_and_pdf_export(p12_client):
    z1 = _zip_files({
        "app/settings.gradle.kts": 'rootProject.name = "p12"\n',
        "app/src/main/kotlin/A.kt": 'val password = "secret_v1_unmasked_value"\n',
    })
    z2 = _zip_files({
        "app/settings.gradle.kts": 'rootProject.name = "p12"\n',
        "app/src/main/kotlin/A.kt": 'val password = "secret_v1_unmasked_value"\n',
        "app/src/main/kotlin/B.kt": 'fun q(u: String) = jdbc.queryForList("SELECT * FROM t WHERE a = \'$u\'")\n',
    })

    up1 = p12_client.post("/api/uploads", files={"file": ("v1.zip", z1, "application/zip")}).json()["upload_id"]
    up2 = p12_client.post("/api/uploads", files={"file": ("v2.zip", z2, "application/zip")}).json()["upload_id"]

    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up1}},
            {"id": "sc1", "type": "scanner.secrets", "params": {}},
            {"id": "sc3", "type": "scanner.sast", "params": {}},
            {"id": "m1", "type": "findings.merge", "params": {}},
            {"id": "e1", "type": "findings.export", "params": {}},
            {"id": "ai1", "type": "ai.explain", "params": {}},
        ],
        "edges": [
            {"id": "e1", "source": "t1", "target": "s1"},
            {"id": "e2", "source": "s1", "target": "sc1"},
            {"id": "e3", "source": "s1", "target": "sc3"},
            {"id": "e4", "source": "sc1", "target": "m1", "targetHandle": "a"},
            {"id": "e5", "source": "sc3", "target": "m1", "targetHandle": "b"},
            {"id": "e6", "source": "m1", "target": "e1"},
            {"id": "e7", "source": "m1", "target": "ai1"},
        ],
    }

    wf_id = p12_client.post("/api/workflows", json={"name": "p12-wf", "graph_json": graph}).json()["id"]
    run1_id = p12_client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    # Update upload_id to v2 (adds SAST finding while keeping SECRET finding)
    graph["nodes"][1]["params"]["upload_id"] = up2
    p12_client.put(f"/api/workflows/{wf_id}", json={"graph_json": graph})
    run2_id = p12_client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]

    # Dedup check on run 2
    dedup = p12_client.get(f"/api/runs/{run2_id}/dedup").json()
    assert dedup["baseline_run_id"] == run1_id
    assert dedup["persisting_count"] >= 1
    assert dedup["new_count"] >= 1

    # Compare run1 -> run2
    cmp_res = p12_client.get(f"/api/runs/compare?base={run1_id}&target={run2_id}")
    assert cmp_res.status_code == 200
    cmp = cmp_res.json()
    assert cmp["summary"]["new_count"] >= 1
    assert cmp["summary"]["persisting_count"] >= 1
    assert cmp["summary"]["delta"] >= 1
    assert "target_dashboard" in cmp

    # PDF Export check
    pdf_res = p12_client.get(f"/api/runs/{run2_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"].startswith("application/pdf")
    assert pdf_res.content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_res.content[-64:]
    assert b"secret_v1_unmasked_value" not in pdf_res.content
