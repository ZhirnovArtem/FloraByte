"""E2E: Manual → Upload → stub scanner → merge → export → valid report.json"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure stubs are on for this test
import os
os.environ["USE_STUB_SCANNERS"] = "1"

from app.config import get_settings
get_settings.cache_clear()

from app.main import app
from app.core.db import init_db, get_engine
from sqlmodel import SQLModel
from tests.conftest import authenticate_client


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    # isolated db + dirs
    base = tmp_path_factory.mktemp("e2e")
    os.environ["DATABASE_URL"] = f"sqlite:///{base}/test.db"
    os.environ["USE_STUB_SCANNERS"] = "1"
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = base / "runs"
    settings.upload_dir = base / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    settings.use_stub_scanners = True
    # re-init db
    SQLModel.metadata.drop_all(get_engine())
    init_db()
    with TestClient(app) as c:
        authenticate_client(c)
        yield c


def _make_zip_with_gradle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("training-project/build.gradle.kts", "plugins { kotlin(\"jvm\") }\n")
        zf.writestr("training-project/settings.gradle.kts", "rootProject.name = \"demo\"\n")
        zf.writestr("training-project/src/main/kotlin/A.kt", "fun main() {}\n")
        zf.writestr("README.md", "demo\n")
    return buf.getvalue()


def test_manual_upload_scanner_export(client: TestClient):
    # 1) upload
    data = _make_zip_with_gradle()
    r = client.post(
        "/api/uploads",
        files={"file": ("demo.zip", data, "application/zip")},
    )
    assert r.status_code == 200, r.text
    upload_id = r.json()["upload_id"]

    # 2) create workflow
    graph = {
        "nodes": [
            {"id": "t1", "type": "trigger.manual", "params": {}, "position": {"x": 0, "y": 0}},
            {
                "id": "s1",
                "type": "source.upload_zip",
                "params": {"upload_id": upload_id},
                "position": {"x": 100, "y": 0},
            },
            {"id": "sc1", "type": "scanner.secrets", "params": {}, "position": {"x": 200, "y": 0}},
            {"id": "m1", "type": "findings.merge", "params": {}, "position": {"x": 300, "y": 0}},
            {"id": "e1", "type": "findings.export", "params": {}, "position": {"x": 400, "y": 0}},
        ],
        "edges": [
            {"id": "e1", "source": "t1", "target": "s1"},
            {"id": "e2", "source": "s1", "target": "sc1"},
            {"id": "e3", "source": "sc1", "target": "m1"},
            {"id": "e4", "source": "m1", "target": "e1"},
        ],
    }
    r = client.post("/api/workflows", json={"name": "e2e-b", "graph_json": graph})
    assert r.status_code == 200, r.text
    wf_id = r.json()["id"]

    # 3) run with wait
    r = client.post(f"/api/workflows/{wf_id}/run?wait=true")
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]

    # 4) check run status
    r = client.get(f"/api/runs/{run_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("success", "partial"), body
    nodes = {n["node_id"]: n for n in body["nodes"]}
    assert nodes["t1"]["status"] == "success"
    assert nodes["s1"]["status"] == "success"
    assert nodes["sc1"]["status"] == "success"
    assert nodes["e1"]["status"] == "success"

    # 5) report.json valid
    r = client.get(f"/api/runs/{run_id}/report.json")
    assert r.status_code == 200
    report = r.json()
    assert "findings" in report
    assert isinstance(report["findings"], list)
    # with stubs we expect at least 1
    assert len(report["findings"]) >= 1
    f0 = report["findings"][0]
    assert f0["category"] in ("SECRET", "SAST", "SCA")
    assert "path" in f0
