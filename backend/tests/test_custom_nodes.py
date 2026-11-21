"""Tests for user-defined Custom Nodes ('Мои ноды'): storage, versioning, sandbox isolation, engine integration, and ACL."""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

import app.core.db as db_mod
from app.config import get_settings
from app.core.crypto import reset_fernet_cache
from app.main import app
from app.nodes.custom_sandbox import execute_custom_node_sandboxed, validate_custom_node_code
from tests.conftest import authenticate_client


@pytest.fixture()
def cn_client(tmp_path, monkeypatch):
    db_file = tmp_path / "custom_nodes.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("WORKFLOW_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("APP_SECRET_KEY_FILE", str(tmp_path / "fernet.key"))
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("TEST_PARENT_SECRET_ENV", "TOP_SECRET_MUST_NOT_LEAK")
    reset_fernet_cache()
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
        auth = authenticate_client(client, email="creator@florabyte.local")
        yield client, auth["user"], tmp_path
    db_mod._engine = None
    get_settings.cache_clear()
    reset_fernet_cache()


def _sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/settings.gradle.kts", 'rootProject.name = "cn"\n')
        zf.writestr("proj/src/main/kotlin/App.kt", 'val apiSecret = "custom_node_secret_999"\n')
    return buf.getvalue()


def test_custom_node_crud_validation_versioning_and_persistence(cn_client):
    client, _, _ = cn_client

    # 1. Syntax & security code validation
    bad_syntax = client.post("/api/custom-nodes/validate", json={"code": "async def run(ctx, inputs, params):\n    return {"})
    assert bad_syntax.status_code == 200
    assert bad_syntax.json()["ok"] is False

    good_code_v1 = """async def run(ctx, inputs, params):
    findings = inputs.get("findings", [])
    threshold = int(params.get("min_count", 1))
    return {"result": {"total": len(findings), "alert": len(findings) >= threshold}}
"""
    ok_res = client.post("/api/custom-nodes/validate", json={"code": good_code_v1})
    assert ok_res.status_code == 200
    assert ok_res.json()["ok"] is True
    assert ok_res.json()["is_async"] is True

    # 2. Create custom node as active
    r_create = client.post(
        "/api/custom-nodes",
        json={
            "name": "Мой анализатор",
            "description": "Считает количество находок",
            "group": "custom",
            "code": good_code_v1,
            "inputs": [{"name": "findings", "kind": "Findings"}],
            "outputs": [{"name": "result", "kind": "Any"}],
            "params_schema": {"type": "object", "properties": {"min_count": {"type": "integer", "default": 1}}},
            "status": "active",
            "visibility": "private",
        },
    )
    assert r_create.status_code == 200, r_create.text
    node_v1 = r_create.json()
    node_id = node_v1["id"]
    node_type = node_v1["node_type"]
    assert node_v1["version"] == 1
    assert node_type.startswith("custom.")

    # Appears in /api/node-types alongside standard nodes
    catalog = client.get("/api/node-types").json()["nodes"]
    assert any(n["type"] == node_type and n.get("is_custom") is True and n.get("version") == 1 for n in catalog)
    assert any(n["type"] == "scanner.secrets" for n in catalog)

    # 3. Test-run in isolated sandbox
    r_tr = client.post(
        f"/api/custom-nodes/{node_id}/test-run",
        json={"inputs": {"findings": [{"severity": "HIGH"}]}, "params": {"min_count": 1}},
    )
    assert r_tr.status_code == 200
    assert r_tr.json()["ok"] is True
    assert r_tr.json()["output"]["result"] == {"total": 1, "alert": True}

    # 4. Update code -> version bumps to v2 and v1 snapshot preserved in versions history
    good_code_v2 = """async def run(ctx, inputs, params):
    findings = inputs.get("findings", [])
    return {"result": {"total": len(findings), "v": 2}}
"""
    r_upd = client.put(f"/api/custom-nodes/{node_id}", json={"code": good_code_v2})
    assert r_upd.status_code == 200
    assert r_upd.json()["version"] == 2
    assert [v["version"] for v in r_upd.json()["versions"]] == [2, 1]

    # 5. Duplicate creates independent v1 draft copy
    r_dup = client.post(f"/api/custom-nodes/{node_id}/duplicate")
    assert r_dup.status_code == 200
    assert r_dup.json()["status"] == "draft"
    assert r_dup.json()["version"] == 1
    assert r_dup.json()["node_type"] != node_type

    # 6. Simulate logout + backend restart + re-login: node persists in DB and palette
    db_mod._engine = None
    with TestClient(app) as restarted:
        authenticate_client(restarted, email="creator@florabyte.local")
        listed = restarted.get("/api/custom-nodes").json()["custom_nodes"]
        assert any(n["id"] == node_id and n["version"] == 2 for n in listed)
        pal = restarted.get("/api/node-types").json()["nodes"]
        assert any(n["type"] == node_type and n["version"] == 2 for n in pal)


def test_custom_node_in_workflow_execution_port_check_and_pinned_version(cn_client):
    client, _, _ = cn_client

    # Custom node acting as a custom Findings transformer/filter
    filter_code = """async def run(ctx, inputs, params):
    findings = inputs.get("findings", [])
    # tag description with node version for verification
    out = []
    for f in findings:
        item = dict(f)
        item["description"] = f"[v{ctx.get('custom_node_version')}] " + str(item.get("description") or "")
        out.append(item)
    return {"findings": out}
"""
    cn = client.post(
        "/api/custom-nodes",
        json={
            "name": "Custom Tagger",
            "group": "custom",
            "code": filter_code,
            "inputs": [{"name": "findings", "kind": "Findings"}],
            "outputs": [{"name": "findings", "kind": "Findings"}],
            "status": "active",
            "visibility": "private",
        },
    ).json()
    cn_id = cn["id"]
    cn_type = cn["node_type"]

    up_id = client.post("/api/uploads", files={"file": ("app.zip", _sample_zip(), "application/zip")}).json()["upload_id"]

    # Port compatibility check: connecting Workspace -> Findings input must fail
    bad_wf = client.post(
        "/api/workflows",
        json={
            "name": "bad-port-custom",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.manual", "params": {}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
                    {"id": "c1", "type": cn_type, "params": {}},
                ],
                "edges": [
                    {"id": "e1", "source": "t1", "target": "s1"},
                    {"id": "e2", "source": "s1", "sourceHandle": "workspace", "target": "c1", "targetHandle": "findings"},
                ],
            },
        },
    )
    assert bad_wf.status_code == 400
    assert "Incompatible ports" in bad_wf.text

    # Valid workflow: trigger -> upload -> scanner.secrets -> custom node -> findings.export
    wf_id = client.post(
        "/api/workflows",
        json={
            "name": "wf-with-custom-node",
            "graph_json": {
                "nodes": [
                    {"id": "t1", "type": "trigger.manual", "params": {}},
                    {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": up_id}},
                    {"id": "sc1", "type": "scanner.secrets", "params": {}},
                    {"id": "c1", "type": cn_type, "params": {"_custom_version": 1}},
                    {"id": "e1", "type": "findings.export", "params": {}},
                ],
                "edges": [
                    {"id": "ed1", "source": "t1", "target": "s1"},
                    {"id": "ed2", "source": "s1", "target": "sc1"},
                    {"id": "ed3", "source": "sc1", "sourceHandle": "findings", "target": "c1", "targetHandle": "findings"},
                    {"id": "ed4", "source": "c1", "sourceHandle": "findings", "target": "e1", "targetHandle": "findings"},
                ],
            },
        },
    ).json()["id"]

    run1_id = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    r1 = client.get(f"/api/runs/{run1_id}").json()
    assert r1["status"] == "success"
    assert r1["summary"]["custom_nodes"]["c1"]["version"] == 1
    rep1 = client.get(f"/api/runs/{run1_id}/report.json").json()
    assert len(rep1["findings"]) == 1
    assert rep1["findings"][0]["description"].startswith("[v1]")

    # Update custom node to v2: pinned run with _custom_version=1 STILL runs v1 snapshot!
    client.put(
        f"/api/custom-nodes/{cn_id}",
        json={"code": filter_code.replace('"[v{ctx.get(\'custom_node_version\')}] "', '"[UPDATED_V2] "')},
    )
    run_pinned = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()["run_id"]
    rep_pinned = client.get(f"/api/runs/{run_pinned}/report.json").json()
    assert rep_pinned["findings"][0]["description"].startswith("[v1]")


def test_custom_node_access_control_private_and_public(cn_client):
    client_a, _, _ = cn_client
    priv = client_a.post(
        "/api/custom-nodes",
        json={"name": "Private Node", "status": "active", "visibility": "private"},
    ).json()
    pub = client_a.post(
        "/api/custom-nodes",
        json={"name": "Public Node", "status": "active", "visibility": "public"},
    ).json()

    with TestClient(app) as client_b:
        authenticate_client(client_b, email="other_user@florabyte.local")
        b_list_ids = {n["id"] for n in client_b.get("/api/custom-nodes").json()["custom_nodes"]}
        assert priv["id"] not in b_list_ids
        assert pub["id"] in b_list_ids

        b_palette = {n["type"] for n in client_b.get("/api/node-types").json()["nodes"]}
        assert priv["node_type"] not in b_palette
        assert pub["node_type"] in b_palette

        # Cannot view/edit/delete A's private node, and cannot edit/delete A's public node
        assert client_b.get(f"/api/custom-nodes/{priv['id']}").status_code == 403
        assert client_b.put(f"/api/custom-nodes/{priv['id']}", json={"name": "hacked"}).status_code == 403
        assert client_b.put(f"/api/custom-nodes/{pub['id']}", json={"name": "hacked"}).status_code == 403
        assert client_b.delete(f"/api/custom-nodes/{pub['id']}").status_code == 403

        # CAN duplicate A's public node to B's own workspace
        dup_b = client_b.post(f"/api/custom-nodes/{pub['id']}/duplicate")
        assert dup_b.status_code == 200
        assert dup_b.json()["is_owner"] is True


@pytest.mark.asyncio
async def test_custom_node_sandbox_blocks_malicious_code_env_and_infinite_loops():
    malicious_samples = [
        "import os\nasync def run(ctx, inputs, params):\n    return {'result': dict(os.environ)}",
        "import subprocess\nasync def run(ctx, inputs, params):\n    return {'result': 1}",
        "import socket\nasync def run(ctx, inputs, params):\n    return {'result': 1}",
        "async def run(ctx, inputs, params):\n    return {'result': open('/etc/passwd').read()}",
        "async def run(ctx, inputs, params):\n    return {'result': ().__class__.__base__.__subclasses__()}",
        "async def run(ctx, inputs, params):\n    return {'result': eval('1+1')}",
    ]
    for code in malicious_samples:
        v = validate_custom_node_code(code)
        assert v.ok is False, f"Expected rejection for: {code}"
        with pytest.raises(RuntimeError):
            await execute_custom_node_sandboxed(code=code, ctx_info={}, inputs={}, params={})

    # Timeout protection on infinite loop
    inf_code = "def run(ctx, inputs, params):\n    while True:\n        pass\n    return {'result': 1}"
    with pytest.raises(RuntimeError, match="лимит времени"):
        await execute_custom_node_sandboxed(code=inf_code, ctx_info={}, inputs={}, params={}, timeout_sec=0.8)

    # Even valid code executes in an isolated subprocess with empty env and safe stdlib only
    safe_code = """import json, hashlib
async def run(ctx, inputs, params):
    digest = hashlib.sha256(json.dumps(inputs).encode()).hexdigest()[:12]
    return {"result": {"digest": digest}}
"""
    res, _ = await execute_custom_node_sandboxed(
        code=safe_code,
        ctx_info={"run_id": "r1"},
        inputs={"x": 1},
        params={},
        outputs_spec=[{"name": "result", "kind": "Any"}],
    )
    assert len(res["result"]["digest"]) == 12
