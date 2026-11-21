"""Phase 6 security tests: API/WS auth, ZIP bomb/symlink/slip, SSRF/DNS-pinning, Fernet persistence."""

from __future__ import annotations

import asyncio
import io
import logging
import socket
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.config import get_settings
from app.core.crypto import decrypt, encrypt, reset_fernet_cache
from app.core.db import get_engine, init_db
from app.core.logging import RedactingFilter
from app.main import app
from app.nodes.notify.webhook import _resolve_and_pin
from app.nodes.source.upload_zip import safe_extract


@pytest.fixture()
def secured_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/sec6.db")
    monkeypatch.setenv("WORKFLOW_ACCESS_TOKEN", "demo-wf-secret-123")
    monkeypatch.setenv("CI_TOKEN", "demo-ci-secret-456")
    monkeypatch.setenv("APP_SECRET_KEY_FILE", str(tmp_path / "persist.key"))
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    reset_fernet_cache()
    get_settings.cache_clear()
    settings = get_settings()
    settings.runs_dir = tmp_path / "runs"
    settings.upload_dir = tmp_path / "uploads"
    settings.runs_dir.mkdir()
    settings.upload_dir.mkdir()
    SQLModel.metadata.drop_all(get_engine())
    init_db()
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()
    reset_fernet_cache()


def test_api_ws_ci_and_credentials_access_control(secured_client: TestClient):
    # Unauthenticated API requests rejected
    assert secured_client.get("/api/workflows").status_code == 401
    assert secured_client.get("/api/credentials").status_code == 401
    assert secured_client.get("/api/ci/status").status_code == 401

    # Valid X-Workflow-Token grants API access; credentials never return plaintext
    headers = {"X-Workflow-Token": "demo-wf-secret-123"}
    assert secured_client.get("/api/workflows", headers=headers).status_code == 200
    c_resp = secured_client.post(
        "/api/credentials",
        headers=headers,
        json={"name": "bot", "kind": "telegram", "value": "123456789:AAFakeSecretBotToken999"},
    )
    assert c_resp.status_code == 200
    assert "AAFakeSecretBotToken999" not in c_resp.text
    assert c_resp.json()["value_preview"].endswith("n999")

    # CI upload accepted with X-CI-Token
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "ok")
    assert (
        secured_client.post(
            "/api/uploads",
            headers={"X-CI-Token": "demo-ci-secret-456"},
            files={"file": ("x.zip", buf.getvalue(), "application/zip")},
        ).status_code
        == 200
    )

    # WebSocket rejects missing auth subprotocol, accepts valid auth.<token>
    with pytest.raises(Exception):
        with secured_client.websocket_connect("/ws/runs/nonexistent"):
            pass
    with secured_client.websocket_connect(
        "/ws/runs/nonexistent", subprotocols=["florabyte", "auth.demo-wf-secret-123"]
    ) as ws:
        assert ws is not None


def test_zip_symlink_and_bomb_rejected(tmp_path: Path):
    # Symlink rejection
    buf_sym = io.BytesIO()
    with zipfile.ZipFile(buf_sym, "w") as zf:
        info = zipfile.ZipInfo("link.txt")
        info.create_system = 3
        info.external_attr = (0o120777) << 16
        zf.writestr(info, "/etc/passwd")
    buf_sym.seek(0)
    with zipfile.ZipFile(buf_sym, "r") as zf:
        with pytest.raises(ValueError, match="Symlinks not allowed"):
            safe_extract(zf, tmp_path / "sym")

    # Excessive compression ratio zip-bomb check
    buf_bomb = io.BytesIO()
    with zipfile.ZipFile(buf_bomb, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", b"A" * (2 * 1024 * 1024))
    buf_bomb.seek(0)
    with zipfile.ZipFile(buf_bomb, "r") as zf:
        with pytest.raises(ValueError, match="Zip bomb"):
            safe_extract(zf, tmp_path / "bomb")


@pytest.mark.asyncio
async def test_webhook_ssrf_metadata_and_dns_pinning(monkeypatch):
    monkeypatch.setenv("WEBHOOK_HOST_ALLOWLIST", "")
    get_settings.cache_clear()

    # Embedded creds rejected
    with pytest.raises(ValueError, match="embedded credentials"):
        await _resolve_and_pin("https://user:pass@example.com/hook")

    # Metadata / loopback / private IPs blocked
    for target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/hook",
        "http://10.0.0.5/hook",
    ):
        with pytest.raises(PermissionError):
            await _resolve_and_pin(target)

    # DNS pinning returns pinned IP URL + Host + sni_hostname
    fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=fake_addr)):
        pinned_url, host_hdr, sni_host = await _resolve_and_pin("https://hooks.example.com/notify")
    assert pinned_url == "https://93.184.216.34/notify"
    assert host_hdr == "hooks.example.com"
    assert sni_host == "hooks.example.com"


def test_fernet_persistent_key_file_and_log_redaction(tmp_path, monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_SECRET_KEY_FILE", str(tmp_path / "keys" / "florabyte.key"))
    reset_fernet_cache()
    ct = encrypt("persisted-secret-xyz")
    # Simulate process restart
    reset_fernet_cache()
    assert decrypt(ct) == "persisted-secret-xyz"
    assert (tmp_path / "keys" / "florabyte.key").is_file()

    rec = logging.LogRecord("test", logging.INFO, __file__, 1, "token=%s", ("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",), None)
    assert RedactingFilter().filter(rec)
    assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in str(rec.args)
