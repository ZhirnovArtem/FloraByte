"""Tests for persistent rotating file logging, error logs, secret redaction, and /api/logs."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.logging import setup_logging
from app.main import app


def test_file_logging_splits_info_and_errors_and_redacts_secrets(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "site_logs"
    monkeypatch.setenv("LOG_DIR", str(log_dir))
    app_log, err_log = setup_logging()

    lg = logging.getLogger("app.test_logger")
    lg.info("Normal site event ok")
    lg.warning("Warning with token ghp_1234567890abcdef1234567890abcdef1234")
    try:
        raise RuntimeError("Boom with OpenAI key sk-abcdefghijklmnopqrstuvwxyz123456")
    except RuntimeError:
        lg.exception("Unhandled failure occurred")

    for h in logging.getLogger().handlers:
        h.flush()

    assert app_log.exists()
    assert err_log.exists()

    app_text = app_log.read_text(encoding="utf-8")
    err_text = err_log.read_text(encoding="utf-8")

    assert "Normal site event ok" in app_text
    assert "Normal site event ok" not in err_text

    assert "Warning with token" in err_text
    assert "Unhandled failure occurred" in err_text
    assert "RuntimeError: Boom with OpenAI key" in err_text

    assert "ghp_1234567890abcdef" not in app_text
    assert "ghp_1234567890abcdef" not in err_text
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in app_text
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in err_text


def test_http_errors_and_client_error_endpoint_persisted_and_viewable(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "web_logs"
    monkeypatch.setenv("LOG_DIR", str(log_dir))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'logtest.db'}")
    monkeypatch.setenv("APP_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    from app.core import db as db_mod

    db_mod._engine = None

    with TestClient(app) as client:
        # 1. Unauthenticated access to GET /api/logs must be rejected
        unauth = client.get("/api/logs?kind=errors")
        assert unauth.status_code == 401

        # 2. Browser/client error reporting works and writes to errors.log with redaction
        cr = client.post(
            "/api/logs/client-error",
            json={
                "level": "error",
                "source": "window.onerror",
                "message": "TypeError: cannot read x; leaked token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "url": "/editor",
                "status": 500,
                "stack": "at WorkflowEditor.tsx:42\nline2",
            },
        )
        assert cr.status_code == 200
        assert cr.json()["ok"] is True

        # 3. Register and log in, trigger a 404 API error, and inspect /api/logs + download
        reg = client.post(
            "/api/auth/register",
            json={"email": "logviewer@example.com", "password": "StrongPassword123!"},
        )
        assert reg.status_code == 200

        nf = client.get("/api/non-existent-route-check")
        assert nf.status_code == 404

        logs_res = client.get("/api/logs?kind=errors&lines=200")
        assert logs_res.status_code == 200
        body = logs_res.json()
        joined = "\n".join(body["entries"])
        assert "[window.onerror]" in joined
        assert "TypeError: cannot read x" in joined
        assert "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in joined
        assert "/api/non-existent-route-check -> 404" in joined

        dl = client.get("/api/logs/download?kind=errors")
        assert dl.status_code == 200
        assert "attachment;" in dl.headers.get("content-disposition", "")
        assert "TypeError: cannot read x" in dl.text

    app_log = log_dir / "florabyte.log"
    err_log = log_dir / "errors.log"
    assert app_log.exists()
    assert err_log.exists()
