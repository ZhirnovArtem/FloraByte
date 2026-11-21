"""Logging with rotating file persistence and automatic secret redaction across all handlers."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import get_settings
from app.core.masking import redact_text

_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


class RedactingFilter(logging.Filter):
    def __init__(self, known_secrets: list[str] | None = None):
        super().__init__()
        self.known_secrets = known_secrets or []

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg, self.known_secrets)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_text(str(v), self.known_secrets) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    redact_text(str(a), self.known_secrets) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


class RedactingFormatter(logging.Formatter):
    """Formatter that also redacts secrets inside formatted exception tracebacks."""

    def __init__(self, fmt: str = _LOG_FORMAT, known_secrets: list[str] | None = None):
        super().__init__(fmt)
        self.known_secrets = known_secrets or []

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return redact_text(rendered, self.known_secrets)


def _safe_filename(name: str, default: str) -> str:
    cleaned = Path(name or default).name.strip()
    return cleaned or default


def get_log_paths() -> tuple[Path, Path]:
    """Resolve (app_log_path, error_log_path) and ensure the directory is writable."""
    settings = get_settings()
    env_dir = os.environ.get("LOG_DIR", "").strip()
    target_dir = Path(env_dir) if env_dir else Path(settings.log_dir)

    app_name = _safe_filename(os.environ.get("LOG_FILE_NAME", "") or settings.log_file_name, "florabyte.log")
    err_name = _safe_filename(
        os.environ.get("ERROR_LOG_FILE_NAME", "") or settings.error_log_file_name, "errors.log"
    )

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        probe = target_dir / ".write_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError:
        target_dir = Path(tempfile.gettempdir()) / "florabyte_logs"
        target_dir.mkdir(parents=True, exist_ok=True)

    return target_dir / app_name, target_dir / err_name


def _remove_managed_file_handlers(root: logging.Logger) -> None:
    for h in list(root.handlers):
        if getattr(h, "_florabyte_managed", False):
            root.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass


def setup_logging(level: int = logging.INFO) -> tuple[Path, Path]:
    settings = get_settings()
    app_log_path, err_log_path = get_log_paths()
    filt = RedactingFilter()
    formatter = RedactingFormatter(_LOG_FORMAT)

    root = logging.getLogger()

    has_stdout = any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in root.handlers
    )
    if not has_stdout:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(level)
        stdout_handler.setFormatter(formatter)
        root.addHandler(stdout_handler)

    _remove_managed_file_handlers(root)

    max_bytes = max(64 * 1024, int(os.environ.get("LOG_MAX_BYTES", settings.log_max_bytes)))
    backup_count = max(1, int(os.environ.get("LOG_BACKUP_COUNT", settings.log_backup_count)))

    app_file_handler = RotatingFileHandler(
        app_log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    app_file_handler.setLevel(level)
    app_file_handler.setFormatter(formatter)
    app_file_handler.addFilter(filt)
    setattr(app_file_handler, "_florabyte_managed", True)
    setattr(app_file_handler, "_florabyte_kind", "app")
    root.addHandler(app_file_handler)

    err_file_handler = RotatingFileHandler(
        err_log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    err_file_handler.setLevel(logging.WARNING)
    err_file_handler.setFormatter(formatter)
    err_file_handler.addFilter(filt)
    setattr(err_file_handler, "_florabyte_managed", True)
    setattr(err_file_handler, "_florabyte_kind", "errors")
    root.addHandler(err_file_handler)

    for handler in root.handlers:
        handler.setFormatter(formatter)
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(filt)

    for name in ("httpx", "httpcore", "uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in lg.filters):
            lg.addFilter(filt)
        lg.propagate = True

    root.setLevel(level)
    return app_log_path, err_log_path


def tail_log_file(kind: str = "errors", lines: int = 200) -> dict:
    app_log_path, err_log_path = get_log_paths()
    selected = err_log_path if kind == "errors" else app_log_path
    limit = max(1, min(int(lines), 1000))
    if not selected.exists():
        return {
            "kind": "errors" if kind == "errors" else "app",
            "file_name": selected.name,
            "path": str(selected),
            "entries": [],
            "total_returned": 0,
        }
    with selected.open("r", encoding="utf-8", errors="replace") as fh:
        buf = deque((line.rstrip("\r\n") for line in fh), maxlen=limit)
    entries = list(buf)
    return {
        "kind": "errors" if kind == "errors" else "app",
        "file_name": selected.name,
        "path": str(selected),
        "entries": entries,
        "total_returned": len(entries),
    }
