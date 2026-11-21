"""Logging with automatic secret redaction across app, httpx, and uvicorn loggers."""

from __future__ import annotations

import logging
import sys

from app.core.masking import redact_text


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


def setup_logging(level: int = logging.INFO) -> None:
    filt = RedactingFilter()
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        root.addHandler(handler)
    for handler in root.handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(filt)
    for name in ("httpx", "httpcore", "uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in lg.filters):
            lg.addFilter(filt)
    root.setLevel(level)
