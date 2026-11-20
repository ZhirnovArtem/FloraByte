"""Logging with automatic secret redaction."""

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
            record.args = tuple(
                redact_text(str(a), self.known_secrets) if isinstance(a, str) else a
                for a in record.args
            )
        return True


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        handler.addFilter(RedactingFilter())
        root.addHandler(handler)
    root.setLevel(level)
