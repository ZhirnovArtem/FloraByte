"""Secret masking utilities. Never expose raw secrets in findings, logs, API or LLM payloads."""

from __future__ import annotations

import re
from typing import Pattern

# Common patterns that look like secrets (used for log redaction and evidence masking)
_TOKEN_PATTERNS: list[Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd|bearer|authorization)\s*[:=]\s*['\"]?([^\s'\"\\]{8,})"),
    re.compile(r"(?i)bearer\s+([a-z0-9\-_\.]{20,})"),
    re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"[0-9]{8,10}:[A-Za-z0-9_\-]{30,}"),  # Telegram-like
]


def mask_secret(value: str | None, keep_last: int = 4) -> str:
    """Mask a secret value. Keeps last `keep_last` characters if long enough."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= keep_last + 2:
        return "****"
    return "*" * (len(s) - keep_last) + s[-keep_last:]


def mask_evidence(text: str | None, max_len: int = 120) -> str | None:
    """Return a short, redacted evidence snippet safe for logs / LLM / API."""
    if not text:
        return None
    redacted = text
    for pat in _TOKEN_PATTERNS:
        redacted = pat.sub(lambda m: m.group(0)[: m.start(m.lastindex or 0) - m.start()] + "****", redacted)
    # generic long token-like strings
    redacted = re.sub(r"[A-Za-z0-9_\-]{24,}", lambda m: mask_secret(m.group(0)), redacted)
    if len(redacted) > max_len:
        redacted = redacted[: max_len - 3] + "..."
    return redacted


def redact_text(text: str, known_secrets: list[str] | None = None) -> str:
    """Redact known secrets and token-like patterns from arbitrary text (logs, messages)."""
    if not text:
        return text
    out = text
    if known_secrets:
        for sec in known_secrets:
            if sec and len(sec) >= 6:
                out = out.replace(sec, mask_secret(sec))
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(lambda m: (m.group(0)[: max(0, m.start(m.lastindex or 0) - m.start())] + "****") if m.lastindex else "****", out)
    return out
