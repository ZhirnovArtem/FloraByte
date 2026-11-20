"""Defensive scrubbing секретов перед отправкой провайдеру.

Эвристика. Не гарантирует обнаружение всех секретов и может давать
false positives. Дополняет system instruction и политику передачи
данных, но не заменяет их.

Гарантии:
  - оригинальный вход не мутируется;
  - возвращается новая структура;
  - набор правил расширяется через параметр `rules`.

Не гарантирует:
  - полноту обнаружения (новые форматы токенов, кастомные схемы);
  - отсутствие false positives;
  - отсутствие секретов в логах/исключениях (это ответственность
    вызывающего кода: scrubber не пишет ничего никуда).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class ScrubRule:
    name: str
    pattern: re.Pattern[str]
    replacement: str = REDACTED


DEFAULT_RULES: tuple[ScrubRule, ...] = (
    ScrubRule("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    ScrubRule("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ScrubRule("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ScrubRule("openai_sk", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ScrubRule(
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    ScrubRule(
        "pem_private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    ScrubRule(
        "password_assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd)(\s*[:=]\s*)"
            r"(\"[^\"]{2,}\"|'[^']{2,}'|[^\s,;'\"<>]{2,})"
        ),
        replacement=r"\1\2[REDACTED]",
    ),
    ScrubRule(
        "token_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|authorization)(\s*[:=]\s*)"
            r"(\"[^\"]{6,}\"|'[^']{6,}'|[^\s,;'\"<>]{6,})"
        ),
        replacement=r"\1\2[REDACTED]",
    ),
)


def scrub_text(text: str, rules: Iterable[ScrubRule] = DEFAULT_RULES) -> str:
    """Применить правила к строке. Не-строки и пустая строка — как есть."""
    if not isinstance(text, str) or not text:
        return text
    result = text
    for rule in rules:
        result = rule.pattern.sub(rule.replacement, result)
    return result


def scrub_value(value: Any, rules: Iterable[ScrubRule] = DEFAULT_RULES) -> Any:
    """Рекурсивно очистить строки в произвольной структуре.

    Возвращает новую структуру; оригинал не мутируется.
    """
    if isinstance(value, str):
        return scrub_text(value, rules)
    if isinstance(value, dict):
        return {k: scrub_value(v, rules) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_value(v, rules) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub_value(v, rules) for v in value)
    return value


def scrub_findings(
    findings: list[dict], rules: Iterable[ScrubRule] = DEFAULT_RULES
) -> list[dict]:
    """Очистить список findings для отправки провайдеру.

    Оригинальный список не мутируется; каждый элемент — новый dict.
    """
    return [scrub_value(f, rules) for f in findings]