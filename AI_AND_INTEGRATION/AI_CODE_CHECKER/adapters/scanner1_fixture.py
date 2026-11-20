"""FIXTURE adapter for Scanner 1.

Это НЕ реальный адаптер. Формат вывода Scanner 1 неизвестен.
Используется только для тестов и демо до получения обезличенного
реального примера. Вход обязан содержать "_fixture": true.

Реальный адаптер заменит этот файл целиком.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from contracts.adapters import AdapterError
from contracts.finding import ContractError, validate_findings


class Scanner1FixtureAdapter:
    name = "scanner1_fixture"

    def normalize(self, raw: Any) -> list[dict]:
        if not isinstance(raw, dict):
            raise AdapterError("Scanner 1 fixture: ожидался JSON-объект.")
        if raw.get("_fixture") is not True:
            raise AdapterError(
                'Scanner 1 fixture: отсутствует маркер "_fixture": true. '
                "Реальные данные через этот адаптер не обрабатываются."
            )
        issues = raw.get("issues")
        if not isinstance(issues, list):
            raise AdapterError("Scanner 1 fixture: отсутствует массив issues.")

        normalized: list[dict] = []
        for index, issue in enumerate(issues):
            if not isinstance(issue, dict):
                raise AdapterError(
                    f"Scanner 1 fixture: issues[{index}] не объект."
                )
            normalized.append(
                {
                    "rule_id": _require_str(issue, "id", index),
                    "file": _require_str(issue, "path", index),
                    "line": _optional_line(issue, index),
                    "severity": _require_str(issue, "level", index),
                    "message": _require_str(issue, "title", index),
                    "evidence": _optional_str(issue, "snippet"),
                }
            )

        try:
            validate_findings(normalized)
        except ContractError as exc:
            raise AdapterError(
                f"Scanner 1 fixture: результат не соответствует canonical v1.0: {exc}"
            ) from None
        return normalized


def _require_str(obj: dict, key: str, index: int) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(
            f"Scanner 1 fixture: issues[{index}].{key} должен быть непустой строкой."
        )
    return value


def _optional_str(obj: dict, key: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterError(
            f"Scanner 1 fixture: {key} должен быть строкой или null."
        )
    return value


def _optional_line(obj: dict, index: int) -> int | None:
    value = obj.get("line")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AdapterError(
            f"Scanner 1 fixture: issues[{index}].line должен быть int >= 1 или null."
        )
    return value


def load_fixture(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))