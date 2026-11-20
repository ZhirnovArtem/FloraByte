"""FIXTURE adapter for Scanner 2.

Это НЕ реальный адаптер. Формат вывода Scanner 2 неизвестен.
Используется только для тестов и демо до получения обезличенного
реального примера. Вход обязан содержать "_fixture": true.

Отличие от Scanner 1 (искусственное, только для проверки гибкости
адаптеров): вложенный location, severity в любом регистре (нормализуется
в верхний), другие имена полей.

Реальный адаптер заменит этот файл целиком.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from contracts.adapters import AdapterError
from contracts.finding import ContractError, validate_findings


class Scanner2FixtureAdapter:
    name = "scanner2_fixture"

    def normalize(self, raw: Any) -> list[dict]:
        if not isinstance(raw, dict):
            raise AdapterError("Scanner 2 fixture: ожидался JSON-объект.")
        if raw.get("_fixture") is not True:
            raise AdapterError(
                'Scanner 2 fixture: отсутствует маркер "_fixture": true. '
                "Реальные данные через этот адаптер не обрабатываются."
            )
        results = raw.get("results")
        if not isinstance(results, list):
            raise AdapterError("Scanner 2 fixture: отсутствует массив results.")

        normalized: list[dict] = []
        for index, item in enumerate(results):
            if not isinstance(item, dict):
                raise AdapterError(
                    f"Scanner 2 fixture: results[{index}] не объект."
                )
            location = item.get("location")
            if not isinstance(location, dict):
                raise AdapterError(
                    f"Scanner 2 fixture: results[{index}].location не объект."
                )
            normalized.append(
                {
                    "rule_id": _require_str(item, "check_id", index),
                    "file": _require_str(
                        location, "file", index, where="location"
                    ),
                    "line": _optional_line(location, index),
                    "severity": _require_str(item, "severity", index).upper(),
                    "message": _require_str(item, "description", index),
                    "evidence": _optional_str(item, "context"),
                }
            )

        try:
            validate_findings(normalized)
        except ContractError as exc:
            raise AdapterError(
                f"Scanner 2 fixture: результат не соответствует canonical v1.0: {exc}"
            ) from None
        return normalized


def _require_str(
    obj: dict, key: str, index: int, *, where: str = "results"
) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(
            f"Scanner 2 fixture: {where}[{index}].{key} "
            "должен быть непустой строкой."
        )
    return value


def _optional_str(obj: dict, key: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterError(
            f"Scanner 2 fixture: {key} должен быть строкой или null."
        )
    return value


def _optional_line(location: dict, index: int) -> int | None:
    value = location.get("line")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AdapterError(
            f"Scanner 2 fixture: results[{index}].location.line "
            "должен быть int >= 1 или null."
        )
    return value


def load_fixture(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))