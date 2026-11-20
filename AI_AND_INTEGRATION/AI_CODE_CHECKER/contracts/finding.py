"""Canonical SecurityFinding v1.0 contract.

Версия контракта — в contracts.version.CONTRACT_VERSION.
Отдельного поля версии в payload нет: добавление поля сломало бы
strict-потребителей (extra="forbid").
"""

from pydantic import ValidationError

from schemas.ai import SecurityFinding

MAX_FINDINGS_PER_CALL = 32
MAX_BATCH_BYTES = 65536


class ContractError(RuntimeError):
    """Нарушение canonical-контракта.

    Не является AIServiceError: сервисный слой сам транслирует эту ошибку
    в AIServiceError, сохраняя обратную совместимость публичного API.
    """


def validate_findings(raw: object) -> list[SecurityFinding]:
    """Проверить сырые данные по canonical SecurityFinding v1.0.

    Возвращает список SecurityFinding. Не мутирует вход.
    Ошибка входа — ContractError (без сети, без провайдера).
    """
    if not isinstance(raw, list):
        raise ContractError("findings должен быть списком объектов.")
    if len(raw) > MAX_FINDINGS_PER_CALL:
        raise ContractError(
            f"Не более {MAX_FINDINGS_PER_CALL} findings за запрос; "
            "разделите отчёт на пакеты."
        )
    parsed: list[SecurityFinding] = []
    for index, item in enumerate(raw):
        try:
            parsed.append(SecurityFinding.model_validate(item))
        except ValidationError:
            raise ContractError(
                f"Finding #{index} не соответствует схеме SecurityFinding."
            ) from None
    total = sum(len(f.model_dump_json().encode()) for f in parsed)
    if total > MAX_BATCH_BYTES:
        raise ContractError(
            f"Пакет findings превышает {MAX_BATCH_BYTES} байт."
        )
    return parsed