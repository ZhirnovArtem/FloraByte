"""Интерфейс адаптеров сканеров → canonical SecurityFinding v1.0.

Реальные адаптеры появятся только после получения обезличенных
примеров вывода Scanner 1 / Scanner 2. До этого существуют только
fixture-реализации в adapters/ с явной меткой в имени.
"""

from typing import Any, Protocol, runtime_checkable


class AdapterError(RuntimeError):
    """Ошибка нормализации внутри адаптера сканера."""


@runtime_checkable
class ScannerAdapter(Protocol):
    """Нормализует сырой вывод сканера в список dict, валидных по canonical v1.0.

    Контракт адаптера:
      - вход: произвольный сырой вывод сканера;
      - выход: list[dict], проходящий contracts.validate_findings;
      - ошибка: AdapterError (не AIServiceError);
      - не вызывает провайдера, не работает с сетью, не пишет в stdout.
    """

    name: str

    def normalize(self, raw: Any) -> list[dict]:
        ...