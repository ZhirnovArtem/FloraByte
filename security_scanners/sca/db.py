from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Vulnerability:
    id: str
    packageName: str
    severity: str
    affected: str
    description: str
    recommendation: str
    exploitAvailable: bool = False

class VulnerabilityDb:
    @staticmethod
    def load_from_resource(name: str = "vulnerabilities.json") -> list[Vulnerability]:
        file_path = Path(__file__).parent / name
        if not file_path.exists():
            raise FileNotFoundError(f"Файл {name} не найден по пути {file_path}")
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return [Vulnerability(**item) for item in data]