from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def downgrade(self) -> "Severity":
        return {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW, Severity.LOW: Severity.LOW}[self]

    def upgrade(self) -> "Severity":
        return {Severity.LOW: Severity.MEDIUM, Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.CRITICAL, Severity.CRITICAL: Severity.CRITICAL}[self]

@dataclass
class Finding:
    id: str
    scanner: str
    type: str
    severity: Severity
    file: str
    line: int
    evidence: str
    description: str
    recommendation: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "scanner": self.scanner, "type": self.type,
            "severity": self.severity.name, "file": self.file, "line": self.line,
            "evidence": self.evidence, "description": self.description,
            "recommendation": self.recommendation, "metadata": self.metadata,
        }

@dataclass
class SourceFile:
    path: str
    content: str
    _EXCLUDED = ("/build/", "/.git/", "/node_modules/", "/.gradle/")
    _BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".zip", ".jar", ".class", ".bin")

    @property
    def is_text(self) -> bool:
        return not self.path.lower().endswith(self._BINARY_EXT)

    def is_scannable(self) -> bool:
        return not any(part in self.path for part in self._EXCLUDED)

@dataclass
class ScanInput:
    repo_path: str
    files: list[SourceFile]
    config: dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanStats:
    files_scanned: int = 0
    rules_applied: int = 0
    duration_ms: int = 0

@dataclass
class ScanResult:
    scanner_id: str
    findings: list[Finding]
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "findings": [f.to_dict() for f in self.findings],
            "stats": {"files_scanned": self.stats.files_scanned, "rules_applied": self.stats.rules_applied, "duration_ms": self.stats.duration_ms},
        }