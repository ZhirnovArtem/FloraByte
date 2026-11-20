from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Finding(BaseModel):
    """Finding v1. Fields align with project section 8; category/path/class are training-report aliases."""
    model_config = ConfigDict(extra="forbid")
    id: str
    scanner: str = "sast"
    rule_id: str
    title: str
    file: str
    line: int = Field(ge=1)
    column: int = Field(default=1, ge=1)
    severity: Severity
    confidence: Confidence
    cwe: str
    message: str
    evidence: str
    remediation: str
    fingerprint: str
    rationale: str
    schema_version: str = "1.0"

    def training_dict(self) -> dict:
        """Project-specific training JSON projection; does not alter canonical Finding."""
        return {
            "category": "SAST", "path": self.file, "class": self.rule_id,
            "line": self.line, "endLine": self.line,
        }
