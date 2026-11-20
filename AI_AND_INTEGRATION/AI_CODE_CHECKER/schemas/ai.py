from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityFinding(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", hide_input_in_errors=True
    )

    rule_id: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: Optional[int] = Field(default=None, ge=1)
    severity: str = Field(min_length=1)
    message: str = Field(min_length=1)
    evidence: Optional[str] = None

    @field_validator("rule_id", "file", "severity", "message")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("пустое поле")
        return value


class AIAnalysis(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", hide_input_in_errors=True
    )

    rule_id: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: Optional[int]
    severity: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    risk: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)

    @field_validator("explanation", "risk", "recommendation")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("пустое текстовое поле")
        return text


class AIReport(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", hide_input_in_errors=True
    )

    status: Literal["ok"]
    summary: str = Field(min_length=1)
    findings: list[AIAnalysis]

    @field_validator("status", "summary")
    @classmethod
    def reject_blank_report_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("пустое поле отчёта")
        return text