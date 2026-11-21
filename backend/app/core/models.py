"""Core domain models: Finding (submission-compatible) and DB models."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import Column, Text
from sqlmodel import Field as SQLField, SQLModel, JSON


# ---------------------------------------------------------------------------
# Finding — must match organisers' submission-format.md
# ---------------------------------------------------------------------------

Category = Literal["SECRET", "SAST", "SCA"]
SeverityLiteral = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # required for export
    category: Category
    path: str  # relative to project root, '/' separators

    # SECRET / SAST
    class_: str | None = Field(None, alias="class")
    line: int | None = None  # >= 1
    endLine: int | None = None  # line <= endLine <= line + 14

    # SCA
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    advisoryId: str | None = None

    # optional common
    severity: SeverityLiteral | None = None
    description: str | None = None  # never contain raw secret
    remediation: str | None = None

    # internal — NOT exported by to_submission()
    id: str = ""
    rule_id: str = ""
    evidence: str | None = None  # already masked
    confidence: float = 1.0

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("path must be non-empty")
        p = str(v).replace("\\", "/")
        if p.startswith("/") or re.search(r"^[A-Za-z]:", p) or ".." in p.split("/") or ":" in p:
            raise ValueError(f"path must be relative, no '..', no drive letters, no colon: {v!r}")
        return p

    @field_validator("line", "endLine", mode="before")
    @classmethod
    def validate_line_int(cls, v: Any) -> int | None:
        if v is None:
            return None
        # Reject bool and non-int before Pydantic coerces strings
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("line/endLine must be int or null")
        if v < 1:
            raise ValueError("line/endLine must be >= 1")
        return v

    @model_validator(mode="after")
    def check_category_fields(self) -> "Finding":
        if self.category in ("SECRET", "SAST"):
            if not self.class_:
                raise ValueError(f"{self.category} requires 'class'")
            if self.line is None:
                raise ValueError(f"{self.category} requires 'line'")
            if self.endLine is not None:
                if self.endLine < self.line:
                    raise ValueError("endLine must be >= line")
                if self.endLine > self.line + 14:
                    raise ValueError("endLine must be <= line + 14")
        if self.category == "SCA":
            for name in ("group", "artifact", "version", "advisoryId"):
                if not getattr(self, name):
                    raise ValueError(f"SCA requires '{name}'")
        if not self.id:
            object.__setattr__(self, "id", str(uuid.uuid4()))
        return self

    def to_submission(self) -> dict[str, Any]:
        """Return only keys allowed by organisers' specification (exact casing)."""
        out: dict[str, Any] = {
            "category": self.category,
            "path": self.path,
        }
        if self.category in ("SECRET", "SAST"):
            out["class"] = self.class_
            out["line"] = self.line
            if self.endLine is not None:
                out["endLine"] = self.endLine
        if self.category == "SCA":
            out["group"] = self.group
            out["artifact"] = self.artifact
            out["version"] = self.version
            out["advisoryId"] = self.advisoryId
        if self.severity:
            out["severity"] = self.severity
        if self.description:
            out["description"] = self.description
        if self.remediation:
            out["remediation"] = self.remediation
        return out


class FindingsReport(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

    def to_submission(self) -> dict[str, Any]:
        return {"findings": [f.to_submission() for f in self.findings]}


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Workflow(SQLModel, table=True):
    __tablename__ = "workflows"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str
    graph_json: dict = SQLField(default_factory=dict, sa_column=Column(JSON))
    is_template: bool = False
    description: str = ""
    owner_id: str | None = SQLField(default=None, index=True)
    created_at: datetime = SQLField(default_factory=_utcnow)
    updated_at: datetime = SQLField(default_factory=_utcnow)


class Run(SQLModel, table=True):
    __tablename__ = "runs"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    workflow_id: str = SQLField(index=True)
    owner_id: str | None = SQLField(default=None, index=True)
    status: str = "pending"  # pending | running | success | failed | partial
    trigger: str = "manual"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary_json: dict | None = SQLField(default=None, sa_column=Column(JSON))
    ai_report_json: dict | None = SQLField(default=None, sa_column=Column(JSON))


class NodeRun(SQLModel, table=True):
    __tablename__ = "node_runs"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    run_id: str = SQLField(index=True)
    node_id: str
    status: str = "pending"  # pending | running | success | failed | skipped
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output_preview_json: dict | None = SQLField(default=None, sa_column=Column(JSON))
    error: str | None = SQLField(default=None, sa_column=Column(Text))


class Credential(SQLModel, table=True):
    __tablename__ = "credentials"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str
    kind: str  # telegram | llm | webhook | smtp | generic
    encrypted_value: str  # Fernet ciphertext
    owner_id: str | None = SQLField(default=None, index=True)
    created_at: datetime = SQLField(default_factory=_utcnow)


class IntegrationSetting(SQLModel, table=True):
    __tablename__ = "integration_settings"

    kind: str = SQLField(primary_key=True)  # "ai" | "telegram" or "{user_id}:ai" | "{user_id}:telegram"
    enabled: bool = True
    auto_send: bool = True  # for telegram: auto send after scan vs on-demand
    config_json: dict = SQLField(default_factory=dict, sa_column=Column(JSON))
    encrypted_secret: str = ""  # Fernet-encrypted API key / bot token
    updated_at: datetime = SQLField(default_factory=_utcnow)


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    email: str = SQLField(index=True, unique=True)
    password_hash: str
    is_active: bool = True
    created_at: datetime = SQLField(default_factory=_utcnow)


class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_id: str = SQLField(index=True)
    token_hash: str = SQLField(index=True, unique=True)
    csrf_token: str
    expires_at: datetime
    revoked: bool = False
    created_at: datetime = SQLField(default_factory=_utcnow)


class PasswordResetToken(SQLModel, table=True):
    __tablename__ = "password_reset_tokens"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_id: str = SQLField(index=True)
    token_hash: str = SQLField(index=True)
    expires_at: datetime
    used: bool = False
    created_at: datetime = SQLField(default_factory=_utcnow)


class CustomNode(SQLModel, table=True):
    __tablename__ = "custom_nodes"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    owner_id: str | None = SQLField(default=None, index=True)
    node_type: str = SQLField(index=True, unique=True)
    name: str
    description: str = ""
    group: str = "custom"
    code: str
    inputs_json: list[dict[str, Any]] = SQLField(default_factory=list, sa_column=Column(JSON))
    outputs_json: list[dict[str, Any]] = SQLField(default_factory=list, sa_column=Column(JSON))
    params_schema_json: dict[str, Any] = SQLField(default_factory=dict, sa_column=Column(JSON))
    version: int = 1
    status: str = "active"  # draft | active | disabled
    visibility: str = "private"  # private | public
    created_at: datetime = SQLField(default_factory=_utcnow)
    updated_at: datetime = SQLField(default_factory=_utcnow)


class CustomNodeVersion(SQLModel, table=True):
    __tablename__ = "custom_node_versions"

    id: str = SQLField(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    custom_node_id: str = SQLField(index=True)
    version: int
    name: str
    description: str = ""
    group: str = "custom"
    code: str
    inputs_json: list[dict[str, Any]] = SQLField(default_factory=list, sa_column=Column(JSON))
    outputs_json: list[dict[str, Any]] = SQLField(default_factory=list, sa_column=Column(JSON))
    params_schema_json: dict[str, Any] = SQLField(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = SQLField(default_factory=_utcnow)

