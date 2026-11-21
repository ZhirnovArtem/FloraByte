"""Secrets scanner node — adapter over team package `security_scanners.secrets`."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.config import get_settings
from app.core.masking import mask_evidence, mask_secret, redact_text
from app.core.models import Finding
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from security_scanners.core.models import ScanInput, SourceFile  # noqa: E402
from security_scanners.secrets.scanner import SecretsScanner  # noqa: E402

_SKIP_DIRS = {".git", "build", ".gradle", "node_modules", "__pycache__", ".venv", "venv"}

# Map SecretsScanner rule IDs to organisers' `class` codes (docs/submission-format.md)
_RULE_TO_CLASS: dict[str, str] = {
    "hardcoded-password": "password",
    "jdbc-url-with-password": "password",
    "mongodb-uri-with-password": "password",
    "postgres-uri-with-password": "password",
    "hardcoded-api-key": "api-key",
    "aws-access-key": "api-key",
    "aws-secret-key": "api-key",
    "google-api-key": "api-key",
    "github-token": "api-key",
    "slack-token": "api-key",
    "telegram-bot-token": "api-key",
    "secret-fallback": "secret-fallback",
    "recoverable-token": "recoverable-token",
    "bearer-token": "configuration-token",
    "jwt-token": "configuration-token",
    "private-key": "private-key",
}


def _map_class(rule_id: str, rel_path: str) -> str:
    if rule_id in _RULE_TO_CLASS:
        return _RULE_TO_CLASS[rule_id]
    if rule_id == "generic-secret-assignment":
        if rel_path.lower().endswith((".yml", ".yaml", ".properties", ".json", ".toml", ".env")):
            return "configuration-token"
        return "api-key"
    return rule_id


def _strict_mask_evidence(raw: str | None) -> str | None:
    if not raw:
        return None
    masked = redact_text(raw)
    # Also mask `Bearer <token>` regardless of token length >= 6
    masked = re.sub(
        r"(?i)\b(bearer\s+)([^\s\"']{4,})",
        lambda m: m.group(1) + mask_secret(m.group(2)),
        masked,
    )
    # Mask remaining quoted literals >= 4 chars
    masked = re.sub(
        r"""(["'])([^"']{4,})\1""",
        lambda m: f"{m.group(1)}{mask_secret(m.group(2))}{m.group(1)}",
        masked,
    )
    return mask_evidence(masked) or masked[:120]


def _collect_source_files(root: Path) -> list[SourceFile]:
    files: list[SourceFile] = []
    if not root.exists():
        return files
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        rel = "/".join(rel_parts)
        try:
            content = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files.append(SourceFile(path=rel, content=content))
    return files


def scan(root: Path, params: dict | None = None) -> list[Finding]:
    files = _collect_source_files(root)
    scanner = SecretsScanner()
    result = scanner.scan(ScanInput(repo_path=str(root), files=files))

    out: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for f in result.findings:
        rel_path = f.file.replace("\\", "/").lstrip("./")
        cls = _map_class(f.type, rel_path)
        key = (rel_path, cls, f.line)
        if key in seen:
            continue
        seen.add(key)

        sev = f.severity.name if f.severity.name in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM"
        end_line = f.metadata.get("end_line", f.line)
        if not isinstance(end_line, int) or end_line < f.line or end_line > f.line + 14:
            end_line = f.line
        out.append(
            Finding(
                category="SECRET",
                path=rel_path,
                **{"class": cls},
                line=f.line,
                endLine=end_line,
                severity=sev,
                description=redact_text(f.description),
                remediation=f.recommendation,
                rule_id=f.type,
                evidence=_strict_mask_evidence(f.evidence),
            )
        )
    return out


class Params(BaseModel):
    pass


@register_node
class SecretsScannerNode(BaseNode):
    type = "scanner.secrets"
    label = "Secrets Scanner"
    group = "scanner"
    inputs = [Port(name="workspace", kind="Workspace")]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        root = inputs.get("workspace") or inputs.get("in")
        if not root:
            raise ValueError("scanner.secrets requires workspace input")
        root = Path(root)
        settings = get_settings()
        if settings.use_stub_scanners:
            from app.nodes.scanners._stubs import stub_secrets_scan

            findings = stub_secrets_scan(root, {})
        else:
            findings = await asyncio.to_thread(scan, root, {})
        return {"findings": findings}
