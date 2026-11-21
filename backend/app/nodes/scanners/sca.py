"""SCA scanner node — adapter over team package `security_scanners.sca`."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.models import Finding
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from security_scanners.core.models import ScanInput, SourceFile  # noqa: E402
from security_scanners.sca.db import Vulnerability, VulnerabilityDb  # noqa: E402
from security_scanners.sca.scanner import ScaScanner  # noqa: E402

_SKIP_DIRS = {".git", "build", ".gradle", "node_modules", "__pycache__", ".venv", "venv"}


def _resolve_db_path(raw_path: str | Path | None, root: Path) -> Path | None:
    if not raw_path:
        return None
    p = Path(raw_path)
    candidates = [p] if p.is_absolute() else [p, root / p, _REPO_ROOT / p, _REPO_ROOT / "backend" / p]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _range_to_affected(rng: dict[str, Any]) -> str:
    parts: list[str] = []
    lower = rng.get("lower")
    if lower is not None:
        op = ">=" if rng.get("lowerInclusive", True) else ">"
        parts.append(f"{op}{lower}")
    upper = rng.get("upper")
    if upper is not None:
        op = "<=" if rng.get("upperInclusive", False) else "<"
        parts.append(f"{op}{upper}")
    return " ".join(parts)


def _load_vulnerabilities(vuln_db_path: str | Path | None, root: Path) -> list[Vulnerability]:
    resolved = _resolve_db_path(vuln_db_path, root)
    if resolved is None:
        return VulnerabilityDb.load_from_resource()

    raw = json.loads(resolved.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [Vulnerability(**item) for item in raw]

    if isinstance(raw, dict) and isinstance(raw.get("vulnerabilities"), list):
        vulns: list[Vulnerability] = []
        for item in raw["vulnerabilities"]:
            group = item.get("group", "")
            artifact = item.get("artifact", "")
            if not group or not artifact:
                continue
            aliases = item.get("aliases") or []
            cve_aliases = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
            advisory_id = cve_aliases[0] if cve_aliases else str(item.get("id", ""))
            if not advisory_id:
                continue
            sev = str(item.get("severity") or "MEDIUM").upper()
            if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                sev = "MEDIUM"
            fixed = item.get("fixedVersions") or []
            rec = f"Обновить {group}:{artifact} до версии {', '.join(fixed)}" if fixed else f"Обновить {group}:{artifact}"
            desc = f"Known vulnerability {item.get('id', advisory_id)} in {group}:{artifact}"
            for rng in item.get("ranges") or []:
                affected = _range_to_affected(rng)
                if not affected:
                    continue
                vulns.append(
                    Vulnerability(
                        id=advisory_id,
                        packageName=f"{group}:{artifact}",
                        severity=sev,
                        affected=affected,
                        description=desc,
                        recommendation=rec,
                        exploitAvailable=False,
                    )
                )
        return vulns

    return VulnerabilityDb.load_from_resource()


def _collect_gradle_files(root: Path) -> list[SourceFile]:
    files: list[SourceFile] = []
    if not root.exists():
        return files
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        if p.name in ("build.gradle.kts", "build.gradle", "settings.gradle.kts", "gradle.properties", "gradle.lockfile", "libs.versions.toml"):
            try:
                content = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            files.append(SourceFile(path="/".join(rel_parts), content=content))
    return files


def scan(root: Path, params: dict | None = None) -> list[Finding]:
    params = params or {}
    vuln_db = _load_vulnerabilities(params.get("vuln_db_path"), root)
    files = _collect_gradle_files(root)
    scanner = ScaScanner(vulnerability_db=vuln_db, lockfile_priority=params.get("lockfile_priority", True))
    result = scanner.scan(ScanInput(repo_path=str(root), files=files))

    out: list[Finding] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for f in result.findings:
        pkg = f.metadata.get("package", "")
        if ":" in pkg:
            group, artifact = pkg.split(":", 1)
        else:
            group, artifact = pkg, ""
        version = f.metadata.get("version", "")
        advisory_id = f.metadata.get("cve", "")
        rel_path = f.file.replace("\\", "/").lstrip("./")
        key = (rel_path, group, artifact, version, advisory_id)
        if key in seen:
            continue
        seen.add(key)

        sev = f.severity.name if f.severity.name in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM"
        out.append(
            Finding(
                category="SCA",
                path=rel_path,
                group=group,
                artifact=artifact,
                version=version,
                advisoryId=advisory_id,
                severity=sev,
                description=f.description,
                remediation=f.recommendation,
                rule_id=f"sca.{f.type}",
                evidence=f.evidence,
            )
        )
    return out


class Params(BaseModel):
    vuln_db_path: str = Field("", description="Override path to vulnerabilities.json")
    lockfile_priority: bool = True


@register_node
class ScaScannerNode(BaseNode):
    type = "scanner.sca"
    label = "SCA Scanner"
    group = "scanner"
    inputs = [Port(name="workspace", kind="Workspace")]
    outputs = [Port(name="findings", kind="Findings")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        root = inputs.get("workspace") or inputs.get("in")
        if not root:
            raise ValueError("scanner.sca requires workspace input")
        root = Path(root)
        settings = get_settings()
        scan_params = {
            "vuln_db_path": params.vuln_db_path or str(settings.vuln_db_path),
            "lockfile_priority": params.lockfile_priority,
        }
        if settings.use_stub_scanners:
            from app.nodes.scanners._stubs import stub_sca_scan

            findings = stub_sca_scan(root, scan_params)
        else:
            findings = await asyncio.to_thread(scan, root, scan_params)
        return {"findings": findings}
