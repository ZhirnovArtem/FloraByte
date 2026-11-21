"""In-house dependency matching, using explicit Gradle declarations and resolved lockfiles."""
from __future__ import annotations

import time
from ..core.classifier import SeverityClassifier
from ..core.models import Finding, ScanInput, ScanResult, ScanStats, Severity
from ..core.scanner import SecurityScanner
from .db import Vulnerability, VulnerabilityDb
from .parser import GradleDependency, GradleDependencyParser
from .version_range import VersionRange


class ScaScanner(SecurityScanner):
    def __init__(
        self,
        vulnerability_db: list[Vulnerability] | None = None,
        parser: GradleDependencyParser | None = None,
        lockfile_priority: bool = True,
    ) -> None:
        self._db = vulnerability_db if vulnerability_db is not None else VulnerabilityDb.load_from_resource()
        self._parser = parser or GradleDependencyParser()
        self._lockfile_priority = lockfile_priority

    @property
    def id(self) -> str:
        return "sca"

    @property
    def name(self) -> str:
        return "SCA Scanner"

    def scan(self, scan_input: ScanInput) -> ScanResult:
        start = time.perf_counter()
        files = [f for f in scan_input.files if f.is_scannable()]
        gradle_files = [f for f in files if f.path.endswith(("build.gradle.kts", "build.gradle", "settings.gradle.kts"))]
        property_files = [f for f in files if f.path.endswith("gradle.properties")]
        catalog_files = [f for f in files if f.path.endswith("libs.versions.toml")]
        lock_files = [f for f in files if f.path.endswith("gradle.lockfile")]

        variables = self._parser.variables([f.content for f in gradle_files + property_files])
        aliases: dict[str, tuple[str, str, str]] = {}
        for f in catalog_files:
            aliases.update(self._parser.catalog(f.content))
        locked: dict[str, GradleDependency] = {}
        locked_paths: dict[str, str] = {}
        for f in lock_files:
            for dep in self._parser.locked_dependencies(f.content):
                locked[dep.package_name] = dep
                locked_paths[dep.package_name] = f.path

        findings: list[Finding] = []
        declared_packages: set[str] = set()
        for f in gradle_files:
            deps = self._parser.parse(f.content, f.path, variables=variables, aliases=aliases)
            for dep in deps:
                declared_packages.add(dep.package_name)
                if self._lockfile_priority and dep.package_name in locked:
                    dep = GradleDependency(dep.configuration, dep.group, dep.artifact, locked[dep.package_name].version, dep.line)
                findings.extend(self._check_dependencies([dep], f.path))
        # Lock-only coordinates are still concrete resolved dependencies.
        for package, dep in locked.items():
            if package not in declared_packages:
                findings.extend(self._check_dependencies([dep], locked_paths[package]))

        seen: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = f"{f.metadata.get('cve')}:{f.metadata.get('package')}:{f.metadata.get('version')}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(SeverityClassifier.classify(f))
        deduped.sort(key=lambda f: f.severity.value, reverse=True)
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ScanResult(scanner_id=self.id, findings=deduped, stats=ScanStats(
            files_scanned=len(gradle_files + catalog_files + lock_files),
            rules_applied=len(self._db), duration_ms=duration_ms,
        ))

    def _check_dependencies(self, deps: list[GradleDependency], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            for vuln in self._db:
                if vuln.packageName == dep.package_name and VersionRange.in_range(dep.version, vuln.affected):
                    findings.append(Finding(
                        id=f"{vuln.id}:{dep.package_name}:{dep.version}", scanner=self.id,
                        type="vulnerable_dependency", severity=Severity[vuln.severity],
                        file=file_path, line=dep.line, evidence=f"{dep.package_name}:{dep.version}",
                        description=f"{vuln.id}: {vuln.description}", recommendation=vuln.recommendation,
                        metadata={
                            "cve": vuln.id, "package": dep.package_name, "version": dep.version,
                            "configuration": dep.configuration,
                            "exploit_available": str(vuln.exploitAvailable).lower(),
                        },
                    ))
        return findings
