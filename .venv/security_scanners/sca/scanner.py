from __future__ import annotations
import time
from ..core.classifier import SeverityClassifier
from ..core.models import Finding, ScanInput, ScanResult, ScanStats, Severity
from ..core.scanner import SecurityScanner
from .db import Vulnerability, VulnerabilityDb
from .parser import GradleDependency, GradleDependencyParser
from .version_range import VersionRange

class ScaScanner(SecurityScanner):
    def __init__(self, vulnerability_db: list[Vulnerability] | None = None, parser: GradleDependencyParser | None = None) -> None:
        self._db = vulnerability_db if vulnerability_db is not None else VulnerabilityDb.load_from_resource()
        self._parser = parser or GradleDependencyParser()

    @property
    def id(self) -> str:
        return "sca"

    @property
    def name(self) -> str:
        return "SCA Scanner"

    def scan(self, scan_input: ScanInput) -> ScanResult:
        start = time.perf_counter()
        gradle_files = [
            f for f in scan_input.files
            if f.is_scannable() and (f.path.endswith("build.gradle.kts") or f.path.endswith("build.gradle") or f.path.endswith("settings.gradle.kts"))
        ]
        findings: list[Finding] = []
        for file in gradle_files:
            deps = self._parser.parse(file.content, file.path)
            findings.extend(self._check_dependencies(deps, file.path))

        seen: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = f"{f.metadata.get('cve')}:{f.metadata.get('package')}:{f.metadata.get('version')}"
            if key in seen: continue
            seen.add(key)
            deduped.append(SeverityClassifier.classify(f))
        deduped.sort(key=lambda f: f.severity.value, reverse=True)
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ScanResult(scanner_id=self.id, findings=deduped, stats=ScanStats(files_scanned=len(gradle_files), rules_applied=len(self._db), duration_ms=duration_ms))

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
                            "configuration": dep.configuration, "exploit_available": str(vuln.exploitAvailable).lower(),
                        },
                    ))
        return findings