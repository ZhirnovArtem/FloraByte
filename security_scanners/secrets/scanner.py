from __future__ import annotations
import re
import time
from ..core.classifier import SeverityClassifier
from ..core.models import Finding, ScanInput, ScanResult, ScanStats, SourceFile
from ..core.scanner import SecurityScanner
from .rules import DefaultSecretRules, SecretRule

class SecretsScanner(SecurityScanner):
    _SCANNABLE_EXTENSIONS = (
        ".kt", ".kts", ".java", ".properties", ".yml", ".yaml",
        ".json", ".xml", ".env", ".txt", ".md", ".gradle", ".toml",
    )

    def __init__(self, rules: list[SecretRule] | None = None) -> None:
        self._rules = rules if rules is not None else DefaultSecretRules.all()

    @property
    def id(self) -> str:
        return "secrets"

    @property
    def name(self) -> str:
        return "Secrets Scanner"

    def scan(self, scan_input: ScanInput) -> ScanResult:
        start = time.perf_counter()
        files = [
            f for f in scan_input.files
            if f.is_text and f.is_scannable()
            and f.path.lower().endswith(self._SCANNABLE_EXTENSIONS)
        ]

        findings: list[Finding] = []
        for file in files:
            findings.extend(self._scan_file(file))

        seen: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = f"{f.type}:{f.file}:{f.line}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(SeverityClassifier.classify(f))

        deduped.sort(key=lambda f: f.severity.value, reverse=True)
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ScanResult(scanner_id=self.id, findings=deduped, stats=ScanStats(files_scanned=len(files), rules_applied=len(self._rules), duration_ms=duration_ms))

    def _scan_file(self, file: SourceFile) -> list[Finding]:
        findings: list[Finding] = []
        for index, line in enumerate(file.content.splitlines(), start=1):
            for rule in self._rules:
                match = rule.pattern.search(line)
                if not match or any(a.search(line) for a in rule.allowlist):
                    continue
                findings.append(Finding(
                    id=f"{rule.id}:{file.path}:{index}", scanner=self.id, type=rule.id,
                    severity=rule.severity, file=file.path, line=index,
                    evidence=self._mask_evidence(match.group(0)),
                    description=rule.description, recommendation=rule.recommendation,
                    metadata={"rule_id": rule.id, "confidence": "high"},
                ))
        return findings

    @staticmethod
    def _mask_evidence(value: str) -> str:
        def repl(m: re.Match[str]) -> str:
            s = m.group(1)
            return '"****"' if len(s) <= 4 else f'"{s[:2]}***{s[-1]}"'
        return re.sub(r"""["']([^"']{4,})["']""", repl, value)[:120]