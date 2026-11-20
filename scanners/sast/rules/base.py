from dataclasses import dataclass
from typing import Callable
from ..context import FileContext
from ..model import Finding, Severity, Confidence
import re

def mask_evidence(value: str) -> str:
    """Conservative evidence redaction; shared Secrets service remains authoritative."""
    value = re.sub(r'(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[=:]\s*)[\'\"]?[^\s,;\'\"]+', r'\1\2[REDACTED]', value)
    value = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', value)
    value = re.sub(r'(?i)(AKIA[0-9A-Z]{16})', '[REDACTED]', value)
    return value

@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    title: str
    base_severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    check: Callable[[FileContext], list[tuple[int, int, str, str]]]

    def run(self, ctx: FileContext) -> list[Finding]:
        results = []
        for line, col, evidence, rationale in self.check(ctx):
            severity = self.base_severity
            conf = self.confidence
            if ctx.profile in {"dev", "local", "test"} and severity in {Severity.HIGH, Severity.MEDIUM}:
                severity = Severity.MEDIUM if severity == Severity.HIGH else Severity.LOW
                rationale += "; профиль dev/local/test: severity снижена на один уровень"
            if "/src/test/" in f"/{ctx.rel_path}/":
                severity, conf = Severity.INFO, Confidence.LOW
                rationale += "; тестовый исходник: INFO"
            evidence = mask_evidence(evidence[:180])
            from hashlib import sha1
            import re
            normalized = re.sub(r"\s+", " ", evidence).strip().lower()
            fp = sha1(f"{self.id}|{ctx.rel_path}|{normalized}".encode()).hexdigest()
            results.append(Finding(
                id=f"{self.id}:{ctx.rel_path}:{line}:{col}", rule_id=self.id,
                title=self.title, file=ctx.rel_path, line=line, column=col,
                severity=severity, confidence=conf, cwe=self.cwe,
                message=self.description, evidence=evidence,
                remediation=self.remediation, fingerprint=f"sha1:{fp}", rationale=rationale,
            ))
        return results
