from __future__ import annotations
import re
import time
from ..core.classifier import SeverityClassifier
from ..core.models import Finding, ScanInput, ScanResult, ScanStats, SourceFile
from ..core.scanner import SecurityScanner
from .rules import DefaultSecretRules, SecretRule

_ASSIGN_LITERAL_RE = re.compile(
    r"""^\s*(?:(?:val|var|const|private|internal|public|lateinit|final|static)\s+)*(?:String\s+)?([A-Za-z_]\w*)\s*(?::\s*String\??\s*)?=\s*["']([^"'\n]{2,})["']"""
)
_ASSIGN_CONCAT_RE = re.compile(
    r"""^\s*(?:(?:val|var|const|private|internal|public|final)\s+)*(?:String\s+)?([A-Za-z_]\w*)\s*(?::\s*String\??\s*)?=\s*([A-Za-z_]\w*(?:\s*\+\s*[A-Za-z_]\w*)+)"""
)
_INLINE_CONCAT_RE = re.compile(
    r"""["']([^"'\n]{3,})["']\s*\+\s*["']([^"'\n]{3,})["']"""
)
_AUTH_SINK_RE = re.compile(
    r"""(?i)(setBearerAuth|\.header\s*\(\s*["'](?:Authorization|X-Api-Key|X-Auth-Token|Api-Key)["']|HttpHeaders\.AUTHORIZATION|Bearer\s+|\b(?:api[_-]?key|token|secret|auth|access|password)\b)"""
)
_PLACEHOLDER_VALUE_RE = re.compile(
    r"""^(?:\$\{.*\}|<[^>]+>|your[-_].*|example.*|dummy.*|changeme|changeit|placeholder.*|test[-_]?token|localhost|\s+)$""",
    re.IGNORECASE,
)


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
        lines = file.content.splitlines()
        for index, line in enumerate(lines, start=1):
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
        if file.path.lower().endswith((".kt", ".kts", ".java")):
            findings.extend(self._detect_recoverable_tokens(file.path, lines))
        return findings

    def _detect_recoverable_tokens(self, path: str, lines: list[str]) -> list[Finding]:
        """Intra-procedural detection of tokens assembled from multiple string literals."""
        # var_name -> (combined_value, first_line, last_line, part_count)
        str_vars: dict[str, tuple[str, int, int, int]] = {}
        out: list[Finding] = []
        reported_lines: set[int] = set()

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*")):
                continue

            # Inline literal concatenation on a single line in an auth context
            inline = _INLINE_CONCAT_RE.search(line)
            if inline and _AUTH_SINK_RE.search(line):
                combined = inline.group(1) + inline.group(2)
                if len(combined) >= 12 and not _PLACEHOLDER_VALUE_RE.match(combined):
                    reported_lines.add(index)
                    out.append(Finding(
                        id=f"recoverable-token:{path}:{index}",
                        scanner=self.id,
                        type="recoverable-token",
                        severity=DefaultSecretRules.hardcoded_api_key().severity,
                        file=path,
                        line=index,
                        evidence=self._mask_evidence(line.strip()),
                        description="Токен собирается из нескольких строковых литералов в коде",
                        recommendation="Передавайте токен через переменные окружения или защищённое хранилище",
                        metadata={"rule_id": "recoverable-token", "confidence": "high", "end_line": index},
                    ))
                    continue

            m_lit = _ASSIGN_LITERAL_RE.match(line)
            if m_lit:
                var_name, val = m_lit.group(1), m_lit.group(2)
                if not _PLACEHOLDER_VALUE_RE.match(val):
                    str_vars[var_name] = (val, index, index, 1)
                continue

            m_cat = _ASSIGN_CONCAT_RE.match(line)
            if m_cat:
                target_var = m_cat.group(1)
                expr = m_cat.group(2)
                parts = [p.strip() for p in expr.split("+")]
                if all(p in str_vars for p in parts):
                    combined = "".join(str_vars[p][0] for p in parts)
                    first_line = min(str_vars[p][1] for p in parts)
                    total_parts = sum(str_vars[p][3] for p in parts)
                    str_vars[target_var] = (combined, first_line, index, total_parts)
                    # If target variable name itself looks like auth/secret and combined >= 12 chars
                    if total_parts >= 2 and len(combined) >= 12 and not _PLACEHOLDER_VALUE_RE.match(combined):
                        # Look ahead a few lines to see if target_var flows into an auth sink
                        sink_line = index
                        has_sink = bool(_AUTH_SINK_RE.search(target_var))
                        for look_idx in range(index, min(len(lines), index + 8)):
                            look_line = lines[look_idx]
                            if re.search(rf"\b{re.escape(target_var)}\b", look_line) and _AUTH_SINK_RE.search(look_line):
                                has_sink = True
                                sink_line = look_idx + 1
                                break
                        if has_sink and first_line not in reported_lines:
                            reported_lines.add(first_line)
                            out.append(Finding(
                                id=f"recoverable-token:{path}:{first_line}",
                                scanner=self.id,
                                type="recoverable-token",
                                severity=DefaultSecretRules.hardcoded_api_key().severity,
                                file=path,
                                line=first_line,
                                evidence=f"{target_var} = {self._mask_evidence(repr(combined))}",
                                description="Токен собирается из нескольких строковых литералов и передаётся в заголовок/авторизацию",
                                recommendation="Передавайте токен целиком через переменные окружения или защищённое хранилище",
                                metadata={
                                    "rule_id": "recoverable-token",
                                    "confidence": "high",
                                    "end_line": min(sink_line, first_line + 14),
                                },
                            ))
        return out

    @staticmethod
    def _mask_evidence(value: str) -> str:
        def repl(m: re.Match[str]) -> str:
            s = m.group(1)
            return '"****"' if len(s) <= 4 else f'"{s[:2]}***{s[-1]}"'
        return re.sub(r"""["']([^"']{4,})["']""", repl, value)[:120]
