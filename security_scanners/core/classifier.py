from .models import Finding, Severity

class SeverityClassifier:
    @staticmethod
    def classify(finding: Finding) -> Finding:
        severity = finding.severity
        if "/test/" in finding.file or finding.file.endswith("Test.kt"):
            severity = severity.downgrade()
        if finding.scanner == "secrets" and finding.file.endswith((".properties", ".yml", ".yaml")):
            severity = severity.upgrade()
        if finding.metadata.get("exploit_available") == "true":
            severity = Severity.CRITICAL
        finding.severity = severity
        return finding