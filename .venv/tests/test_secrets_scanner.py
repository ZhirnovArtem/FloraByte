from security_scanners.core.models import ScanInput, SourceFile
from security_scanners.secrets.scanner import SecretsScanner

def run(content: str, path: str = "Config.kt"):
    scanner = SecretsScanner()
    return scanner.scan(ScanInput("/repo", [SourceFile(path, content)]))

def test_detects_hardcoded_password():
    result = run('val password = "secret123"')
    assert len(result.findings) == 1
    assert result.findings[0].type == "hardcoded-password"
    assert result.findings[0].line == 1

def test_ignores_placeholder_password():
    result = run('val password = "${DB_PASSWORD}"')
    assert result.findings == []

def test_detects_aws_access_key():
    result = run('val key = "AKIAIOSFODNN7REALKEY"')
    assert any(f.type == "aws-access-key" for f in result.findings)

def test_ignores_aws_example_key():
    result = run('val key = "AKIAIOSFODNN7EXAMPLE"')
    assert all(f.type != "aws-access-key" for f in result.findings)

def test_masks_evidence():
    result = run('val password = "supersecret"')
    evidence = result.findings[0].evidence
    assert "***" in evidence
    assert "supersecret" not in evidence