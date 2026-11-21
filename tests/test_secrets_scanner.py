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


def test_detects_secret_fallback_and_ignores_safe_default():
    bad = 'val tok = System.getenv("SVC_TOKEN") ?: "x9kL2pQ8mR4vN7wB"'
    res_bad = run(bad, "Client.kt")
    assert any(f.type == "secret-fallback" for f in res_bad.findings)
    assert all("x9kL2pQ8mR4vN7wB" not in (f.evidence or "") for f in res_bad.findings)

    good = 'val tok = System.getenv("SVC_TOKEN") ?: "changeme"'
    res_good = run(good, "Client.kt")
    assert not any(f.type == "secret-fallback" for f in res_good.findings)


def test_detects_recoverable_token_and_masks_parts():
    code = '''
fun headers(): HttpHeaders {
    val head = "tok_prefix_"
    val tail = "A9b8C7d6E5f4G3h2"
    val full = head + tail
    return HttpHeaders().apply { setBearerAuth(full) }
}
'''
    res = run(code, "Headers.kt")
    rec = [f for f in res.findings if f.type == "recoverable-token"]
    assert len(rec) == 1
    assert rec[0].line == 3
    assert "A9b8C7d6E5f4G3h2" not in (rec[0].evidence or "")
    assert "tok_prefix_" not in (rec[0].evidence or "")