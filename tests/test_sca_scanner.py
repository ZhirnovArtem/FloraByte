import pytest
from security_scanners.core.models import ScanInput, SourceFile, Severity
from security_scanners.sca.scanner import ScaScanner
from security_scanners.sca.db import Vulnerability

@pytest.fixture
def fake_vuln_db():
    return [
        Vulnerability("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "CRITICAL", ">=2.0.0 <2.15.0", "Log4Shell", "Update", True)
    ]

@pytest.fixture
def scanner(fake_vuln_db):
    return ScaScanner(vulnerability_db=fake_vuln_db)

def test_sca_finds_vulnerable_dependency(scanner):
    content = 'dependencies {\n    implementation("org.apache.logging.log4j:log4j-core:2.14.0")\n}'
    files = [SourceFile(path="build.gradle.kts", content=content)]
    result = scanner.scan(ScanInput(repo_path="/fake", files=files))
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].metadata["cve"] == "CVE-2021-44228"

def test_sca_ignores_safe_version(scanner):
    content = 'implementation("org.apache.logging.log4j:log4j-core:2.17.1")'
    files = [SourceFile(path="build.gradle.kts", content=content)]
    result = scanner.scan(ScanInput(repo_path="/fake", files=files))
    assert len(result.findings) == 0