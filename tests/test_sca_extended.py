"""Regression tests for newly supported Gradle forms and resolved dependency versions."""

from security_scanners.sca.db import Vulnerability
from security_scanners.sca.parser import GradleDependencyParser
from security_scanners.sca.scanner import ScaScanner
from security_scanners.sca.version_range import VersionRange
from security_scanners.core.models import ScanInput, SourceFile

DB = [Vulnerability("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "CRITICAL", ">=2.0.0 <2.15.0", "test", "upgrade")]


def test_gradle_variable_resolution():
    text = 'val log4jVersion = "2.14.0"\nimplementation("org.apache.logging.log4j:log4j-core:$log4jVersion")'
    dependencies = GradleDependencyParser().parse(text, "build.gradle.kts")
    assert len(dependencies) == 1
    assert dependencies[0].version == "2.14.0"


def test_gradle_properties_version_resolution():
    files = [
        SourceFile("gradle.properties", "logVersion=2.14.0"),
        SourceFile("build.gradle.kts", 'implementation("org.apache.logging.log4j:log4j-core:${logVersion}")'),
    ]
    result = ScaScanner(vulnerability_db=DB).scan(ScanInput(repo_path="demo", files=files))
    assert len(result.findings) == 1


def test_version_catalog_parsed():
    files = [
        SourceFile("gradle/libs.versions.toml", '[versions]\nlog4j = "2.14.0"\n[libraries]\nlog4j-core = {module="org.apache.logging.log4j:log4j-core", version.ref="log4j"}'),
        SourceFile("build.gradle.kts", 'dependencies {\n  implementation(libs.log4j.core)\n}')
    ]
    result = ScaScanner(vulnerability_db=DB).scan(ScanInput(repo_path="demo", files=files))
    assert len(result.findings) == 1


def test_lockfile_priority():
    files = [
        SourceFile("build.gradle.kts", 'implementation("org.apache.logging.log4j:log4j-core:2.17.2")'),
        SourceFile("gradle.lockfile", "org.apache.logging.log4j:log4j-core:2.14.0=compileClasspath"),
    ]
    scan_input = ScanInput(repo_path="demo", files=files)
    assert len(ScaScanner(vulnerability_db=DB, lockfile_priority=True).scan(scan_input).findings) == 1
    assert len(ScaScanner(vulnerability_db=DB, lockfile_priority=False).scan(scan_input).findings) == 0


def test_version_comparison_with_zero_and_prerelease():
    assert VersionRange.compare("1.0", "1.0.0") == 0
    assert VersionRange.compare("2.15.0-rc1", "2.15.0") < 0
    assert VersionRange.in_range("2.15.0", ">=2.0 <2.15") is False
