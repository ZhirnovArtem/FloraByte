import pytest
from pydantic import ValidationError

from app.core.models import Finding


def test_secret_finding_ok():
    f = Finding(
        category="SECRET",
        path="src/main/kotlin/lab/Foo.kt",
        **{"class": "api-key"},
        line=7,
        severity="MEDIUM",
        description="Embedded API key",
    )
    assert f.class_ == "api-key"
    sub = f.to_submission()
    assert sub["category"] == "SECRET"
    assert sub["class"] == "api-key"
    assert sub["line"] == 7
    assert "id" not in sub
    assert "evidence" not in sub
    assert "rule_id" not in sub


def test_sast_with_endline():
    f = Finding(category="SAST", path="a/b.kt", **{"class": "sql-injection"}, line=13, endLine=14)
    assert f.to_submission()["endLine"] == 14


def test_sca_finding():
    f = Finding(
        category="SCA",
        path="build.gradle.kts",
        group="org.apache.commons",
        artifact="commons-text",
        version="1.9",
        advisoryId="CVE-2022-42889",
    )
    sub = f.to_submission()
    assert set(sub.keys()) >= {"category", "path", "group", "artifact", "version", "advisoryId"}
    assert "class" not in sub
    assert "line" not in sub


def test_path_rejects_absolute_and_dotdot():
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="/etc/passwd", **{"class": "x"}, line=1)
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="../secret", **{"class": "x"}, line=1)
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="C:\\Windows", **{"class": "x"}, line=1)


def test_secret_requires_class_and_line():
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="a.kt", line=1)
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="a.kt", **{"class": "password"})


def test_sca_requires_coords():
    with pytest.raises(ValidationError):
        Finding(category="SCA", path="build.gradle.kts", group="g", artifact="a", version="1.0")


def test_line_must_be_int():
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="a.kt", **{"class": "x"}, line="7")  # type: ignore
    with pytest.raises(ValidationError):
        Finding(category="SECRET", path="a.kt", **{"class": "x"}, line=True)  # type: ignore


def test_endline_bounds():
    with pytest.raises(ValidationError):
        Finding(category="SAST", path="a.kt", **{"class": "x"}, line=10, endLine=9)
    with pytest.raises(ValidationError):
        Finding(category="SAST", path="a.kt", **{"class": "x"}, line=10, endLine=30)
