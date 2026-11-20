import io
import zipfile
from pathlib import Path

import pytest

from app.nodes.source.upload_zip import find_gradle_root, safe_extract, MAX_FILES


def test_find_gradle_root(tmp_path: Path):
    (tmp_path / "training-project").mkdir()
    (tmp_path / "training-project" / "build.gradle.kts").write_text("//")
    (tmp_path / "training-project" / "src").mkdir()
    (tmp_path / "README.md").write_text("x")
    root = find_gradle_root(tmp_path)
    assert root.name == "training-project"


def test_zip_slip_blocked(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # classic zip-slip path
        zf.writestr("../evil.txt", "pwned")
        zf.writestr("ok.txt", "fine")
    buf.seek(0)
    dest = tmp_path / "out"
    dest.mkdir()
    with zipfile.ZipFile(buf, "r") as zf:
        with pytest.raises(ValueError, match="Zip-slip|slip"):
            safe_extract(zf, dest)
