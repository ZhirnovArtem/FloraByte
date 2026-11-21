"""source.upload_zip — unpack uploaded zip, detect Gradle project root."""

from __future__ import annotations

import shutil
import re
import uuid
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.config import get_settings
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

MAX_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILES = 5000


def find_gradle_root(base: Path) -> Path:
    """Find directory containing settings.gradle.kts or build.gradle.kts nearest to base."""
    # Prefer deepest settings.gradle.kts under base
    candidates: list[Path] = []
    for p in base.rglob("settings.gradle.kts"):
        candidates.append(p.parent)
    for p in base.rglob("build.gradle.kts"):
        candidates.append(p.parent)
    for p in base.rglob("settings.gradle"):
        candidates.append(p.parent)
    for p in base.rglob("build.gradle"):
        candidates.append(p.parent)
    if not candidates:
        return base
    # Prefer path that looks like training-project or shortest relative that still has src
    candidates = sorted(set(candidates), key=lambda x: (len(x.parts), str(x)))
    for c in candidates:
        if (c / "src").is_dir() or (c / "build.gradle.kts").exists() or (c / "settings.gradle.kts").exists():
            return c
    return candidates[0]


def safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract zip with zip-slip protection, size and file count limits."""
    total_size = 0
    count = 0
    for info in zf.infolist():
        if stat_is_symlink(info):
            raise ValueError(f"Symlinks not allowed: {info.filename}")
        count += 1
        if count > MAX_FILES:
            raise ValueError(f"Zip contains too many files (>{MAX_FILES})")
        # zip-slip
        member = info.filename.replace("\\", "/")
        # Reject absolute paths, traversal and odd Windows drive letters.
        if member.startswith("/") or any(part in ("..", "") for part in member.split("/")) or re.match(r"^[A-Za-z]:", member):
            raise ValueError(f"Zip-slip: unsafe archive member: {info.filename}")
        target = (dest / member).resolve()
        if not target.is_relative_to(dest.resolve()):
            raise ValueError(f"Zip-slip detected: {info.filename}")
        if info.file_size > MAX_ZIP_BYTES:
            raise ValueError(f"File too large in zip: {info.filename}")
        total_size += info.file_size
        if total_size > MAX_ZIP_BYTES:
            raise ValueError(f"Uncompressed size exceeds {MAX_ZIP_BYTES} bytes")
    zf.extractall(dest)


def stat_is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix symlink: external_attr high bits
    return (info.external_attr >> 16) & 0o170000 == 0o120000


class Params(BaseModel):
    upload_id: str = Field(..., description="ID returned by POST /api/uploads")
    subdir: str = Field("", description="Optional subdirectory inside the archive")


@register_node
class UploadZipNode(BaseNode):
    type = "source.upload_zip"
    label = "Upload ZIP"
    group = "source"
    inputs = [Port(name="in", kind="Any")]
    outputs = [Port(name="workspace", kind="Workspace")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        settings = get_settings()
        try:
            upload_id = str(uuid.UUID(params.upload_id))
        except (ValueError, AttributeError) as exc:
            raise ValueError("upload_id must be a valid UUID") from exc
        upload_path = settings.upload_dir / f"{upload_id}.zip"
        if not upload_path.is_file():
            raise FileNotFoundError(f"Upload not found: {upload_id}")

        extract_dir = Path(ctx.workspace) / "src"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True)

        with zipfile.ZipFile(upload_path, "r") as zf:
            safe_extract(zf, extract_dir)

        root = extract_dir
        if params.subdir:
            root = (extract_dir / params.subdir).resolve()
            if not root.is_relative_to(extract_dir.resolve()):
                raise ValueError("subdir must remain inside the uploaded archive")
            if not root.is_dir():
                raise FileNotFoundError(f"subdir not found in archive: {params.subdir}")

        gradle_root = find_gradle_root(root)
        return {"workspace": gradle_root}
