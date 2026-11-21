"""source.git_clone — shallow clone from allowlist, detect Gradle root."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.config import get_settings
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.source.upload_zip import find_gradle_root


class Params(BaseModel):
    url: str = Field(..., description="HTTPS git URL (must be in allowlist)")
    subdir: str = Field("", description="Subdirectory after clone")
    branch: str = Field("", description="Optional branch/tag")


@register_node
class GitCloneNode(BaseNode):
    type = "source.git_clone"
    label = "Git Clone"
    group = "source"
    inputs = [Port(name="in", kind="Any")]
    outputs = [Port(name="workspace", kind="Workspace")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, Params)
        settings = get_settings()
        url = params.url.strip().rstrip("/")
        allowed = settings.git_allowlist_set()
        # normalize for comparison
        if url not in allowed and url + ".git" not in allowed:
            # allow exact match ignoring trailing .git
            normalized = {u.removesuffix(".git") for u in allowed}
            if url.removesuffix(".git") not in normalized:
                raise PermissionError(
                    f"URL not in allowlist: {url}. Allowed: {sorted(allowed)}"
                )

        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("Only HTTPS git URLs are allowed")

        dest = Path(ctx.workspace) / "repo"
        if dest.exists():
            shutil.rmtree(dest)

        cmd = ["git", "clone", "--depth", "1"]
        if params.branch:
            cmd += ["--branch", params.branch]
        cmd += [url, str(dest)]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {stderr.decode(errors='replace')}")

        root = dest
        if params.subdir:
            root = (dest / params.subdir).resolve()
            if not root.is_relative_to(dest.resolve()):
                raise ValueError("subdir must remain inside the cloned repository")
            if not root.is_dir():
                raise FileNotFoundError(f"subdir not found after clone: {params.subdir}")

        gradle_root = find_gradle_root(root)
        return {"workspace": gradle_root}
