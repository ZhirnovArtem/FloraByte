"""Node package with automatic discovery of all node modules via pkgutil."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from app.nodes.registry import NODE_REGISTRY, get_node_class, list_node_types, register_node


def discover_nodes() -> None:
    """Import all non-private submodules under app.nodes so @register_node executes automatically."""
    pkg_dir = Path(__file__).resolve().parent
    for mod_info in pkgutil.walk_packages([str(pkg_dir)], prefix="app.nodes."):
        leaf = mod_info.name.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue
        if mod_info.name in ("app.nodes.base", "app.nodes.registry"):
            continue
        importlib.import_module(mod_info.name)


discover_nodes()

__all__ = ["NODE_REGISTRY", "discover_nodes", "get_node_class", "list_node_types", "register_node"]
