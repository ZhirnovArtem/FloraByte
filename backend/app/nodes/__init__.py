"""Node package. Importing subpackages registers nodes via decorators."""

from app.nodes.registry import NODE_REGISTRY, get_node_class, list_node_types, register_node

# Side-effect imports to populate registry
from app.nodes import source, triggers, logic, scanners, findings, ai, notify  # noqa: F401

__all__ = ["NODE_REGISTRY", "get_node_class", "list_node_types", "register_node"]
