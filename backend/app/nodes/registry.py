"""Node registry. New node = one file with @register_node, no engine/API changes."""

from __future__ import annotations

from typing import Type

from app.nodes.base import BaseNode

NODE_REGISTRY: dict[str, Type[BaseNode]] = {}


def register_node(cls: Type[BaseNode]) -> Type[BaseNode]:
    if not getattr(cls, "type", None):
        raise ValueError(f"Node class {cls.__name__} must define ClassVar 'type'")
    if cls.type in NODE_REGISTRY:
        raise ValueError(f"Duplicate node type: {cls.type}")
    NODE_REGISTRY[cls.type] = cls
    return cls


def get_node_class(node_type: str) -> Type[BaseNode]:
    try:
        return NODE_REGISTRY[node_type]
    except KeyError as e:
        raise KeyError(f"Unknown node type: {node_type}") from e


def list_node_types() -> list[dict]:
    return [cls.describe() for cls in sorted(NODE_REGISTRY.values(), key=lambda c: c.type)]
