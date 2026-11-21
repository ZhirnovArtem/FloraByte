"""Workflow graph validation and topological ordering."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


class GraphError(ValueError):
    pass


_COMPATIBLE_PORTS = {
    ("Workspace", "Workspace"),
    ("Findings", "Findings"),
    ("Report", "Report"),
    ("Any", "Any"),
    ("Boolean", "Boolean"),
    ("Workspace", "Any"),
    ("Findings", "Any"),
    ("Report", "Any"),
    ("Boolean", "Any"),
    ("Any", "Workspace"),
    ("Any", "Findings"),
    ("Any", "Report"),
    ("Any", "Boolean"),
}


def _resolve_port(
    node_id: str,
    node_type: str,
    handle: str | None,
    direction: str,
    registry: dict,
) -> tuple[str, str]:
    """Return (resolved_port_name, port_kind) or raise GraphError if invalid."""
    cls = registry.get(node_type)
    if not cls:
        raise GraphError(f"Unknown node type: {node_type} (node {node_id})")

    ports = cls.inputs if direction == "in" else cls.outputs
    if not ports:
        side = "input" if direction == "in" else "output"
        raise GraphError(f"Node {node_id} ({node_type}) does not accept {side} connections")

    if handle:
        for p in ports:
            if p.name == handle:
                return p.name, p.kind
        available = ", ".join(p.name for p in ports)
        side = "input" if direction == "in" else "output"
        raise GraphError(
            f"Unknown {side} port {handle!r} on node {node_id} ({node_type}); available: {available}"
        )

    # Handle omitted: for multi-branch outputs (e.g. true/false, match/no_match), require explicit handle
    if direction == "out" and len(ports) > 1:
        available = ", ".join(p.name for p in ports)
        raise GraphError(
            f"Node {node_id} ({node_type}) has multiple output ports ({available}); edge must specify sourceHandle"
        )

    default_port = ports[0]
    return default_port.name, default_port.kind


def validate_graph(graph: dict[str, Any], registry: dict) -> None:
    """Validate workflow graph: nodes exist, no cycles, trigger present, ports & handles valid."""
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])

    if not nodes:
        raise GraphError("Workflow has no nodes")

    for nid, n in nodes.items():
        t = n.get("type")
        if t not in registry:
            raise GraphError(f"Unknown node type: {t} (node {nid})")

    # Build adjacency
    out_edges: dict[str, list[dict]] = defaultdict(list)
    in_degree: dict[str, int] = {nid: 0 for nid in nodes}
    for e in edges:
        src, tgt = e.get("source"), e.get("target")
        if src not in nodes or tgt not in nodes:
            raise GraphError(f"Edge references missing node: {e.get('id')}")
        if src == tgt:
            raise GraphError(f"Self-loop on node {src}")
        out_edges[src].append(e)
        in_degree[tgt] = in_degree.get(tgt, 0) + 1

    # Cycle detection via Kahn
    q = deque([nid for nid, d in in_degree.items() if d == 0])
    visited = 0
    while q:
        u = q.popleft()
        visited += 1
        for e in out_edges[u]:
            v = e["target"]
            in_degree[v] -= 1
            if in_degree[v] == 0:
                q.append(v)
    if visited != len(nodes):
        raise GraphError("Workflow graph contains a cycle")

    # At least one trigger node
    triggers = [n for n in nodes.values() if str(n.get("type", "")).startswith("trigger.")]
    if len(triggers) == 0:
        raise GraphError("Workflow must have at least one trigger node")

    # Port existence, compatibility, and single-target-handle collision check
    used_target_ports: set[tuple[str, str]] = set()
    for e in edges:
        src_node = nodes[e["source"]]
        tgt_node = nodes[e["target"]]
        src_port, sk = _resolve_port(
            e["source"], src_node["type"], e.get("sourceHandle"), "out", registry
        )
        tgt_port, tk = _resolve_port(
            e["target"], tgt_node["type"], e.get("targetHandle"), "in", registry
        )
        if (sk, tk) not in _COMPATIBLE_PORTS:
            raise GraphError(
                f"Incompatible ports on edge {e.get('id')}: {sk} → {tk} "
                f"({src_node['type']}.{src_port} → {tgt_node['type']}.{tgt_port})"
            )
        target_slot = (e["target"], tgt_port)
        if target_slot in used_target_ports:
            raise GraphError(
                f"Multiple edges target the same input port {tgt_port!r} on node {e['target']}"
            )
        used_target_ports.add(target_slot)


def topological_order(graph: dict[str, Any]) -> list[str]:
    """Return node ids in topological order."""
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    out_edges: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = {nid: 0 for nid in nodes}
    for e in edges:
        out_edges[e["source"]].append(e["target"])
        in_degree[e["target"]] = in_degree.get(e["target"], 0) + 1
    q = deque([nid for nid, d in in_degree.items() if d == 0])
    order: list[str] = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in out_edges[u]:
            in_degree[v] -= 1
            if in_degree[v] == 0:
                q.append(v)
    if len(order) != len(nodes):
        raise GraphError("Cycle detected during topological sort")
    return order


def incoming_edges(graph: dict[str, Any], node_id: str) -> list[dict]:
    return [e for e in graph.get("edges", []) if e.get("target") == node_id]


def outgoing_edges(graph: dict[str, Any], node_id: str) -> list[dict]:
    return [e for e in graph.get("edges", []) if e.get("source") == node_id]
