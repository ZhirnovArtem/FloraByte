"""Workflow graph validation and topological ordering."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


class GraphError(ValueError):
    pass


def _port_kind(node_type: str, port_name: str, direction: str, registry: dict) -> str | None:
    cls = registry.get(node_type)
    if not cls:
        return None
    ports = cls.inputs if direction == "in" else cls.outputs
    for p in ports:
        if p.name == port_name:
            return p.kind
    # default single port names
    if direction == "in" and port_name in ("in", "workspace", "findings", "report", ""):
        return "Any"
    if direction == "out" and port_name in ("out", "workspace", "findings", "report", "true", "false"):
        return "Any"
    return None


def validate_graph(graph: dict[str, Any], registry: dict) -> None:
    """Validate workflow graph: nodes exist, no cycles, one trigger per component, port compatibility."""
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
        out_edges[src].append(e)
        in_degree[tgt] = in_degree.get(tgt, 0) + 1

    # Cycle detection via Kahn
    q = deque([nid for nid, d in in_degree.items() if d == 0])
    visited = 0
    order: list[str] = []
    while q:
        u = q.popleft()
        order.append(u)
        visited += 1
        for e in out_edges[u]:
            v = e["target"]
            in_degree[v] -= 1
            if in_degree[v] == 0:
                q.append(v)
    if visited != len(nodes):
        raise GraphError("Workflow graph contains a cycle")

    # Exactly one trigger in the connected component (simplified: at least one trigger, warn on many)
    triggers = [n for n in nodes.values() if str(n.get("type", "")).startswith("trigger.")]
    if len(triggers) == 0:
        raise GraphError("Workflow must have at least one trigger node")
    if len(triggers) > 1:
        # allow for now, but document; strict mode could reject
        pass

    # Port kind compatibility (soft: only error on known incompatible pairs)
    compatible = {
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
    for e in edges:
        src_node = nodes[e["source"]]
        tgt_node = nodes[e["target"]]
        src_handle = e.get("sourceHandle") or "out"
        tgt_handle = e.get("targetHandle") or "in"
        sk = _port_kind(src_node["type"], src_handle, "out", registry) or "Any"
        tk = _port_kind(tgt_node["type"], tgt_handle, "in", registry) or "Any"
        if (sk, tk) not in compatible and sk != "Any" and tk != "Any":
            raise GraphError(
                f"Incompatible ports on edge {e.get('id')}: {sk} → {tk} "
                f"({src_node['type']}.{src_handle} → {tgt_node['type']}.{tgt_handle})"
            )


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
