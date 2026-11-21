import pytest
from app.engine.graph import validate_graph, topological_order, GraphError
from app.nodes.registry import NODE_REGISTRY
import app.nodes  # noqa


def test_topo_simple():
    g = {
        "nodes": [
            {"id": "t", "type": "trigger.manual"},
            {"id": "s", "type": "source.upload_zip"},
            {"id": "e", "type": "findings.export"},
        ],
        "edges": [
            {"id": "e1", "source": "t", "target": "s"},
            {"id": "e2", "source": "s", "target": "e"},
        ],
    }
    order = topological_order(g)
    assert order.index("t") < order.index("s") < order.index("e")


def test_cycle_rejected():
    g = {
        "nodes": [
            {"id": "a", "type": "trigger.manual"},
            {"id": "b", "type": "logic.if_else"},
        ],
        "edges": [
            {"id": "e1", "source": "a", "target": "b"},
            {"id": "e2", "source": "b", "target": "a"},
        ],
    }
    with pytest.raises(GraphError, match="cycle"):
        validate_graph(g, NODE_REGISTRY)


def test_unknown_type():
    g = {"nodes": [{"id": "x", "type": "no.such"}], "edges": []}
    with pytest.raises(GraphError, match="Unknown"):
        validate_graph(g, NODE_REGISTRY)


def test_needs_trigger():
    g = {
        "nodes": [{"id": "s", "type": "source.upload_zip"}],
        "edges": [],
    }
    with pytest.raises(GraphError, match="trigger"):
        validate_graph(g, NODE_REGISTRY)


def test_edge_into_trigger_rejected():
    g = {
        "nodes": [
            {"id": "s", "type": "source.upload_zip"},
            {"id": "t", "type": "trigger.manual"},
        ],
        "edges": [{"id": "e1", "source": "s", "target": "t"}],
    }
    with pytest.raises(GraphError, match="does not accept input"):
        validate_graph(g, NODE_REGISTRY)


def test_unknown_port_rejected():
    g = {
        "nodes": [
            {"id": "t", "type": "trigger.manual"},
            {"id": "s", "type": "source.upload_zip"},
        ],
        "edges": [{"id": "e1", "source": "t", "target": "s", "targetHandle": "bogus"}],
    }
    with pytest.raises(GraphError, match="Unknown input port"):
        validate_graph(g, NODE_REGISTRY)


def test_incompatible_ports_rejected():
    g = {
        "nodes": [
            {"id": "t", "type": "trigger.manual"},
            {"id": "s", "type": "source.upload_zip"},
            {"id": "e", "type": "findings.export"},
        ],
        "edges": [
            {"id": "e1", "source": "t", "target": "s"},
            {"id": "e2", "source": "s", "target": "e"},
        ],
    }
    with pytest.raises(GraphError, match="Incompatible ports"):
        validate_graph(g, NODE_REGISTRY)


def test_multi_branch_requires_source_handle():
    g = {
        "nodes": [
            {"id": "t", "type": "trigger.manual"},
            {"id": "c", "type": "logic.if_else"},
            {"id": "e", "type": "findings.export"},
        ],
        "edges": [
            {"id": "e1", "source": "t", "target": "c"},
            {"id": "e2", "source": "c", "target": "e"},
        ],
    }
    with pytest.raises(GraphError, match="multiple output ports"):
        validate_graph(g, NODE_REGISTRY)


def test_duplicate_target_port_rejected():
    g = {
        "nodes": [
            {"id": "t", "type": "trigger.manual"},
            {"id": "s", "type": "source.upload_zip"},
            {"id": "sc1", "type": "scanner.secrets"},
            {"id": "sc2", "type": "scanner.sast"},
            {"id": "m", "type": "findings.merge"},
        ],
        "edges": [
            {"id": "e1", "source": "t", "target": "s"},
            {"id": "e2", "source": "s", "target": "sc1"},
            {"id": "e3", "source": "s", "target": "sc2"},
            {"id": "e4", "source": "sc1", "target": "m", "targetHandle": "a"},
            {"id": "e5", "source": "sc2", "target": "m", "targetHandle": "a"},
        ],
    }
    with pytest.raises(GraphError, match="Multiple edges target"):
        validate_graph(g, NODE_REGISTRY)
