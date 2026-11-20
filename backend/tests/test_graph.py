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
