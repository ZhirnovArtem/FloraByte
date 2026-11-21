from app.nodes.registry import NODE_REGISTRY, list_node_types, get_node_class
import app.nodes  # noqa: F401


REQUIRED_TYPES = [
    "source.upload_zip",
    "source.git_clone",
    "trigger.manual",
    "trigger.schedule",
    "logic.if_else",
    "logic.compare",
    "logic.regex",
    "scanner.secrets",
    "scanner.sca",
    "scanner.sast",
    "findings.merge",
    "findings.export",
    "ai.explain",
    "notify.telegram",
    "notify.webhook",
]


def test_all_required_nodes_registered():
    for t in REQUIRED_TYPES:
        assert t in NODE_REGISTRY, f"missing node type: {t}"


def test_list_node_types_shape():
    items = list_node_types()
    assert len(items) >= len(REQUIRED_TYPES)
    for item in items:
        assert "type" in item
        assert "label" in item
        assert "group" in item
        assert "inputs" in item
        assert "outputs" in item
        assert "params_schema" in item


def test_get_node_class():
    cls = get_node_class("trigger.manual")
    assert cls.type == "trigger.manual"
    assert cls.group == "trigger"
