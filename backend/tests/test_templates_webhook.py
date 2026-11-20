from app.nodes.registry import NODE_REGISTRY
import app.nodes  # noqa


def test_webhook_registered():
    assert "notify.webhook" in NODE_REGISTRY
    cls = NODE_REGISTRY["notify.webhook"]
    assert cls.group == "notify"


def test_templates_dir_has_samples():
    from pathlib import Path
    d = Path(__file__).resolve().parents[1] / "templates"
    assert d.exists()
    files = list(d.glob("*.json"))
    assert len(files) >= 2
