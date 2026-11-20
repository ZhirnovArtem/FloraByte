import pytest
from app.nodes.logic.if_else import IfElseNode, Params as IfParams, _resolve, _compare
from app.nodes.logic.regex_match import RegexMatchNode, Params as RxParams
from app.nodes.base import NodeContext
import asyncio


def test_resolve_count():
    findings = [{"category": "SECRET", "severity": "HIGH"}, {"category": "SAST", "severity": "LOW"}]
    assert _resolve("findings.count", {"findings": findings}) == 2
    assert _resolve("findings.by_category.SECRET", {"findings": findings}) == 1
    assert _resolve("findings.max_severity", {"findings": findings}) == "HIGH"


def test_compare_ops():
    assert _compare(3, ">", 1) is True
    assert _compare("abc", "regex", "a.c") is True
    assert _compare("x", "in", "xyz") is True


@pytest.mark.asyncio
async def test_if_else_branches():
    node = IfElseNode()
    ctx = NodeContext(run_id="r", node_id="n")
    findings = [{"category": "SECRET"}]
    out = await node.run(ctx, {"findings": findings}, IfParams(left="findings.count", op=">", right="0"))
    assert "true" in out
    out2 = await node.run(ctx, {"findings": []}, IfParams(left="findings.count", op=">", right="0"))
    assert "false" in out2


@pytest.mark.asyncio
async def test_regex_node():
    node = RegexMatchNode()
    ctx = NodeContext(run_id="r", node_id="n")
    out = await node.run(ctx, {"in": "hello world"}, RxParams(pattern=r"world"))
    assert "match" in out
    out2 = await node.run(ctx, {"in": "hello"}, RxParams(pattern=r"world"))
    assert "no_match" in out2
