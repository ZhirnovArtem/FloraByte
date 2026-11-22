from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


class Params(BaseModel):
    cron: str = Field("", description="Cron expression, e.g. '0 9 * * 1-5' (оставьте пустым при использовании интервала)")
    interval_seconds: int | None = Field(None, description="Интервал запуска на сервере в секундах (минимум 30с; повтор делает сервер)")


@register_node
class ScheduleTriggerNode(BaseNode):
    type = "trigger.schedule"
    label = "Schedule Trigger"
    group = "trigger"
    inputs = []
    outputs = [Port(name="out", kind="Any")]
    Params = Params

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        # Actual firing is done by APScheduler; when run as part of graph, just signal
        return {"out": {"triggered": True, "run_id": ctx.run_id, "source": "schedule"}}
