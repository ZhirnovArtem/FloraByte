"""Base node contract. Every concrete node is one file + @register_node."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field


PortKind = Literal["Workspace", "Findings", "Report", "Any", "Boolean", "None"]


class Port(BaseModel):
    name: str
    kind: PortKind = "Any"
    label: str | None = None


class NodeContext(BaseModel):
    """Runtime context passed to every node."""
    model_config = {"arbitrary_types_allowed": True}

    run_id: str
    node_id: str
    workspace: Any = None  # Path
    settings: Any = None
    emit: Any = None  # optional async callback for progress events
    owner_id: str | None = None


class BaseNode(ABC):
    type: ClassVar[str]
    label: ClassVar[str]
    group: ClassVar[str]  # source | trigger | logic | scanner | ai | notify | findings
    inputs: ClassVar[list[Port]] = []
    outputs: ClassVar[list[Port]] = []
    Params: ClassVar[type[BaseModel]] = BaseModel
    continue_downstream_on_error: ClassVar[bool] = False

    @abstractmethod
    async def run(
        self,
        ctx: NodeContext,
        inputs: dict[str, Any],
        params: BaseModel,
    ) -> dict[str, Any]:
        """Execute the node. Return dict keyed by output port names."""
        ...

    @classmethod
    def params_schema(cls) -> dict[str, Any]:
        return cls.Params.model_json_schema()

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "type": cls.type,
            "label": cls.label,
            "group": cls.group,
            "inputs": [p.model_dump() for p in cls.inputs],
            "outputs": [p.model_dump() for p in cls.outputs],
            "params_schema": cls.params_schema(),
        }
