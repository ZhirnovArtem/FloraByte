from pydantic import BaseModel, Field
from .engine import run
from .model import Finding

class SastNodeParams(BaseModel):
    enabled_rules: list[str] | None = None
    exclude_tests: bool = True
    timeout_seconds: int = Field(default=120, ge=1, le=1800)

class NodeResult(BaseModel):
    status: str
    outputs: dict
    logs: list[str] = []

class SastKotlinNode:
    type = "scanner.sast_kotlin"
    params_schema = SastNodeParams

    def run(self, ctx, params: SastNodeParams, inputs: dict) -> NodeResult:
        project_path=inputs.get("project_path")
        if not project_path:
            return NodeResult(status="error",outputs={"findings":[],"summary":{}},logs=["Missing required input: project_path"])
        try:
            cfg={"exclude_tests":params.exclude_tests}
            if params.enabled_rules is not None: cfg["enabled_rules"]=params.enabled_rules
            result=run(project_path,cfg)
            payload=[f.model_dump(mode="json") for f in result.findings]
            return NodeResult(status="warning" if result.errors else "success",outputs={"findings":payload,"summary":result.summary()},logs=result.errors)
        except Exception as exc:
            # Node boundary contains scanner errors; workflow server remains alive.
            return NodeResult(status="error",outputs={"findings":[],"summary":{}},logs=[f"SAST failed: {type(exc).__name__}: {exc}"])
