"""FastAPI entrypoint — Phase F (freeze)."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import secrets
from fastapi.middleware.cors import CORSMiddleware

from app.api.node_types import router as node_types_router
from app.api.workflows import router as workflows_router
from app.api.runs import router as runs_router
from app.api.uploads import router as uploads_router
from app.api.ws import router as ws_router
from app.api.credentials import router as credentials_router
from app.api.templates import router as templates_router
from app.api.ci import router as ci_router
from app.api.ai_generator import router as ai_generator_router
from app.config import get_settings
from app.core.db import init_db, get_engine
from app.core.logging import setup_logging
from app.engine.scheduler import reload_schedules, set_run_callback, start_scheduler
from sqlmodel import Session
import app.nodes  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    get_settings()
    init_db()

    # wire scheduler → executor
    from app.engine.executor import Executor

    def session_factory():
        return Session(get_engine())

    executor = Executor(session_factory)

    async def _cb(workflow_id: str, graph: dict) -> str:
        return await executor.run_workflow(workflow_id, graph, trigger="schedule", wait=False)

    set_run_callback(_cb)
    with Session(get_engine()) as session:
        n = reload_schedules(session)
    start_scheduler()

    yield
    from app.engine.scheduler import scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="AI Security Workflow",
    version="1.0.0-phase-f",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(node_types_router)
app.include_router(workflows_router)
app.include_router(runs_router)
app.include_router(uploads_router)
app.include_router(ws_router)
app.include_router(credentials_router)
app.include_router(templates_router)
app.include_router(ci_router)
app.include_router(ai_generator_router)




@app.middleware("http")
async def protect_workflow_api(request: Request, call_next):
    """Optional shared-token access for exposed demos, not a multi-user auth system."""
    path = request.url.path
    if request.method != "OPTIONS" and path.startswith("/api/") and not path.startswith("/api/ci/"):
        expected = get_settings().workflow_access_token
        if expected:
            supplied = request.headers.get("X-Workflow-Token", "")
            # CI uploads can authenticate using CI_TOKEN instead of the UI token.
            ci_secret = __import__("os").environ.get("CI_TOKEN", "") if path == "/api/uploads" else ""
            ci_supplied = request.headers.get("X-CI-Token", "") if ci_secret else ""
            if not secrets.compare_digest(supplied, expected) and not (
                ci_secret and secrets.compare_digest(ci_supplied, ci_secret)
            ):
                return JSONResponse({"detail": "Missing/invalid X-Workflow-Token"}, status_code=401)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok", "phase": "F", "version": "1.0.0"}
