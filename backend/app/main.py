"""FastAPI entrypoint — Auth sessions, CSRF, CORS, and routers."""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlmodel import Session

import app.nodes  # noqa: F401
from app.api.ai_generator import router as ai_generator_router
from app.api.auth import router as auth_router
from app.api.ci import router as ci_router
from app.api.credentials import router as credentials_router
from app.api.custom_nodes import router as custom_nodes_router
from app.api.integrations import router as integrations_router
from app.api.node_types import router as node_types_router
from app.api.runs import router as runs_router
from app.api.templates import router as templates_router
from app.api.uploads import router as uploads_router
from app.api.workflows import router as workflows_router
from app.api.ws import router as ws_router
from app.config import get_settings
from app.core.auth import SESSION_COOKIE_NAME, resolve_session_from_token
from app.core.crypto import encryption_key_source, get_fernet
from app.core.db import get_engine, init_db
from app.core.logging import setup_logging
from app.engine.scheduler import reload_schedules, set_run_callback, start_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    get_settings()
    get_fernet()
    if encryption_key_source() != "env":
        import logging
        logging.getLogger(__name__).warning(
            "APP_SECRET_KEY is not set in environment; using local file key (configure APP_SECRET_KEY for persistent deployments)."
        )
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
        reload_schedules(session)
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

app.include_router(auth_router)
app.include_router(node_types_router)
app.include_router(workflows_router)
app.include_router(runs_router)
app.include_router(uploads_router)
app.include_router(ws_router)
app.include_router(credentials_router)
app.include_router(templates_router)
app.include_router(ci_router)
app.include_router(ai_generator_router)
app.include_router(integrations_router)
app.include_router(custom_nodes_router)


def _origin_allowed(origin: str, request: Request, allowed_origins: list[str]) -> bool:
    if not origin:
        return True
    cleaned = origin.rstrip("/")
    if cleaned in [o.rstrip("/") for o in allowed_origins]:
        return True
    req_host = request.headers.get("host", "")
    parsed = urlsplit(cleaned)
    return bool(req_host and parsed.netloc == req_host)


@app.middleware("http")
async def protect_workflow_api(request: Request, call_next):
    """Enforce per-user HttpOnly cookie sessions + CSRF (or optional server-to-server token)."""
    path = request.url.path
    if request.method == "OPTIONS" or not path.startswith("/api/"):
        return await call_next(request)

    if path.startswith("/api/auth/") or path.startswith("/api/ci/"):
        return await call_next(request)

    settings = get_settings()

    # 1. User session via HttpOnly cookie
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
    if raw_cookie:
        with Session(get_engine()) as session:
            resolved = resolve_session_from_token(session, raw_cookie)
        if resolved:
            sess_row, user = resolved
            request.state.user = user
            request.state.user_session = sess_row
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                origin = request.headers.get("origin", "")
                if origin and not _origin_allowed(origin, request, settings.cors_origins_list()):
                    return JSONResponse({"detail": "Недопустимый Origin (CSRF)"}, status_code=403)
                csrf = request.headers.get("x-csrf-token", "")
                if not csrf or not secrets.compare_digest(csrf, sess_row.csrf_token):
                    return JSONResponse({"detail": "Недействительный X-CSRF-Token"}, status_code=403)
            return await call_next(request)

    # 2. Optional trusted server-to-server integration token (never used by browser UI)
    expected = settings.workflow_access_token
    supplied = request.headers.get("X-Workflow-Token", "")
    if expected and supplied and secrets.compare_digest(supplied, expected):
        request.state.service_auth = True
        return await call_next(request)

    if path == "/api/uploads":
        ci_secret = os.environ.get("CI_TOKEN", "")
        ci_supplied = request.headers.get("X-CI-Token", "")
        if ci_secret and ci_supplied and secrets.compare_digest(ci_supplied, ci_secret):
            request.state.service_auth = True
            return await call_next(request)

    # 3. Legacy/dev opt-out only when AUTH_REQUIRED=0 AND no WORKFLOW_ACCESS_TOKEN set
    if not settings.auth_required and not expected:
        return await call_next(request)

    return JSONResponse({"detail": "Требуется авторизация"}, status_code=401)


@app.get("/health")
def health():
    db_url = get_settings().database_url.lower()
    return {
        "status": "ok",
        "phase": "F",
        "version": "1.0.0",
        "secret_key_source": encryption_key_source(),
        "storage_backend": "postgresql" if "postgres" in db_url else "sqlite",
    }
