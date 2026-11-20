"""FastAPI entrypoint — Phase C."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.node_types import router as node_types_router
from app.api.workflows import router as workflows_router
from app.api.runs import router as runs_router
from app.api.uploads import router as uploads_router
from app.api.ws import router as ws_router
from app.api.credentials import router as credentials_router
from app.config import get_settings
from app.core.db import init_db
from app.core.logging import setup_logging
import app.nodes  # noqa: F401  — populate registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    get_settings()
    init_db()
    yield


app = FastAPI(
    title="AI Security Workflow",
    version="0.3.0-phase-c",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


@app.get("/health")
def health():
    return {"status": "ok", "phase": "C"}
