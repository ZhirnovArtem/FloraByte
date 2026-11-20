"""FastAPI entrypoint — Phase A skeleton."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.node_types import router as node_types_router
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
    version="0.1.0-phase-a",
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


@app.get("/health")
def health():
    return {"status": "ok", "phase": "A"}
