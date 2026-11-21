"""Site-wide log ingestion (frontend errors) and log inspection/download API."""

from __future__ import annotations

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.core.auth import get_current_user
from app.core.logging import get_log_paths, tail_log_file
from app.core.masking import redact_text
from app.core.models import User
from app.core.rate_limit import SlidingWindowLimiter

router = APIRouter(prefix="/api/logs", tags=["logs"])

_frontend_logger = logging.getLogger("app.frontend")
_client_log_limiter = SlidingWindowLimiter(max_requests=40, window_seconds=60)


class ClientLogRequest(BaseModel):
    level: Literal["error", "warning", "info"] = "error"
    message: str = Field(..., min_length=1, max_length=2000)
    source: str = Field("browser", max_length=120)
    url: str = Field("", max_length=500)
    status: int | None = None
    stack: str = Field("", max_length=4000)


def _single_line(value: str, max_len: int) -> str:
    cleaned = redact_text(value or "").replace("\r", " ").replace("\n", " | ").strip()
    return cleaned[:max_len]


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/client-error")
def report_client_error(body: ClientLogRequest, request: Request):
    ip = _client_ip(request)
    if not _client_log_limiter.allow(f"client_log:{ip}"):
        raise HTTPException(429, "Слишком много записей логов от клиента.")

    msg = _single_line(body.message, 2000)
    src = _single_line(body.source, 120)
    page_url = _single_line(body.url, 500)
    stack = _single_line(body.stack, 1500)
    status_part = f" status={body.status}" if body.status is not None else ""
    url_part = f" url={page_url}" if page_url else ""
    stack_part = f" stack={stack}" if stack else ""

    formatted = f"[{src}]{status_part}{url_part} ip={ip} msg={msg}{stack_part}"
    if body.level == "warning":
        _frontend_logger.warning("%s", formatted)
    elif body.level == "info":
        _frontend_logger.info("%s", formatted)
    else:
        _frontend_logger.error("%s", formatted)
    return {"ok": True}


@router.get("")
def get_logs(
    kind: Literal["errors", "app"] = Query("errors"),
    lines: int = Query(200, ge=1, le=1000),
    user: Optional[User] = Depends(get_current_user),
):
    _ = user
    return tail_log_file(kind=kind, lines=lines)


@router.get("/download")
def download_log(
    kind: Literal["errors", "app"] = Query("errors"),
    user: Optional[User] = Depends(get_current_user),
):
    _ = user
    app_path, err_path = get_log_paths()
    target = err_path if kind == "errors" else app_path
    content = ""
    if target.exists():
        content = redact_text(target.read_text(encoding="utf-8", errors="replace"))
    filename = "florabyte-errors.log" if kind == "errors" else "florabyte.log"
    return PlainTextResponse(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
