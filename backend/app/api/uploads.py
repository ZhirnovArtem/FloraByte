from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import get_settings

router = APIRouter(prefix="/api/uploads", tags=["uploads"])

MAX_UPLOAD = 50 * 1024 * 1024


@router.post("")
async def upload_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Only .zip files are accepted")
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    dest = settings.upload_dir / f"{upload_id}.zip"

    size = 0
    with dest.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD:
                dest.unlink(missing_ok=True)
                raise HTTPException(400, f"File exceeds {MAX_UPLOAD} bytes")
            out.write(chunk)

    return {"upload_id": upload_id, "filename": file.filename, "size": size}
