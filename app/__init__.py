"""Package shim so `uvicorn app.main:app` works from the repository root as well as backend/."""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
_BACKEND_APP = _BACKEND_DIR / "app"

if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

if _BACKEND_APP.is_dir():
    __path__ = [str(_BACKEND_APP)]
