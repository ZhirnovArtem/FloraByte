"""Legacy JSON user-store extraction helper for one-time migration into PostgreSQL.

Runtime authentication uses ONLY the primary database configured by DATABASE_URL (`users` table).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def extract_legacy_accounts_from_json(json_path: Path) -> list[dict[str, Any]]:
    """Read account rows from a legacy `users.json` file for offline migration."""
    if not json_path.exists():
        return []
    try:
        raw = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    items: list[dict[str, Any]] = []
    if isinstance(raw, dict) and isinstance(raw.get("users"), dict):
        items = [v for v in raw["users"].values() if isinstance(v, dict)]
    elif isinstance(raw, list):
        items = [v for v in raw if isinstance(v, dict)]

    out: list[dict[str, Any]] = []
    for item in items:
        email = str(item.get("email") or "").strip().lower()
        pw_hash = str(item.get("password_hash") or "").strip()
        if not email or not pw_hash:
            continue
        out.append(
            {
                "id": str(item.get("id") or "").strip(),
                "email": email,
                "password_hash": pw_hash,
                "is_active": bool(item.get("is_active", True)),
                "created_at": str(item.get("created_at") or "") or None,
            }
        )
    return out
