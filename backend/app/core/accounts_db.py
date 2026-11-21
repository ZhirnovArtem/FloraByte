"""Legacy SQLite account extraction helper for one-time migration into PostgreSQL.

Runtime authentication uses ONLY the primary SQLModel database configured by DATABASE_URL
(PostgreSQL in production) via the `users` table — no runtime dual-writes or fallback restores.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def extract_legacy_accounts_from_sqlite(db_path: Path) -> list[dict[str, Any]]:
    """Read account rows from a legacy SQLite file (`users` and/or `accounts` tables)."""
    if not db_path.exists():
        return []
    records: dict[str, dict[str, Any]] = {}
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table in ("users", "accounts"):
            if table not in tables:
                continue
            rows = conn.execute(
                f"SELECT id, email, password_hash, is_active, created_at FROM {table}"
            ).fetchall()
            for row in rows:
                email = str(row["email"] or "").strip().lower()
                pw_hash = str(row["password_hash"] or "").strip()
                if not email or not pw_hash:
                    continue
                if email not in records:
                    records[email] = {
                        "id": str(row["id"] or "").strip(),
                        "email": email,
                        "password_hash": pw_hash,
                        "is_active": bool(row["is_active"]) if row["is_active"] is not None else True,
                        "created_at": str(row["created_at"] or "") or None,
                    }
    return list(records.values())
