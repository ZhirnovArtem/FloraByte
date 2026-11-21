"""Fernet encryption for credentials. Key from APP_SECRET_KEY or generated file outside repo."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_FILE = Path(os.environ.get("APP_SECRET_KEY_FILE", "/tmp/ai_security_workflow_secret.key"))


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("APP_SECRET_KEY", "").strip()
    if env_key:
        raw = env_key.encode("ascii", errors="strict")
        try:
            Fernet(raw)
        except Exception as e:
            raise ValueError(
                "APP_SECRET_KEY must be a valid 44-character URL-safe base64 Fernet key "
                "(generate via `python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`)"
            ) from e
        return raw

    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes().strip()

    key = Fernet.generate_key()
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(key)
    try:
        _KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key


_fernet: Fernet | None = None
_fernet_key: bytes | None = None


def reset_fernet_cache() -> None:
    global _fernet, _fernet_key
    _fernet = None
    _fernet_key = None


def get_fernet() -> Fernet:
    global _fernet, _fernet_key
    key = _load_or_create_key()
    if _fernet is None or _fernet_key != key:
        _fernet = Fernet(key)
        _fernet_key = key
    return _fernet


def encrypt(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    try:
        return get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Invalid or corrupted credential ciphertext") from e
