"""Fernet encryption for credentials. Key from APP_SECRET_KEY or generated file outside repo."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

def _key_file_path() -> Path:
    custom = os.environ.get("APP_SECRET_KEY_FILE", "").strip()
    if custom:
        return Path(custom)
    return Path.home() / ".florabyte" / "secret.key"


def is_production_env() -> bool:
    """Return True when running in a production / Render deployment environment."""
    if os.environ.get("REQUIRE_APP_SECRET_KEY", "").strip().lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("RENDER", "").strip().lower() in ("1", "true", "yes"):
        return True
    for var in ("ENVIRONMENT", "APP_ENV", "NODE_ENV"):
        if os.environ.get(var, "").strip().lower() in ("production", "prod"):
            return True
    return False


def _get_env_secret_key() -> str:
    direct = os.environ.get("APP_SECRET_KEY", "").strip()
    if direct:
        return direct
    for key, value in os.environ.items():
        if key.upper() == "APP_SECRET_KEY" and value.strip():
            return value.strip()
    return ""


def encryption_key_source() -> str:
    """Return 'env' when APP_SECRET_KEY is configured in environment, otherwise 'file'."""
    return "env" if _get_env_secret_key() else "file"


def _load_or_create_key() -> bytes:
    env_key = _get_env_secret_key()
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

    if is_production_env() and os.environ.get("ALLOW_EPHEMERAL_SECRET_KEY", "").strip().lower() not in ("1", "true", "yes"):
        raise RuntimeError(
            "APP_SECRET_KEY environment variable is required in production/Render so encrypted secrets survive restarts."
        )

    key_file = _key_file_path()
    if key_file.exists():
        return key_file.read_bytes().strip()

    key = Fernet.generate_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
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
