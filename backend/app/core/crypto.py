"""Fernet encryption for credentials. Key from APP_SECRET_KEY or generated file outside repo."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_FILE = Path(os.environ.get("APP_SECRET_KEY_FILE", "/tmp/ai_security_workflow_secret.key"))


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("APP_SECRET_KEY")
    if env_key:
        # Accept raw Fernet key or generate from string (pad/hash to 32 url-safe)
        try:
            return env_key.encode() if len(env_key) == 44 else Fernet.generate_key()  # fallback safe
        except Exception:
            pass
        # If user provided a passphrase-like string, derive a key deterministically for demo
        import base64
        import hashlib
        digest = hashlib.sha256(env_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)

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


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    try:
        return get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Invalid or corrupted credential ciphertext") from e
