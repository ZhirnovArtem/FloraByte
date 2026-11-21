from app.core.masking import mask_secret, mask_evidence, redact_text
from app.core.crypto import encrypt, decrypt


def test_mask_secret():
    assert mask_secret("abcdefghijklmnop") == "************mnop"
    assert mask_secret("short") == "****"
    assert mask_secret(None) == ""


def test_mask_evidence_redacts_tokens():
    text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"'
    m = mask_evidence(text)
    assert m is not None
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in m
    assert "****" in m or "*" in m


def test_encrypt_decrypt_roundtrip():
    plain = "1234567890:AAFakeTokenForUnitTestsOnly1234567890"
    token = encrypt(plain)
    assert token != plain
    assert decrypt(token) == plain


def test_redact_known_secret():
    secret = "super-secret-value-12345"
    msg = f"Sending token {secret} to upstream"
    assert secret not in redact_text(msg, [secret])


def test_app_secret_key_validation(monkeypatch):
    import pytest
    from cryptography.fernet import Fernet
    from app.core.crypto import reset_fernet_cache

    monkeypatch.setenv("APP_SECRET_KEY", "too-short-invalid-key")
    reset_fernet_cache()
    with pytest.raises(ValueError, match="APP_SECRET_KEY"):
        encrypt("hello")

    valid_key = Fernet.generate_key().decode()
    monkeypatch.setenv("APP_SECRET_KEY", valid_key)
    reset_fernet_cache()
    ct = encrypt("hello-persist")
    # Simulate restart with same key
    reset_fernet_cache()
    assert decrypt(ct) == "hello-persist"
    reset_fernet_cache()
