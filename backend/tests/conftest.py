"""Shared pytest helpers for FloraByte tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.auth import login_limiter, register_limiter


def authenticate_client(
    client: TestClient,
    email: str = "tester@florabyte.local",
    password: str = "StrongPass123!",
) -> dict:
    """Register (or log in) a test user, keeping HttpOnly cookie + X-CSRF-Token on the TestClient."""
    login_limiter._hits.clear()
    register_limiter._hits.clear()

    res = client.post("/api/auth/register", json={"email": email, "password": password})
    if res.status_code == 409:
        res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    data = res.json()
    csrf = data.get("csrf_token", "")
    if csrf:
        client.headers["X-CSRF-Token"] = csrf
    return data
