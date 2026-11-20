import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from services.ai_service import (
    AIServiceError,
    MAX_RETRIES_PER_MODEL,
    analyze_findings,
    reset_runtime_cache,
)

FINDING = {
    "rule_id": "HARDCODED_PASSWORD",
    "file": "src/main/App.kt",
    "line": 42,
    "severity": "HIGH",
    "message": "Hardcoded password detected",
    "evidence": "x",
}
API_KEY = "test-key-should-not-leak"


def models_payload(*names):
    return {
        "models": [
            {"name": f"models/{n}", "supportedGenerationMethods": ["generateContent"]}
            for n in names
        ]
    }


def analysis_payload(severity="HIGH", rule_id="HARDCODED_PASSWORD", line=42):
    return {
        "status": "ok",
        "summary": "ok",
        "findings": [
            {
                "rule_id": rule_id,
                "file": "src/main/App.kt",
                "line": line,
                "severity": severity,
                "explanation": "e",
                "risk": "r",
                "recommendation": "c",
            }
        ],
    }


def resp(body, status=200, url="https://example.test"):
    return httpx.Response(status, json=body, request=httpx.Request("POST", url))


def text_resp(text, finish="STOP"):
    return {
        "candidates": [
            {"finishReason": finish, "content": {"parts": [{"text": text}]}}
        ]
    }


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None, params=None):
        self.calls.append(("GET", url))
        return self.handler("GET", url, headers, None)

    async def post(self, url, headers=None, json=None):
        self.calls.append(("POST", url))
        return self.handler("POST", url, headers, json)


def _env(model="gemini-3.5-flash-lite"):
    return patch.dict(
        os.environ,
        {"GEMINI_API_KEY": API_KEY, "GEMINI_MODEL": model},
        clear=False,
    )


def _no_dotenv():
    return patch("services.ai_service.load_dotenv", lambda *a, **kw: None)


def _client(handler):
    fc = FakeClient(handler)
    return fc, patch(
        "services.ai_service.httpx.AsyncClient", lambda *a, **kw: fc
    )


class RetryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_runtime_cache()

    def tearDown(self):
        reset_runtime_cache()

    async def _run(self, handler):
        fc, p = _client(handler)
        with _no_dotenv(), _env(), p, patch(
            "services.ai_service.asyncio.sleep", new=AsyncMock()
        ):
            with self.assertRaises(AIServiceError) as ctx:
                await analyze_findings([FINDING])
        return fc, ctx.exception

    async def test_429_is_retried(self):
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            return resp({"error": {"message": "quota"}}, status=429)

        fc, exc = await self._run(handler)
        self.assertEqual(exc.status_code, 429)
        posts = [c for c in fc.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1 + MAX_RETRIES_PER_MODEL)

    async def test_500_is_retried(self):
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            return resp({"error": {"message": "oops"}}, status=500)

        fc, exc = await self._run(handler)
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(
            len([c for c in fc.calls if c[0] == "POST"]),
            1 + MAX_RETRIES_PER_MODEL,
        )

    async def test_400_not_retried(self):
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            return resp({"error": {"message": "bad"}}, status=400)

        fc, exc = await self._run(handler)
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(len([c for c in fc.calls if c[0] == "POST"]), 1)

    async def test_503_does_not_retry_same_model(self):
        # 503 обрабатывается как _SwitchModel, а не как retry на той же модели.
        # Модель в каталоге одна -> после неё очередь пуста.
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            return resp({"error": {"message": "high demand"}}, status=503)

        fc, exc = await self._run(handler)
        self.assertEqual(exc.status_code, 503)
        self.assertEqual(len([c for c in fc.calls if c[0] == "POST"]), 1)


class PostTimeoutTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_runtime_cache()

    def tearDown(self):
        reset_runtime_cache()

    async def test_post_timeout_raises(self):
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            raise httpx.ReadTimeout("timed out")

        fc, p = _client(handler)
        with _no_dotenv(), _env(), p:
            with self.assertRaises(AIServiceError) as ctx:
                await analyze_findings([FINDING])
        self.assertIn("время ожидания", str(ctx.exception).lower())


class IdentityRestoreTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_runtime_cache()

    def tearDown(self):
        reset_runtime_cache()

    async def _run(self, reply_payload, finding):
        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            return resp(text_resp(json.dumps(reply_payload)))

        fc, p = _client(handler)
        with _no_dotenv(), _env(), p:
            return await analyze_findings([finding])

    async def test_identity_restored_when_model_alters(self):
        report = analysis_payload(severity="LOW", rule_id="OTHER", line=99)
        result = await self._run(report, dict(FINDING))
        item = result["findings"][0]
        self.assertEqual(item["rule_id"], "HARDCODED_PASSWORD")
        self.assertEqual(item["file"], "src/main/App.kt")
        self.assertEqual(item["line"], 42)
        self.assertEqual(item["severity"], "HIGH")

    async def test_null_line_restored(self):
        finding = dict(FINDING)
        finding["line"] = None
        report = analysis_payload(line=99)
        result = await self._run(report, finding)
        self.assertIsNone(result["findings"][0]["line"])

    async def test_summary_preserved_from_model(self):
        report = analysis_payload()
        report["summary"] = "custom summary text"
        result = await self._run(report, dict(FINDING))
        self.assertEqual(result["summary"], "custom summary text")


class ScrubIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Провайдер получает ОЧИЩЕННУЮ копию, а не оригинал."""

    def setUp(self):
        reset_runtime_cache()

    def tearDown(self):
        reset_runtime_cache()

    async def test_secret_scrubbed_before_provider(self):
        captured = {}

        def handler(method, url, headers, body):
            if method == "GET":
                return resp(models_payload("gemini-3.5-flash-lite"))
            captured["body"] = body
            return resp(text_resp(json.dumps(analysis_payload())))

        fc, p = _client(handler)
        finding = dict(FINDING)
        finding["evidence"] = "password=hunter2"
        with _no_dotenv(), _env(), p:
            await analyze_findings([finding])

        text = captured["body"]["contents"][0]["parts"][0]["text"]
        self.assertNotIn("hunter2", text)
        self.assertIn("[REDACTED]", text)