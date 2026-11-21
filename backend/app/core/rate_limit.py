"""In-memory sliding-window rate limiter for auth and abuse protection."""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class SlidingWindowLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 300) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        bucket = [ts for ts in self._hits.get(key, []) if ts > cutoff]
        if bucket:
            self._hits[key] = bucket
        else:
            self._hits.pop(key, None)
        return bucket

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return len(self._prune(key, now)) >= self.max_requests

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._prune(key, now)
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            self._hits[key] = bucket
            return True

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
