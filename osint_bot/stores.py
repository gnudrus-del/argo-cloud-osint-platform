"""Pluggable stores for ephemeral state.

Session state and rate-limit windows are per-process today. The interfaces
defined here make the swap to a shared backend (Redis, memcached, a second
SQLite file) a one-line change: write a new class that implements the same
methods and inject it at boot.

Why this matters now: multi-instance Pro deployments need shared sessions
and shared rate limits; rewriting the call sites later is much more painful
than introducing the seam now while everything still fits in one process.
"""

from __future__ import annotations

import threading
import time
from typing import Iterable, Protocol


class SessionStore(Protocol):
    def get(self, session_id: str) -> dict | None: ...
    def put(self, session_id: str, session: dict) -> None: ...
    def delete(self, session_id: str) -> None: ...
    def touch(self, session_id: str, now: float) -> None: ...


class RateLimiter(Protocol):
    def hit(self, key: str, window_seconds: int, limit: int) -> bool:
        """Record a hit and return False when the caller has exceeded *limit*."""


class InMemorySessionStore:
    def __init__(self):
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            return self._data.get(session_id)

    def put(self, session_id: str, session: dict) -> None:
        with self._lock:
            self._data[session_id] = session

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def touch(self, session_id: str, now: float) -> None:
        with self._lock:
            session = self._data.get(session_id)
            if session is not None:
                session["last_seen"] = now

    def all_ids(self) -> Iterable[str]:
        with self._lock:
            return list(self._data.keys())


class InMemoryRateLimiter:
    def __init__(self):
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, window_seconds: int, limit: int) -> bool:
        now = time.time()
        with self._lock:
            window = [stamp for stamp in self._windows.get(key, []) if now - stamp < window_seconds]
            if len(window) >= limit:
                self._windows[key] = window
                return False
            window.append(now)
            self._windows[key] = window
            return True
