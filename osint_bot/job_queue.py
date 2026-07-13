"""In-process job queue for OSINT investigations.

Two flavours of work are accepted:

* ``submit(job_id, handler)``: legacy callable form. Kept so any external
  caller that built a closure still works during transition.
* ``submit_spec(job_spec)``: the preferred form. A ``JobSpec`` is a plain
  dict-shaped record (id, profile, settings, actor) — no Python references,
  no closures. The worker resolves it to an executable function via the
  registered dispatcher. This is what lets us:

    - persist the queue in SQLite and replay on restart
    - swap the in-process worker for RQ/Celery without touching plugins
    - re-enqueue queued jobs at boot if the previous process crashed
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

JobSpecDict = dict[str, Any]
Dispatcher = Callable[[JobSpecDict], None]


@dataclass(frozen=True)
class JobSpec:
    """Plain-data description of an enqueued job.

    Anything in here can be JSON-serialised; the worker dispatcher reads only
    these fields. Keep this dataclass small — extra runtime state belongs in
    Storage, not in the queue.
    """

    job_id: str
    profile: dict[str, Any]
    payload: dict[str, Any]
    actor: str = "system"

    def to_dict(self) -> JobSpecDict:
        return {
            "job_id": self.job_id,
            "profile": dict(self.profile),
            "payload": dict(self.payload),
            "actor": self.actor,
        }

    @classmethod
    def from_dict(cls, data: JobSpecDict) -> JobSpec:
        return cls(
            job_id=str(data["job_id"]),
            profile=dict(data.get("profile") or {}),
            payload=dict(data.get("payload") or {}),
            actor=str(data.get("actor") or "system"),
        )


@dataclass(frozen=True)
class _QueuedItem:
    job_id: str
    handler: Callable[[], None]


class JobQueue:
    def __init__(self):
        self._queue: queue.Queue[_QueuedItem] = queue.Queue()
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._dispatcher: Dispatcher | None = None

    def register_dispatcher(self, dispatcher: Dispatcher) -> None:
        """Wire the function that turns a JobSpec dict into actual work."""
        self._dispatcher = dispatcher

    def submit(self, job_id: str, handler: Callable[[], None]) -> None:
        """Legacy: enqueue a no-arg callable."""
        self._queue.put(_QueuedItem(job_id=job_id, handler=handler))
        self._ensure_worker()

    def submit_spec(self, spec: JobSpec) -> None:
        """Preferred: enqueue a serialisable JobSpec to be dispatched."""
        if self._dispatcher is None:
            raise RuntimeError(
                "JobQueue.submit_spec called before register_dispatcher; "
                "set a dispatcher at boot time."
            )
        dispatcher = self._dispatcher
        spec_dict = spec.to_dict()
        self._queue.put(
            _QueuedItem(job_id=spec.job_id, handler=lambda: dispatcher(spec_dict))
        )
        self._ensure_worker()

    def pending_count(self) -> int:
        return self._queue.qsize()

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker and self._worker.is_alive():
                return
            self._worker = threading.Thread(target=self._run, name="gufo-job-worker", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            try:
                queued = self._queue.get(timeout=1.0)
            except queue.Empty:
                with self._lock:
                    if self._queue.empty():
                        self._worker = None
                        return
                continue
            try:
                queued.handler()
            finally:
                self._queue.task_done()
