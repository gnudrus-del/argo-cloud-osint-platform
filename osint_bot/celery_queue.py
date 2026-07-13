"""Backend di coda Celery/Redis — alternativo al JobQueue in-process.

Il ``JobQueue`` (job_queue.py) esegue i job in un thread worker dentro lo stesso
processo: perfetto per single-node, ma non scala oltre il processo e perde la
coda a un riavvio non pulito. Questo modulo fornisce un backend Celery che
mantiene la STESSA interfaccia (``register_dispatcher`` / ``submit_spec`` /
``pending_count``), così ``web.py`` non cambia: enfila i JobSpec su un broker
Redis e li fa eseguire da worker Celery separati (scalabili orizzontalmente).

Selezione a runtime via env:
    QUEUE_BACKEND=celery          attiva questo backend
    CELERY_BROKER_URL=redis://…   broker (default redis://127.0.0.1:6379/0)
    CELERY_RESULT_BACKEND=…       opzionale (default = broker)

Se ``celery`` non è installato o il backend non è richiesto, ``create_job_queue``
ritorna il JobQueue in-process (nessuna dipendenza obbligatoria).

Worker:
    celery -A osint_bot.celery_queue:celery_app worker --loglevel=info
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from .job_queue import JobQueue, JobSpec

JobSpecDict = dict[str, Any]


def _broker_url() -> str:
    return os.getenv("CELERY_BROKER_URL") or os.getenv("REDIS_URL") or "redis://127.0.0.1:6379/0"


def _build_celery_app():
    """Crea il Celery app se la libreria è disponibile, altrimenti None."""
    try:
        from celery import Celery  # type: ignore
    except Exception:
        return None
    broker = _broker_url()
    backend = os.getenv("CELERY_RESULT_BACKEND") or broker
    app = Celery("argo_osint", broker=broker, backend=backend)
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_acks_late=True,          # ri-processa se il worker muore a metà
        worker_prefetch_multiplier=1,  # fairness: un job pesante per worker alla volta
        task_default_queue="argo-jobs",
    )
    return app


# App a livello modulo: il worker la scopre via ``-A osint_bot.celery_queue:celery_app``.
celery_app = _build_celery_app()


if celery_app is not None:
    @celery_app.task(name="argo.run_job_spec", bind=True, max_retries=2)
    def run_job_spec(self, spec_dict: JobSpecDict):  # type: ignore
        """Task eseguito nel processo worker: ricostruisce ed esegue il job.

        Importa ``dispatch_job_spec`` lazy per evitare cicli di import (web
        importa questo modulo, questo task importa web solo a runtime nel worker).
        """
        from .web import dispatch_job_spec
        dispatch_job_spec(spec_dict)
else:  # pragma: no cover - solo quando celery non è installato
    run_job_spec = None  # type: ignore


class CeleryJobQueue:
    """Duck-type compatibile con JobQueue, ma enfila su Celery/Redis."""

    def __init__(self):
        if celery_app is None or run_job_spec is None:
            raise RuntimeError("Celery non disponibile: installa 'celery' e 'redis'.")
        self._app = celery_app
        self._dispatcher: Callable[[JobSpecDict], None] | None = None

    def register_dispatcher(self, dispatcher: Callable[[JobSpecDict], None]) -> None:
        # Il worker usa la funzione a livello modulo (dispatch_job_spec), non
        # questa reference: la teniamo solo per parità d'interfaccia / debug.
        self._dispatcher = dispatcher

    def submit(self, job_id: str, handler: Callable[[], None]) -> None:
        # I closure non sono serializzabili verso un worker remoto: non
        # supportato dal backend Celery. Usa submit_spec.
        raise NotImplementedError("CeleryJobQueue supporta solo submit_spec (JobSpec serializzabile).")

    def submit_spec(self, spec: JobSpec) -> None:
        run_job_spec.apply_async(args=[spec.to_dict()], queue="argo-jobs")

    def pending_count(self) -> int:
        """Best-effort: lunghezza della coda Redis 'argo-jobs'. 0 se non deducibile."""
        try:
            broker = _broker_url()
            if broker.startswith("redis://") or broker.startswith("rediss://"):
                import redis  # type: ignore
                client = redis.Redis.from_url(broker)
                return int(client.llen("argo-jobs") or 0)
        except Exception:
            pass
        return 0


def create_job_queue():
    """Factory: ritorna il backend di coda giusto in base a ``QUEUE_BACKEND``.

    - ``celery`` + celery installato + broker raggiungibile -> CeleryJobQueue
    - altrimenti (default) -> JobQueue in-process (ThreadPoolExecutor-like).

    Non solleva mai per assenza di celery: degrada sul backend in-process.
    """
    backend = os.getenv("QUEUE_BACKEND", "inprocess").strip().lower()
    if backend == "celery":
        try:
            return CeleryJobQueue()
        except Exception as exc:
            import logging
            logging.getLogger("osint_bot.queue").warning(
                "QUEUE_BACKEND=celery ma non disponibile (%s); fallback in-process.", exc
            )
    return JobQueue()


def capabilities() -> dict[str, Any]:
    return {
        "backend": os.getenv("QUEUE_BACKEND", "inprocess").strip().lower(),
        "celery_available": celery_app is not None,
        "broker": _broker_url() if celery_app is not None else "",
    }
