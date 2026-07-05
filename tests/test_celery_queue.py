"""Test del backend di coda: il default è in-process; con QUEUE_BACKEND=celery
ma senza celery installato si degrada in-process senza sollevare."""
import os
import unittest

from osint_bot.celery_queue import capabilities, create_job_queue
from osint_bot.job_queue import JobQueue


class CeleryQueueTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop("QUEUE_BACKEND", None)

    def tearDown(self):
        os.environ.pop("QUEUE_BACKEND", None)

    def test_default_is_inprocess(self):
        q = create_job_queue()
        self.assertIsInstance(q, JobQueue)

    def test_celery_request_degrades_without_celery(self):
        os.environ["QUEUE_BACKEND"] = "celery"
        try:
            import celery  # noqa: F401
            has_celery = True
        except Exception:
            has_celery = False
        q = create_job_queue()
        if not has_celery:
            # Senza celery installato deve tornare al backend in-process.
            self.assertIsInstance(q, JobQueue)
        else:
            # Con celery installato torna un CeleryJobQueue (duck-typed).
            self.assertTrue(hasattr(q, "submit_spec"))
            self.assertTrue(hasattr(q, "register_dispatcher"))
            self.assertTrue(hasattr(q, "pending_count"))

    def test_capabilities_shape(self):
        caps = capabilities()
        self.assertIn("backend", caps)
        self.assertIn("celery_available", caps)
        self.assertIsInstance(caps["celery_available"], bool)

    def test_interface_parity(self):
        # Qualsiasi backend deve esporre la stessa interfaccia usata da web.py.
        q = create_job_queue()
        for attr in ("register_dispatcher", "submit_spec", "pending_count"):
            self.assertTrue(callable(getattr(q, attr, None)), attr)


if __name__ == "__main__":
    unittest.main()
