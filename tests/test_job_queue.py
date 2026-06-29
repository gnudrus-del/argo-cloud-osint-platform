import json
import threading
import unittest

from osint_bot.job_queue import JobQueue, JobSpec


class JobQueueTests(unittest.TestCase):
    def test_queue_runs_submitted_job(self):
        done = threading.Event()
        ran: list[str] = []
        queue = JobQueue()

        def handler():
            ran.append("ok")
            done.set()

        queue.submit("job1", handler)

        self.assertTrue(done.wait(2))
        self.assertEqual(ran, ["ok"])

    def test_submit_spec_routes_through_registered_dispatcher(self):
        done = threading.Event()
        received: list[dict] = []
        queue = JobQueue()

        def dispatcher(spec_dict: dict) -> None:
            received.append(spec_dict)
            done.set()

        queue.register_dispatcher(dispatcher)
        spec = JobSpec(
            job_id="a" * 32,
            profile={"target": "example.com", "target_type": "domain"},
            payload={"confirm_authorization": True},
            actor="alice",
        )
        queue.submit_spec(spec)

        self.assertTrue(done.wait(2))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["job_id"], "a" * 32)
        self.assertEqual(received[0]["actor"], "alice")
        # Dispatched dict must be JSON-serialisable (no closures, no objects).
        json.dumps(received[0])

    def test_submit_spec_without_dispatcher_raises(self):
        queue = JobQueue()
        with self.assertRaises(RuntimeError):
            queue.submit_spec(JobSpec(job_id="x", profile={}, payload={}))

    def test_jobspec_roundtrip(self):
        spec = JobSpec(
            job_id="b" * 32,
            profile={"agents": ["web", "opsec"], "depth": 3},
            payload={"include_contact": False},
            actor="bob",
        )
        clone = JobSpec.from_dict(spec.to_dict())
        self.assertEqual(clone, spec)


if __name__ == "__main__":
    unittest.main()
