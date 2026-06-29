import json
import tempfile
import threading
import unittest
from pathlib import Path

from osint_bot.audit import append_audit_event, verify_audit_log


class AuditTests(unittest.TestCase):
    def test_audit_hash_chain_verifies_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            append_audit_event(root, "analyst", "job_created", {"job_id": "1"})
            append_audit_event(root, "analyst", "job_completed", {"job_id": "1"})
            log_path = root / "audit.log"

            self.assertTrue(verify_audit_log(log_path))

            lines = log_path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])
            record["action"] = "tampered"
            lines[0] = json.dumps(record, sort_keys=True)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            self.assertFalse(verify_audit_log(log_path))

    def test_concurrent_appends_preserve_chain(self):
        thread_count = 16
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            barrier = threading.Barrier(thread_count)

            def worker(idx: int) -> None:
                barrier.wait()
                append_audit_event(root, f"worker-{idx}", "concurrent_event", {"idx": idx})

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            log_path = root / "audit.log"
            self.assertTrue(verify_audit_log(log_path))
            lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(lines), thread_count)


if __name__ == "__main__":
    unittest.main()
