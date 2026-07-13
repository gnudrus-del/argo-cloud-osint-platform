"""H2 — scripts/enforce_safe_http.py is what CI relies on to prevent
new connectors from bypassing _safe_http. Exercise the script itself
so a regression in the guard is caught in unit tests too."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "scripts" / "enforce_safe_http.py"


class SsrfGuardCiTests(unittest.TestCase):
    def test_guard_script_exists(self):
        self.assertTrue(GUARD.is_file(), f"missing {GUARD}")

    def test_guard_passes_on_current_tree(self):
        """With every existing connector grandfathered, the check must
        exit 0. If this fails, either a connector was added without a
        grandfathered entry (should migrate to _safe_http instead) or
        the grandfathered set was carelessly extended."""
        result = subprocess.run(
            [sys.executable, str(GUARD)],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        self.assertEqual(
            result.returncode, 0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("SSRF guard: OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
