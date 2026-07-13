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
        """Every connector routes through _safe_http, so the check must
        exit 0. If this fails, a connector regressed to a direct
        urllib/httpx/requests call — migrate it to _safe_http."""
        result = subprocess.run(
            [sys.executable, str(GUARD)],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        self.assertEqual(
            result.returncode, 0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("SSRF guard: OK", result.stdout)

    def test_grandfathered_set_is_empty(self):
        """The migration is complete — the exceptions set must stay empty.
        A non-empty set means a connector was allowed to keep a direct
        network call instead of being migrated."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("enforce_safe_http", GUARD)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(
            mod.GRANDFATHERED, set(),
            msg=f"GRANDFATHERED must be empty, found: {sorted(mod.GRANDFATHERED)}",
        )


if __name__ == "__main__":
    unittest.main()
