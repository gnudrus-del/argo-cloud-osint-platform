import contextlib
import tempfile
import unittest
from pathlib import Path

from osint_bot.orchestrator import RunProfile
from osint_bot.storage import Storage


@contextlib.contextmanager
def _isolated_storage():
    import osint_bot.web as web

    with tempfile.TemporaryDirectory() as tmp:
        original_root = web.JOB_ROOT
        original_storage = web.STORAGE
        web.JOB_ROOT = Path(tmp)
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        try:
            yield Path(tmp), web.STORAGE
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.JOB_ROOT = original_root
            web.STORAGE = original_storage


def _profile() -> RunProfile:
    return RunProfile(
        command="Analizza example.com",
        target="example.com",
        target_type="domain",
        agents=["web"],
        external_tools=[],
        seed_urls=[],
        depth=1, max_pages=1, notes=[],
    )


class DashboardOverviewTests(unittest.TestCase):
    def test_empty_actor_returns_zeroed_shape(self):
        from osint_bot.web import dashboard_overview

        with _isolated_storage():
            data = dashboard_overview("alice")
        self.assertEqual(data["totals"], {"cases": 0, "jobs": 0})
        self.assertEqual(data["stats"]["complete"], 0)
        self.assertEqual(data["recent_cases"], [])
        self.assertEqual(data["recent_jobs"], [])
        # Coverage keys always present so the UI can render without guards.
        for key in ("providers_configured", "providers_total", "tools_available", "tools_total"):
            self.assertIn(key, data["coverage"])
        # Case selector list is part of the server-backed payload.
        self.assertEqual(data["cases_select"], [])

    def test_only_owner_data_is_aggregated(self):
        from osint_bot.web import create_case, create_job, dashboard_overview

        with _isolated_storage():
            create_case({"title": "Caso di Alice", "legal_basis": {"type": "consent"}}, actor="alice")
            create_job(_profile(), {}, actor="bob")
            data = dashboard_overview("alice")
        self.assertEqual(data["totals"]["cases"], 1)
        # Bob's job must not leak into Alice's dashboard.
        self.assertEqual(data["totals"]["jobs"], 0)
        self.assertEqual(data["recent_cases"][0]["title"], "Caso di Alice")

    def test_unspecified_legal_basis_raises_compliance_warning(self):
        from osint_bot.web import create_case, dashboard_overview

        with _isolated_storage():
            create_case({"title": "Senza base", "legal_basis": {"type": "unspecified"}}, actor="alice")
            data = dashboard_overview("alice")
        messages = [w["message"] for w in data["warnings"]]
        self.assertTrue(any("base giuridica" in m for m in messages))

    def test_clear_legal_basis_and_scope_no_warning(self):
        from osint_bot.web import create_case, dashboard_overview

        with _isolated_storage():
            # Base giuridica chiara + scope presente => nessun avviso.
            create_case(
                {"title": "Con base", "legal_basis": {"type": "contract"},
                 "allowed_targets": ["example.com"]},
                actor="alice",
            )
            data = dashboard_overview("alice")
        self.assertEqual(data["warnings"], [])

    def test_missing_scope_raises_info_warning(self):
        from osint_bot.web import create_case, dashboard_overview

        with _isolated_storage():
            create_case({"title": "Senza scope", "legal_basis": {"type": "contract"}}, actor="alice")
            data = dashboard_overview("alice")
        messages = [w["message"] for w in data["warnings"]]
        self.assertTrue(any("scope" in m for m in messages))

    def test_cases_select_lists_all_cases(self):
        from osint_bot.web import create_case, dashboard_overview

        with _isolated_storage():
            for i in range(3):
                create_case({"title": f"Caso {i}", "legal_basis": {"type": "consent"}}, actor="alice")
            data = dashboard_overview("alice")
        self.assertEqual(len(data["cases_select"]), 3)
        for item in data["cases_select"]:
            self.assertIn("id", item)
            self.assertIn("title", item)

    def test_job_status_counts(self):
        from osint_bot.web import create_job, dashboard_overview

        with _isolated_storage():
            create_job(_profile(), {}, actor="alice")
            data = dashboard_overview("alice")
        self.assertEqual(data["totals"]["jobs"], 1)
        self.assertEqual(sum(data["stats"].values()), 1)


if __name__ == "__main__":
    unittest.main()
