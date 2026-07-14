"""H2-follow-up — osint_bot.fetch.Fetcher is the CLI/job-queue "seed URL"
fetcher (reachable from the web job-queue via seed_urls, not just the CLI).
It used to open raw urllib connections; it must now refuse internal targets
exactly like every connector does through _safe_http."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from osint_bot import _safe_http
from osint_bot.fetch import FetchConfig, Fetcher, RobotsCache


def _mock_open_url(status=200, body=b"", headers=None):
    return (status, body, headers or {})


class FetcherSsrfTests(unittest.TestCase):
    def setUp(self):
        self.fetcher = Fetcher(FetchConfig())

    def test_blocks_cloud_metadata(self):
        page = self.fetcher.fetch("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(page.status, 0)
        self.assertIn("SSRF", page.error)

    def test_blocks_loopback(self):
        page = self.fetcher.fetch("http://127.0.0.1:8000/")
        self.assertEqual(page.status, 0)
        self.assertIn("SSRF", page.error)

    def test_blocks_rfc1918(self):
        for url in ("http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/"):
            page = self.fetcher.fetch(url)
            self.assertEqual(page.status, 0, msg=url)
            self.assertIn("SSRF", page.error, msg=url)

    def test_blocked_target_never_reaches_open_url(self):
        """The guard must short-circuit before any network call is attempted."""
        with patch("osint_bot._safe_http.open_url") as mocked:
            self.fetcher.fetch("http://169.254.169.254/")
        mocked.assert_not_called()

    def test_redirect_to_internal_is_blocked(self):
        """A public-looking host that 302s to a metadata IP must still be
        rejected — the guard re-validates every redirect hop, not just the
        entry URL. Exercised via _safe_http.open_url raising SSRFBlocked
        (its own redirect handler is covered by tests/test_safe_http.py)."""
        with patch(
            "osint_bot._safe_http.open_url",
            side_effect=_safe_http.SSRFBlocked("redirected to internal target"),
        ):
            page = self.fetcher.fetch("http://example.com/bounce")
        self.assertEqual(page.status, 0)
        self.assertIn("SSRF", page.error)

    def test_happy_path_uses_safe_http_gateway(self):
        html = b"<html><head><title>T</title></head><body>hello</body></html>"
        with patch(
            "osint_bot._safe_http.open_url",
            return_value=_mock_open_url(200, html, {"content-type": "text/html"}),
        ) as mocked:
            page = self.fetcher.fetch("https://example.com/")
        self.assertEqual(page.status, 200)
        self.assertEqual(page.title, "T")
        self.assertIn("hello", page.text)
        # Called twice: once for robots.txt (also gateway-routed — see
        # RobotsCacheSsrfTests) and once for the page itself.
        self.assertEqual(mocked.call_count, 2)

    def test_proxy_url_is_forwarded_to_gateway(self):
        fetcher = Fetcher(FetchConfig(proxy_url="http://127.0.0.1:9050"))
        html = b"<html><head><title>P</title></head><body>x</body></html>"
        with patch(
            "osint_bot._safe_http.open_url",
            return_value=_mock_open_url(200, html, {"content-type": "text/html"}),
        ) as mocked:
            fetcher.fetch("https://example.com/")
        self.assertEqual(mocked.call_args.kwargs.get("proxy_url"), "http://127.0.0.1:9050")

    def test_http_error_is_surfaced(self):
        import urllib.error

        with patch(
            "osint_bot._safe_http.open_url",
            side_effect=urllib.error.HTTPError("https://example.com/", 404, "Not Found", {}, None),
        ):
            page = self.fetcher.fetch("https://example.com/missing")
        self.assertEqual(page.status, 404)


class RobotsCacheSsrfTests(unittest.TestCase):
    def test_robots_fetch_uses_safe_http_gateway(self):
        cache = RobotsCache(user_agent="osint-bot/test", timeout=5)
        robots_txt = b"User-agent: *\nDisallow: /private/\n"
        with patch(
            "osint_bot._safe_http.open_url",
            return_value=_mock_open_url(200, robots_txt, {}),
        ) as mocked:
            self.assertTrue(cache.allowed("https://example.com/public/"))
            self.assertFalse(cache.allowed("https://example.com/private/x"))
        # Cached after the first lookup — one fetch for both calls.
        mocked.assert_called_once()

    def test_robots_fetch_blocked_falls_back_to_allowed(self):
        """If robots.txt fetch itself gets SSRF-blocked (e.g. a redirect
        smuggled it toward an internal target), fail open on the robots
        courtesy-check — the real content fetch right after this is what
        actually enforces the SSRF boundary, via guard_ssrf in Fetcher.fetch."""
        cache = RobotsCache(user_agent="osint-bot/test", timeout=5)
        with patch(
            "osint_bot._safe_http.open_url",
            side_effect=_safe_http.SSRFBlocked("blocked"),
        ):
            self.assertTrue(cache.allowed("https://example.com/"))


if __name__ == "__main__":
    unittest.main()
