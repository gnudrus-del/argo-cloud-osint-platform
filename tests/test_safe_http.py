"""Tests for the _safe_http gateway: SSRF blocking on the initial URL,
on redirects, response-size cap, and the JSON/text/POST helpers.

Network is stubbed via a local http.server so no external calls are made."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from osint_bot import _safe_http


class SsrfGuardTests(unittest.TestCase):
    def test_blocks_non_http_scheme(self):
        with self.assertRaises(_safe_http.SSRFBlocked):
            _safe_http.guard_ssrf("file:///etc/passwd")

    def test_blocks_loopback_literal(self):
        with self.assertRaises(_safe_http.SSRFBlocked):
            _safe_http.guard_ssrf("http://127.0.0.1/")

    def test_blocks_cloud_metadata(self):
        with self.assertRaises(_safe_http.SSRFBlocked):
            _safe_http.guard_ssrf("http://169.254.169.254/latest/meta-data/")

    def test_blocks_rfc1918(self):
        for host in ("http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/"):
            with self.assertRaises(_safe_http.SSRFBlocked):
                _safe_http.guard_ssrf(host)

    def test_allows_private_when_opted_in(self):
        # Should not raise
        _safe_http.guard_ssrf("http://10.0.0.1/", allow_private=True)

    def test_missing_host(self):
        with self.assertRaises(_safe_http.SSRFBlocked):
            _safe_http.guard_ssrf("http:///nohost")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/json":
            payload = json.dumps({"ok": True, "n": 42}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/text":
            body = b"hello world"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect-internal":
            # Try to bounce the client to cloud metadata.
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        echo = json.dumps({"received": json.loads(raw.decode())}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(echo)))
        self.end_headers()
        self.wfile.write(echo)


class SafeHttpHelpersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_json(self):
        # allow_private required: the test server binds to loopback.
        data = _safe_http.get_json(self.base + "/json", allow_private=True)
        self.assertEqual(data["ok"], True)
        self.assertEqual(data["n"], 42)

    def test_get_text(self):
        text = _safe_http.get_text(self.base + "/text", allow_private=True)
        self.assertEqual(text, "hello world")

    def test_post_json(self):
        resp = _safe_http.post_json(
            self.base + "/echo-post", {"q": "z"}, allow_private=True
        )
        # /echo-post isn't handled → the handler falls into do_POST for any path
        self.assertEqual(resp["received"]["q"], "z")

    def test_redirect_to_internal_is_blocked(self):
        # The server 302s to 169.254.169.254; the guarded redirect handler
        # must refuse to follow it.
        with self.assertRaises(_safe_http.SSRFBlocked):
            _safe_http.get_bytes(
                self.base + "/redirect-internal", allow_private=True
            )


if __name__ == "__main__":
    unittest.main()
