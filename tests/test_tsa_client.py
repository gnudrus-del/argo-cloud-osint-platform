"""osint_bot.tsa_client — client RFC3161 (Time-Stamp Protocol). Nessun test
qui contatta una vera TSA: ogni chiamata di rete passa da
_safe_http.open_url, mockato (stesso pattern di tests/test_llm_client.py).
La fixture in tests/fixtures/tsa_response_digicert_granted.b64 e' una vera
risposta RFC3161 catturata manualmente una tantum (vedi commento sotto),
usata per validare il parsing contro un token reale invece di uno finto."""
from __future__ import annotations

import base64
import hashlib
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from asn1crypto import tsp

from osint_bot import _safe_http, tsa_client

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Digest SHA-256 di b"argo-osint-rfc3161-scratch-test", usato per generare la
# richiesta reale che ha prodotto la fixture "granted" qui sotto.
_FIXTURE_DIGEST_HEX = "2a096de28bb765db8c90e6b8ed9b046064306e572f1aaca65a33602b30197e6e"


def _load_fixture(name: str) -> bytes:
    b64 = (_FIXTURES_DIR / name).read_text(encoding="ascii").strip()
    return base64.b64decode(b64)


def _mock_open_url(status=200, body=b"", headers=None):
    return (status, body, headers or {})


class BuildTimestampRequestTests(unittest.TestCase):
    def test_round_trips_through_asn1crypto_loader(self):
        digest = hashlib.sha256(b"payload").digest()
        der = tsa_client.build_timestamp_request(digest)
        reloaded = tsp.TimeStampReq.load(der)
        self.assertEqual(reloaded["message_imprint"]["hashed_message"].native, digest)
        self.assertEqual(reloaded["message_imprint"]["hash_algorithm"]["algorithm"].native, "sha256")
        self.assertTrue(reloaded["cert_req"].native)

    def test_rejects_non_sha256_length_digest(self):
        with self.assertRaises(ValueError):
            tsa_client.build_timestamp_request(b"too-short")

    def test_nonce_included_when_provided(self):
        digest = hashlib.sha256(b"payload").digest()
        der = tsa_client.build_timestamp_request(digest, nonce=42)
        reloaded = tsp.TimeStampReq.load(der)
        self.assertEqual(reloaded["nonce"].native, 42)


class ParseTimestampResponseTests(unittest.TestCase):
    """Contro una vera risposta RFC3161 (fixture catturata manualmente da
    timestamp.digicert.com — mai in un test automatico si contatta la TSA
    davvero, la fixture e' un blob statico registrato una volta)."""

    def test_granted_response_parses_gen_time_and_token(self):
        body = _load_fixture("tsa_response_digicert_granted.b64")
        result = tsa_client._parse_timestamp_response(body, http_status=200)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "granted")
        self.assertTrue(result.gen_time.startswith("2026-07-15"))
        self.assertGreater(len(result.token_der_b64), 100)
        self.assertEqual(result.error_class, "")

    def test_garbage_body_raises_valueerror(self):
        # _parse_timestamp_response si aspetta che il chiamante (request_timestamp)
        # catturi l'eccezione e la traduca in error_class="invalid_response" —
        # vedi test_malformed_response_body_is_invalid_response_not_raise sotto.
        with self.assertRaises(ValueError):
            tsa_client._parse_timestamp_response(b"not a der blob", http_status=200)


class RequestTimestampTests(unittest.TestCase):
    def test_invalid_digest_hex_short_circuits_before_network(self):
        with patch("osint_bot._safe_http.open_url") as mocked:
            result = tsa_client.request_timestamp("https://tsa.example/", "not-hex")
        mocked.assert_not_called()
        self.assertFalse(result.ok)
        self.assertEqual(result.error_class, "invalid_request")

    def test_ssrf_blocked_surfaces_as_error_not_raise(self):
        with patch("osint_bot._safe_http.open_url",
                    side_effect=_safe_http.SSRFBlocked("blocked")):
            result = tsa_client.request_timestamp("http://169.254.169.254/", _FIXTURE_DIGEST_HEX)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_class, "ssrf_blocked")

    def test_network_error_surfaces_as_error_not_raise(self):
        with patch("osint_bot._safe_http.open_url",
                    side_effect=urllib.error.URLError("timed out")):
            result = tsa_client.request_timestamp("https://tsa.example/", _FIXTURE_DIGEST_HEX)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_class, "network_error")

    def test_non_200_http_status_is_http_error(self):
        with patch("osint_bot._safe_http.open_url",
                    return_value=_mock_open_url(status=503, body=b"")):
            result = tsa_client.request_timestamp("https://tsa.example/", _FIXTURE_DIGEST_HEX)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_class, "http_error")
        self.assertEqual(result.http_status, 503)

    def test_success_returns_parsed_result_from_mocked_transport(self):
        body = _load_fixture("tsa_response_digicert_granted.b64")
        with patch("osint_bot._safe_http.open_url",
                    return_value=_mock_open_url(status=200, body=body)) as mocked:
            result = tsa_client.request_timestamp("https://tsa.example/", _FIXTURE_DIGEST_HEX)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "granted")
        # verifica che la richiesta sia stata fatta con content-type binario RFC3161,
        # non JSON come tutte le altre integrazioni di Argo
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/timestamp-query")
        self.assertEqual(kwargs["method"], "POST")
        self.assertNotIn("allow_private", kwargs)  # mai per un host TSA pubblico

    def test_malformed_response_body_is_invalid_response_not_raise(self):
        with patch("osint_bot._safe_http.open_url",
                    return_value=_mock_open_url(status=200, body=b"garbage")):
            result = tsa_client.request_timestamp("https://tsa.example/", _FIXTURE_DIGEST_HEX)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_class, "invalid_response")


if __name__ == "__main__":
    unittest.main()
