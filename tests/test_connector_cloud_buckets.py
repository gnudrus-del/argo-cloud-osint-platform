"""Test offline (nessuna rete) per il connettore cloud_buckets (Fase 13)."""
from __future__ import annotations

import unittest
import urllib.error
from unittest.mock import patch

from osint_bot.connector import ACTION_ACTIVE_GATED, ConnectorContext
from osint_bot.connectors import build_default_registry
from osint_bot.connectors.cloud_buckets import CloudBucketsConnector, _candidate_names


def _ctx(target: str = "acme.com", target_type: str = "domain", timeout: int = 5) -> ConnectorContext:
    return ConnectorContext(target=target, target_type=target_type, timeout=timeout, case_id="T")


class CloudBucketsRegistrationTests(unittest.TestCase):
    def test_registered_in_default_registry(self):
        reg = build_default_registry()
        conns = getattr(reg, "_connectors", {})
        self.assertIn("cloud_buckets", conns)

    def test_spec_is_active_gated(self):
        self.assertEqual(CloudBucketsConnector.spec.action_class, ACTION_ACTIVE_GATED)
        self.assertIn("domain", CloudBucketsConnector.spec.input_types)
        self.assertIn("company", CloudBucketsConnector.spec.input_types)
        self.assertEqual(CloudBucketsConnector.spec.required_key, "")


class CloudBucketsEmptyTargetTests(unittest.TestCase):
    def test_empty_target_is_error(self):
        conn = CloudBucketsConnector()
        result = conn._fetch(_ctx(target=""))
        self.assertEqual(result.status, "error")

    def test_whitespace_only_target_is_error(self):
        conn = CloudBucketsConnector()
        result = conn._fetch(_ctx(target="   "))
        self.assertEqual(result.status, "error")


class CandidateGenerationTests(unittest.TestCase):
    def test_domain_stem_extraction(self):
        candidates = _candidate_names("acme.com")
        self.assertIn("acme", candidates)

    def test_company_name_normalization(self):
        candidates = _candidate_names("Acme Corporation")
        self.assertTrue(any(c.startswith("acme") for c in candidates))
        # niente spazi/maiuscole nei candidati generati
        for c in candidates:
            self.assertTrue(all(ch.isalnum() or ch == "-" for ch in c))
            self.assertEqual(c, c.lower())

    def test_candidates_include_prefixes_and_suffixes(self):
        candidates = _candidate_names("acme.com")
        self.assertIn("backup-acme", candidates)
        self.assertIn("acme-backup", candidates)
        self.assertIn("acme-dev", candidates)
        self.assertIn("dev-acme", candidates)

    def test_candidates_deduplicated_and_capped(self):
        candidates = _candidate_names("acme.com")
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertLessEqual(len(candidates), 30)

    def test_empty_target_yields_no_candidates(self):
        self.assertEqual(_candidate_names(""), [])
        self.assertEqual(_candidate_names("   "), [])


class CloudBucketsProbeTests(unittest.TestCase):
    """Mocka _safe_http.open_url (stesso pattern usato in tests/test_connectors.py
    e tests/test_fetch_ssrf.py) per simulare le risposte HTTP dei 3 provider,
    senza fare nessuna vera richiesta di rete."""

    def test_all_404_yields_no_findings(self):
        def fake_open_url(url, *, method=None, timeout=20, **kwargs):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with patch("osint_bot.connectors.cloud_buckets._safe_http.open_url", side_effect=fake_open_url):
            conn = CloudBucketsConnector()
            result = conn._fetch(_ctx(target="acme.com"))

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings, [])

    def test_listable_bucket_yields_critical_finding(self):
        listing_body = b"<ListBucketResult><Contents><Key>secret.csv</Key></Contents></ListBucketResult>"

        def fake_open_url(url, *, method=None, timeout=20, **kwargs):
            if url == "https://acme.s3.amazonaws.com/":
                if method == "HEAD":
                    return (200, b"", {})
                return (200, listing_body, {})
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with patch("osint_bot.connectors.cloud_buckets._safe_http.open_url", side_effect=fake_open_url):
            conn = CloudBucketsConnector()
            result = conn._fetch(_ctx(target="acme.com"))

        self.assertEqual(result.status, "ok")
        critical = [f for f in result.findings if f.severity == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].kind, "public_cloud_bucket_listable")
        self.assertEqual(critical[0].value, "s3:acme")

    def test_existing_non_listable_bucket_yields_high_finding(self):
        def fake_open_url(url, *, method=None, timeout=20, **kwargs):
            if url == "https://acme.storage.googleapis.com/":
                if method == "HEAD":
                    return (200, b"", {})
                return (200, b"<Error><Code>AccessDenied</Code></Error>", {})
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with patch("osint_bot.connectors.cloud_buckets._safe_http.open_url", side_effect=fake_open_url):
            conn = CloudBucketsConnector()
            result = conn._fetch(_ctx(target="acme.com"))

        self.assertEqual(result.status, "ok")
        high = [f for f in result.findings if f.severity == "high"]
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].kind, "public_cloud_bucket_exists")
        self.assertEqual(high[0].value, "gcs:acme")

    def test_private_bucket_yields_low_confidence_info_finding(self):
        def fake_open_url(url, *, method=None, timeout=20, **kwargs):
            if url == "https://acme.blob.core.windows.net/":
                raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with patch("osint_bot.connectors.cloud_buckets._safe_http.open_url", side_effect=fake_open_url):
            conn = CloudBucketsConnector()
            result = conn._fetch(_ctx(target="acme.com"))

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.kind, "cloud_bucket_private")
        self.assertEqual(f.severity, "info")
        self.assertLess(f.confidence, 0.5)

    def test_network_error_on_one_candidate_does_not_abort_others(self):
        listing_body = b"<ListBucketResult></ListBucketResult>"

        def fake_open_url(url, *, method=None, timeout=20, **kwargs):
            if "timeout-candidate" in url:
                raise TimeoutError("simulated timeout")
            if url == "https://acme.s3.amazonaws.com/":
                if method == "HEAD":
                    return (200, b"", {})
                return (200, listing_body, {})
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with patch("osint_bot.connectors.cloud_buckets._safe_http.open_url", side_effect=fake_open_url):
            conn = CloudBucketsConnector()
            result = conn._fetch(_ctx(target="acme.com"))

        self.assertEqual(result.status, "ok")
        self.assertTrue(any(f.kind == "public_cloud_bucket_listable" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
