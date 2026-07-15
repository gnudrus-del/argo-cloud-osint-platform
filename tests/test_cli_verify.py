"""osint_bot.cli_verify — verifica indipendente (offline) di un sigillo di
report esportato. Nessuna chiamata di rete: opera solo su un file JSON e la
libreria report_signing."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osint_bot import cli_verify, report_signing


def _make_seal(job_root: Path, digest_hex: str, **overrides) -> dict:
    signature = report_signing.sign_digest(digest_hex, job_root)
    seal = {
        "id": "seal1", "case_id": "c" * 32, "job_id": "1" * 32,
        "manifest_hash": digest_hex, "artifact_count": 3,
        "signature_b64": signature["signature_b64"],
        "signing_pubkey_b64": signature["public_key_b64"],
        "signing_pubkey_fingerprint": signature["fingerprint_sha256"],
        "sealed_at": "2026-07-15T00:00:00+00:00", "sealed_by": "alice",
        "tsa_url_host": "", "tsa_status": "", "tsa_token_der_b64": "",
        "tsa_gen_time": "", "tsa_requested_at": "",
    }
    seal.update(overrides)
    return seal


class VerifySealTests(unittest.TestCase):
    def test_valid_signature_reports_ok(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex)
            ok, lines = cli_verify.verify_seal(seal)
            self.assertTrue(ok)
            self.assertIn("VALIDA", lines[0])

    def test_tampered_manifest_hash_fails(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex)
            seal["manifest_hash"] = hashlib.sha256(b"tampered content").hexdigest()
            ok, lines = cli_verify.verify_seal(seal)
            self.assertFalse(ok)
            self.assertIn("NON VALIDA", lines[0])

    def test_incomplete_seal_fails_cleanly(self):
        ok, lines = cli_verify.verify_seal({"manifest_hash": "abc"})
        self.assertFalse(ok)
        self.assertIn("incompleto", lines[0])

    def test_pubkey_override_used_instead_of_embedded(self):
        """Un seal.json potrebbe essere stato sostituito insieme alla sua
        stessa chiave pubblica embedded — --pubkey permette di verificare
        contro una copia ottenuta per altra via."""
        import hashlib
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp_a), digest_hex)
            other_key_sig = report_signing.sign_digest(digest_hex, Path(tmp_b))
            ok, lines = cli_verify.verify_seal(seal, pubkey_b64_override=other_key_sig["public_key_b64"])
            self.assertFalse(ok)  # la firma non corrisponde alla chiave "esterna"

    def test_tsa_token_present_reports_gen_time(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex, tsa_status="granted",
                              tsa_gen_time="2026-07-15T05:25:04+00:00",
                              tsa_url_host="timestamp.digicert.com",
                              tsa_token_der_b64="ZGVhZGJlZWY=")
            ok, lines = cli_verify.verify_seal(seal)
            self.assertTrue(ok)
            joined = "\n".join(lines)
            self.assertIn("2026-07-15T05:25:04+00:00", joined)
            self.assertIn("timestamp.digicert.com", joined)

    def test_no_tsa_token_notes_local_signature_only(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex)
            ok, lines = cli_verify.verify_seal(seal)
            self.assertIn("Nessun timestamp RFC3161", "\n".join(lines))


class MainCliTests(unittest.TestCase):
    def test_main_returns_0_on_valid_seal_file(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex)
            seal_path = Path(tmp) / "seal.json"
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            rc = cli_verify.main([str(seal_path)])
            self.assertEqual(rc, 0)

    def test_main_returns_1_on_tampered_seal_file(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex)
            seal["signature_b64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
            seal_path = Path(tmp) / "seal.json"
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            rc = cli_verify.main([str(seal_path)])
            self.assertEqual(rc, 1)

    def test_main_returns_2_on_missing_file(self):
        rc = cli_verify.main(["/nonexistent/seal.json"])
        self.assertEqual(rc, 2)

    def test_main_saves_tsa_token_when_requested(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = hashlib.sha256(b"manifest content").hexdigest()
            seal = _make_seal(Path(tmp), digest_hex, tsa_token_der_b64="ZGVhZGJlZWY=")
            seal_path = Path(tmp) / "seal.json"
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            token_path = Path(tmp) / "token.der"
            rc = cli_verify.main([str(seal_path), "--save-tsa-token", str(token_path)])
            self.assertEqual(rc, 0)
            self.assertEqual(token_path.read_bytes(), b"deadbeef")


if __name__ == "__main__":
    unittest.main()
