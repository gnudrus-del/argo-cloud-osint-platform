"""Tests for Pillar 0.3 — chain of custody and artifact integrity."""
import tempfile
import unittest
from pathlib import Path

from osint_bot.custody import (
    artifact_sha256,
    command_hash,
    export_case_manifest,
    save_artifact,
)
from osint_bot.storage import Storage


def _store(tmp: str) -> Storage:
    return Storage(Path(tmp) / "gufo.sqlite3")


class ArtifactHashTests(unittest.TestCase):
    def test_sha256_str_and_bytes_consistent(self):
        content = "hello world"
        self.assertEqual(artifact_sha256(content), artifact_sha256(content.encode("utf-8")))

    def test_sha256_changes_on_tamper(self):
        original = artifact_sha256("original content")
        tampered = artifact_sha256("tampered content")
        self.assertNotEqual(original, tampered)

    def test_command_hash_deterministic(self):
        argv = ["nmap", "-Pn", "-sV", "--", "example.com"]
        self.assertEqual(command_hash(argv), command_hash(argv))

    def test_command_hash_order_sensitive(self):
        a = command_hash(["tool", "arg1", "arg2"])
        b = command_hash(["tool", "arg2", "arg1"])
        self.assertNotEqual(a, b)


class SaveArtifactTests(unittest.TestCase):
    def test_save_artifact_records_hash(self):
        tmp_obj = tempfile.TemporaryDirectory()
        tmp = tmp_obj.name
        store = _store(tmp)
        try:
            content = "nmap output line 1\nline 2"
            art = save_artifact(
                artifact_type="tool_output",
                content=content,
                job_id="a" * 32,
                tool_name="nmap",
                argv=["nmap", "-Pn", "--", "example.com"],
                actor="analyst",
                storage=store,
            )
            self.assertEqual(art["content_sha256"], artifact_sha256(content))
            self.assertEqual(art["tool_name"], "nmap")
            self.assertEqual(art["artifact_type"], "tool_output")

            loaded = store.get_artifact(art["id"])
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["content_sha256"], art["content_sha256"])
        finally:
            store.close()
            tmp_obj.cleanup()

    def test_save_artifact_survives_missing_storage(self):
        # No storage provided — must not raise.
        art = save_artifact(
            artifact_type="tool_output",
            content="data",
            tool_name="sherlock",
        )
        self.assertIn("content_sha256", art)


class ManifestTests(unittest.TestCase):
    def _run_with_store(self, func):
        """Run *func(tmp: str, store: Storage)* with guaranteed close+cleanup."""
        tmp_obj = tempfile.TemporaryDirectory()
        store = _store(tmp_obj.name)
        try:
            func(tmp_obj.name, store)
        finally:
            store.close()
            tmp_obj.cleanup()

    def test_manifest_all_verified_when_no_files(self):
        """Ephemeral artifacts (no storage_path) count as verified."""
        def run(tmp, store):
            case_id = "case-001"
            save_artifact(
                artifact_type="tool_output",
                content="sherlock output",
                case_id=case_id,
                tool_name="sherlock",
                storage=store,
            )
            manifest = export_case_manifest(case_id, store, Path(tmp))
            self.assertEqual(manifest["case_id"], case_id)
            self.assertEqual(manifest["artifact_count"], 1)
            self.assertTrue(manifest["all_verified"])
            self.assertIn("manifest_hash", manifest)
        self._run_with_store(run)

    def test_manifest_detects_tampered_file(self):
        """An on-disk artifact whose content differs from the recorded hash fails verification."""
        def run(tmp, store):
            case_id = "case-002"
            original = b"original content"
            rel_path = "artifact.bin"
            abs_path = Path(tmp) / rel_path
            abs_path.write_bytes(original)
            save_artifact(
                artifact_type="archive",
                content=original,
                case_id=case_id,
                tool_name="singlefile",
                storage_path=rel_path,
                storage=store,
            )
            manifest_ok = export_case_manifest(case_id, store, Path(tmp))
            self.assertTrue(manifest_ok["all_verified"])
            abs_path.write_bytes(b"tampered content")
            manifest_bad = export_case_manifest(case_id, store, Path(tmp))
            self.assertFalse(manifest_bad["all_verified"])
        self._run_with_store(run)

    def test_manifest_hash_changes_when_new_artifact_added(self):
        def run(tmp, store):
            case_id = "case-003"
            save_artifact(artifact_type="tool_output", content="a", case_id=case_id, storage=store)
            m1 = export_case_manifest(case_id, store, Path(tmp))
            save_artifact(artifact_type="tool_output", content="b", case_id=case_id, storage=store)
            m2 = export_case_manifest(case_id, store, Path(tmp))
            self.assertNotEqual(m1["manifest_hash"], m2["manifest_hash"])
        self._run_with_store(run)


class ProvenanceOnFindingTests(unittest.TestCase):
    def test_finding_provenance_serializes_via_asdict(self):
        """Provenance must survive asdict() round-trip (used in Investigation.to_dict)."""
        from dataclasses import asdict

        from osint_bot.models import Evidence, Finding, Provenance

        prov = Provenance(
            tool="sherlock",
            collected_at="2026-06-26T10:00:00+00:00",
            actor="analyst",
            case_id="case-xyz",
            command_hash="abc123",
        )
        finding = Finding(
            kind="external_sherlock_profile",
            value="https://twitter.com/target",
            confidence=0.55,
            evidence=[Evidence(url="tool://sherlock", title="sherlock")],
            provenance=prov,
        )
        d = asdict(finding)
        self.assertEqual(d["provenance"]["tool"], "sherlock")
        self.assertEqual(d["provenance"]["case_id"], "case-xyz")

    def test_finding_without_provenance_is_backward_compatible(self):
        from dataclasses import asdict

        from osint_bot.models import Finding

        f = Finding(kind="domain", value="example.com", confidence=0.9)
        d = asdict(f)
        self.assertIsNone(d["provenance"])


if __name__ == "__main__":
    unittest.main()
