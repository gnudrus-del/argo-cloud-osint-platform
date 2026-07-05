import unittest

from osint_bot.stix_export import (
    investigation_to_misp_event,
    investigation_to_stix_bundle,
)


SAMPLE = {
    "target": "example.com",
    "target_type": "domain",
    "generated_at": "2026-07-01T10:00:00",
    "entities": [
        {"id": "e1", "type": "domain", "value": "example.com", "confidence": 0.9},
        {"id": "e2", "type": "ip", "value": "93.184.216.34", "confidence": 0.8},
        {"id": "e3", "type": "email", "value": "admin@example.com", "confidence": 0.7},
        {"id": "e4", "type": "person", "value": "Mario Rossi", "confidence": 0.6},
        {"id": "e5", "type": "crypto", "value": "0xabc123", "confidence": 0.5},
    ],
    "relationships": [
        {"source": "e1", "target": "e2", "kind": "resolves_to", "confidence": 0.85},
        {"source": "e1", "target": "e3", "kind": "has_contact", "confidence": 0.7},
    ],
    "findings": [
        {"kind": "dns_a", "value": "93.184.216.34", "confidence": 0.95,
         "source_reliability": "A", "info_credibility": 1, "notes": "record A"},
        {"kind": "archived_url", "value": "https://example.com/old", "confidence": 0.9,
         "source_reliability": "A", "info_credibility": 1},
    ],
}


class StixExportTests(unittest.TestCase):
    def test_bundle_is_valid_shape(self):
        bundle = investigation_to_stix_bundle(SAMPLE)
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("identity", types)          # Argo + persona
        self.assertIn("domain-name", types)
        self.assertIn("ipv4-addr", types)
        self.assertIn("email-addr", types)
        self.assertIn("relationship", types)
        self.assertIn("note", types)
        self.assertIn("report", types)

    def test_bundle_ids_are_deterministic(self):
        b1 = investigation_to_stix_bundle(SAMPLE)
        b2 = investigation_to_stix_bundle(SAMPLE)
        self.assertEqual(b1["id"], b2["id"])
        self.assertEqual(
            [o["id"] for o in b1["objects"]],
            [o["id"] for o in b2["objects"]],
        )

    def test_relationships_reference_real_objects(self):
        bundle = investigation_to_stix_bundle(SAMPLE)
        ids = {o["id"] for o in bundle["objects"]}
        for obj in bundle["objects"]:
            if obj["type"] == "relationship":
                self.assertIn(obj["source_ref"], ids)
                self.assertIn(obj["target_ref"], ids)

    def test_report_refs_all_objects(self):
        bundle = investigation_to_stix_bundle(SAMPLE)
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        other_ids = {o["id"] for o in bundle["objects"] if o["type"] != "report"}
        self.assertEqual(set(report["object_refs"]), other_ids)

    def test_ipv6_detected(self):
        inv = {"target": "x", "target_type": "ip", "generated_at": "2026-01-01",
               "entities": [{"id": "a", "type": "ip", "value": "2001:db8::1"}],
               "relationships": [], "findings": []}
        bundle = investigation_to_stix_bundle(inv)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv6-addr", types)

    def test_misp_event_shape(self):
        event = investigation_to_misp_event(SAMPLE)
        self.assertIn("Event", event)
        attrs = event["Event"]["Attribute"]
        values = {a["value"] for a in attrs}
        self.assertIn("example.com", values)
        self.assertIn("93.184.216.34", values)
        types = {a["type"] for a in attrs}
        self.assertIn("domain", types)
        self.assertIn("ip-dst", types)
        # crypto 0x -> eth
        self.assertIn("eth", types)

    def test_misp_dedupes(self):
        event = investigation_to_misp_event(SAMPLE)
        attrs = event["Event"]["Attribute"]
        keys = [(a["type"], a["value"]) for a in attrs]
        self.assertEqual(len(keys), len(set(keys)))

    def test_empty_investigation_does_not_crash(self):
        bundle = investigation_to_stix_bundle({})
        self.assertEqual(bundle["type"], "bundle")
        event = investigation_to_misp_event({})
        self.assertIn("Event", event)


if __name__ == "__main__":
    unittest.main()
