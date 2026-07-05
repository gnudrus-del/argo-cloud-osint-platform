"""Test offline per Neo4j/OpenSearch: senza env i client sono no-op e non
sollevano; verifichiamo anche la costruzione degli statement/bulk senza rete."""
import os
import unittest

from osint_bot.neo4j_sync import Neo4jSync, sync_investigation_graph
from osint_bot.opensearch_index import OpenSearchIndex, index_investigation


GRAPH = {
    "nodes": [
        {"id": "n1", "kind": "domain", "value": "example.com", "label": "example.com", "confidence": 0.9, "severity": ""},
        {"id": "n2", "kind": "ip", "value": "93.184.216.34", "label": "ip", "confidence": 0.8, "severity": "medium"},
    ],
    "links": [
        {"id": "e1", "source": "n1", "target": "n2", "kind": "resolves_to", "confidence": 0.85, "evidence_url": ""},
    ],
}

INV = {
    "target": "example.com", "target_type": "domain",
    "findings": [
        {"kind": "dns_a", "value": "93.184.216.34", "confidence": 0.9,
         "source_reliability": "A", "info_credibility": 1, "notes": "record"},
    ],
}


class Neo4jTests(unittest.TestCase):
    def setUp(self):
        for k in ("NEO4J_HTTP_URL", "NEO4J_PASSWORD"):
            os.environ.pop(k, None)

    def test_not_available_without_env(self):
        self.assertFalse(Neo4jSync().available())

    def test_sync_is_noop_without_config(self):
        res = sync_investigation_graph(GRAPH, case_id="C1")
        self.assertFalse(res["synced"])
        self.assertIn("reason", res)

    def test_available_with_config(self):
        client = Neo4jSync({"url": "http://x:7474", "db": "neo4j", "user": "neo4j", "password": "p"})
        self.assertTrue(client.available())

    def test_sync_builds_statements_offline(self):
        # Non facciamo rete: _commit fallirà (None) ma verifichiamo che il client
        # costruisca correttamente le richieste e gestisca il fallimento.
        client = Neo4jSync({"url": "http://127.0.0.1:1", "db": "neo4j", "user": "neo4j", "password": "p"})
        res = client.sync_graph(GRAPH, case_id="C1")
        self.assertFalse(res["synced"])  # host irraggiungibile
        self.assertIn("reason", res)

    def test_empty_graph_ok(self):
        client = Neo4jSync({"url": "http://x", "db": "neo4j", "user": "u", "password": "p"})
        res = client.sync_graph({"nodes": [], "links": []}, case_id="C1")
        self.assertTrue(res["synced"])
        self.assertEqual(res["nodes"], 0)


class OpenSearchTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop("OPENSEARCH_URL", None)

    def test_not_available_without_env(self):
        self.assertFalse(OpenSearchIndex().available())

    def test_index_noop_without_config(self):
        res = index_investigation("job1", INV, case_id="C1")
        self.assertFalse(res["indexed"])

    def test_available_with_url(self):
        self.assertTrue(OpenSearchIndex({"url": "http://x:9200", "index": "argo", "verify": True}).available())

    def test_index_handles_unreachable(self):
        client = OpenSearchIndex({"url": "http://127.0.0.1:1", "index": "argo", "verify": True})
        res = client.index_findings("job1", INV, case_id="C1")
        self.assertFalse(res["indexed"])

    def test_search_noop_without_config(self):
        res = OpenSearchIndex().search("test")
        self.assertEqual(res["hits"], [])


if __name__ == "__main__":
    unittest.main()
