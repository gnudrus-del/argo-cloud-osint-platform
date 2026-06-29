"""Tests for Pillar 4 — link_analysis.py."""
from __future__ import annotations

import json
import unittest

from osint_bot.link_analysis import (
    EntityGraph,
    GraphCluster,
    GraphEdge,
    GraphNode,
    GraphPath,
    detect_clusters,
    export_d3_json,
    export_graphml,
    find_paths,
    resolve_entities,
    _stable_id,
)
from osint_bot.models import Evidence, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(kind: str, value: str, confidence: float = 0.7,
       ev_url: str = "") -> Finding:
    evidence = [Evidence(url=ev_url, title="test")] if ev_url else []
    return Finding(kind=kind, value=value, confidence=confidence,
                   evidence=evidence, severity="medium")


def _graph_triangle() -> EntityGraph:
    """A→B→C→A cycle (3 nodes, 3 edges)."""
    g = EntityGraph()
    a = g.upsert_node("domain", "a.com")
    b = g.upsert_node("ip", "1.2.3.4")
    c = g.upsert_node("email", "x@a.com")
    g.upsert_edge(a, b, "resolves_to", 0.9)
    g.upsert_edge(b, c, "related_to", 0.8)
    g.upsert_edge(c, a, "linked_from", 0.7)
    return g


# ---------------------------------------------------------------------------
# EntityGraph basic operations
# ---------------------------------------------------------------------------

class EntityGraphTests(unittest.TestCase):
    def test_upsert_node_creates_node(self):
        g = EntityGraph()
        nid = g.upsert_node("domain", "example.com")
        self.assertIsNotNone(g.node(nid))
        self.assertEqual(g.node_count(), 1)

    def test_duplicate_node_merges(self):
        g = EntityGraph()
        g.upsert_node("domain", "example.com", confidence=0.5)
        g.upsert_node("domain", "example.com", confidence=0.9)
        self.assertEqual(g.node_count(), 1)
        nid = _stable_id("domain", "example.com")
        self.assertAlmostEqual(g.node(nid).confidence, 0.9)

    def test_upsert_edge_creates_edge(self):
        g = EntityGraph()
        a = g.upsert_node("domain", "a.com")
        b = g.upsert_node("ip", "1.2.3.4")
        eid = g.upsert_edge(a, b, "resolves_to", 0.8)
        self.assertEqual(g.edge_count(), 1)
        self.assertEqual(g.edge(eid).kind, "resolves_to")

    def test_out_edges(self):
        g = _graph_triangle()
        a = _stable_id("domain", "a.com")
        out = g.out_edges(a)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].kind, "resolves_to")

    def test_neighbours(self):
        g = _graph_triangle()
        a = _stable_id("domain", "a.com")
        nb = g.neighbours(a)
        self.assertEqual(len(nb), 2)

    def test_degree_in_triangle(self):
        g = _graph_triangle()
        a = _stable_id("domain", "a.com")
        self.assertEqual(g.degree(a), 2)  # 1 out + 1 in

    def test_stable_id_deterministic(self):
        id1 = _stable_id("domain", "example.com")
        id2 = _stable_id("domain", "example.com")
        self.assertEqual(id1, id2)

    def test_stable_id_different_kinds(self):
        self.assertNotEqual(
            _stable_id("domain", "x.com"),
            _stable_id("ip", "x.com"),
        )

    def test_merge_graph(self):
        g1 = EntityGraph()
        g1.upsert_node("domain", "a.com")
        g2 = EntityGraph()
        g2.upsert_node("ip", "1.2.3.4")
        g1.merge_graph(g2)
        self.assertEqual(g1.node_count(), 2)


# ---------------------------------------------------------------------------
# resolve_entities
# ---------------------------------------------------------------------------

class ResolveEntitiesTests(unittest.TestCase):
    def test_one_finding_one_node(self):
        findings = [_f("subdomain_ct", "api.example.com")]
        g = resolve_entities(findings)
        self.assertEqual(g.node_count(), 1)

    def test_duplicate_values_merged(self):
        findings = [
            _f("subdomain_ct", "api.example.com", ev_url="https://crt.sh"),
            _f("shodan_hostname", "api.example.com", ev_url="https://shodan.io"),
        ]
        g = resolve_entities(findings)
        # Both resolve to "domain" kind + same value → same node
        self.assertEqual(g.node_count(), 1)

    def test_co_location_edge_created(self):
        findings = [
            _f("shodan_open_port", "1.2.3.4:80/tcp", ev_url="https://shodan.io/host/1.2.3.4"),
            _f("shodan_vuln", "CVE-2021-41773", ev_url="https://shodan.io/host/1.2.3.4"),
        ]
        g = resolve_entities(findings)
        self.assertGreater(g.edge_count(), 0)

    def test_no_edge_without_shared_evidence(self):
        findings = [
            _f("subdomain_ct", "api.example.com"),
            _f("shodan_vuln", "CVE-2021-41773"),
        ]
        g = resolve_entities(findings)
        # No shared evidence URL → no edge
        self.assertEqual(g.edge_count(), 0)

    def test_severity_propagated_to_node(self):
        f = Finding(kind="red_team_aws_access_key", value="AKIA...",
                    confidence=0.9, severity="critical", evidence=[])
        g = resolve_entities([f])
        node = list(g.nodes())[0]
        self.assertEqual(node.severity, "critical")

    def test_finding_kind_stored_in_attributes(self):
        findings = [_f("shodan_open_port", "1.2.3.4:443/tcp")]
        g = resolve_entities(findings)
        node = list(g.nodes())[0]
        self.assertEqual(node.attributes.get("finding_kind"), "shodan_open_port")

    def test_empty_findings_returns_empty_graph(self):
        g = resolve_entities([])
        self.assertEqual(g.node_count(), 0)
        self.assertEqual(g.edge_count(), 0)


# ---------------------------------------------------------------------------
# find_paths
# ---------------------------------------------------------------------------

class FindPathsTests(unittest.TestCase):
    def _linear_graph(self) -> tuple[EntityGraph, str, str, str]:
        """A → B → C linear path."""
        g = EntityGraph()
        a = g.upsert_node("domain", "a.com")
        b = g.upsert_node("ip", "1.1.1.1")
        c = g.upsert_node("email", "x@a.com")
        g.upsert_edge(a, b, "resolves_to", 0.9)
        g.upsert_edge(b, c, "related_to", 0.8)
        return g, a, b, c

    def test_direct_neighbours_found(self):
        g, a, b, _ = self._linear_graph()
        paths = find_paths(g, a, b)
        self.assertTrue(paths)
        self.assertEqual(paths[0].length, 1)

    def test_indirect_path_found(self):
        g, a, _, c = self._linear_graph()
        paths = find_paths(g, a, c)
        self.assertTrue(paths)
        self.assertEqual(paths[0].length, 2)

    def test_no_path_between_disconnected_nodes(self):
        g = EntityGraph()
        a = g.upsert_node("domain", "a.com")
        b = g.upsert_node("ip", "9.9.9.9")
        paths = find_paths(g, a, b)
        self.assertEqual(paths, [])

    def test_source_equals_target_returns_trivial_path(self):
        g, a, _, _ = self._linear_graph()
        paths = find_paths(g, a, a)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].length, 0)

    def test_max_depth_respected(self):
        # Chain: a → b → c → d → e (4 hops)
        g = EntityGraph()
        ids = [g.upsert_node("entity", str(i)) for i in range(5)]
        for i in range(4):
            g.upsert_edge(ids[i], ids[i + 1], "chain", 0.9)
        paths = find_paths(g, ids[0], ids[4], max_depth=2)
        # max_depth=2 means at most 3 nodes → 4-hop path should not be found
        self.assertEqual(paths, [])

    def test_unknown_node_returns_empty(self):
        g, a, _, _ = self._linear_graph()
        paths = find_paths(g, a, "non-existent-id")
        self.assertEqual(paths, [])

    def test_confidence_product_computed(self):
        g, a, _, c = self._linear_graph()
        paths = find_paths(g, a, c)
        self.assertAlmostEqual(paths[0].total_confidence, round(0.9 * 0.8, 4))


# ---------------------------------------------------------------------------
# detect_clusters
# ---------------------------------------------------------------------------

class DetectClustersTests(unittest.TestCase):
    def test_triangle_forms_one_cluster(self):
        g = _graph_triangle()
        clusters = detect_clusters(g)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].size, 3)

    def test_two_disconnected_components(self):
        g = EntityGraph()
        a = g.upsert_node("domain", "a.com")
        b = g.upsert_node("ip", "1.1.1.1")
        g.upsert_edge(a, b, "resolves_to", 0.8)
        c = g.upsert_node("domain", "z.com")
        d = g.upsert_node("ip", "9.9.9.9")
        g.upsert_edge(c, d, "resolves_to", 0.8)
        clusters = detect_clusters(g)
        self.assertEqual(len(clusters), 2)

    def test_clusters_sorted_by_size_descending(self):
        g = _graph_triangle()
        a = g.upsert_node("domain", "solo.com")
        b = g.upsert_node("ip", "10.0.0.1")
        g.upsert_edge(a, b, "resolves_to", 0.7)
        clusters = detect_clusters(g)
        sizes = [c.size for c in clusters]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_isolated_node_excluded_with_min_degree_1(self):
        g = EntityGraph()
        g.upsert_node("domain", "isolated.com")   # degree 0
        a = g.upsert_node("ip", "1.1.1.1")
        b = g.upsert_node("email", "x@x.com")
        g.upsert_edge(a, b, "related_to", 0.8)
        clusters = detect_clusters(g, min_degree=1)
        all_nodes = set().union(*[set(c.node_ids) for c in clusters])
        self.assertNotIn(_stable_id("domain", "isolated.com"), all_nodes)

    def test_hub_is_highest_degree_node(self):
        g = EntityGraph()
        hub = g.upsert_node("ip", "central.ip")
        for i in range(4):
            spoke = g.upsert_node("domain", f"spoke{i}.com")
            g.upsert_edge(hub, spoke, "has_port", 0.8)
        clusters = detect_clusters(g)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].hub_node_id, hub)


# ---------------------------------------------------------------------------
# Export formats
# ---------------------------------------------------------------------------

class ExportD3JSONTests(unittest.TestCase):
    def test_has_nodes_and_links_keys(self):
        g = _graph_triangle()
        d = export_d3_json(g)
        self.assertIn("nodes", d)
        self.assertIn("links", d)
        self.assertIn("meta", d)

    def test_node_count_matches(self):
        g = _graph_triangle()
        d = export_d3_json(g)
        self.assertEqual(len(d["nodes"]), 3)

    def test_link_count_matches(self):
        g = _graph_triangle()
        d = export_d3_json(g)
        self.assertEqual(len(d["links"]), 3)

    def test_serialisable_to_json(self):
        g = _graph_triangle()
        d = export_d3_json(g)
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["meta"]["node_count"], 3)

    def test_node_has_required_fields(self):
        g = EntityGraph()
        g.upsert_node("domain", "example.com", confidence=0.8)
        d = export_d3_json(g)
        node = d["nodes"][0]
        for key in ("id", "kind", "label", "value", "confidence", "severity"):
            self.assertIn(key, node)


class ExportGraphMLTests(unittest.TestCase):
    def test_produces_xml_string(self):
        g = _graph_triangle()
        xml_str = export_graphml(g)
        self.assertIn("<graphml", xml_str)
        self.assertIn("<node", xml_str)
        self.assertIn("<edge", xml_str)

    def test_node_count_in_xml(self):
        g = _graph_triangle()
        xml_str = export_graphml(g)
        self.assertEqual(xml_str.count("<node "), 3)

    def test_edge_count_in_xml(self):
        g = _graph_triangle()
        xml_str = export_graphml(g)
        self.assertEqual(xml_str.count("<edge "), 3)

    def test_graphml_is_valid_xml(self):
        g = _graph_triangle()
        xml_str = export_graphml(g)
        # Should not raise
        import xml.etree.ElementTree as ET
        ET.fromstring(xml_str)


if __name__ == "__main__":
    unittest.main()
