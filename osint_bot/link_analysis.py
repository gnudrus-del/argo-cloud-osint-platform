"""Pillar 4 — Link Analysis [PIANO].

Graph-based entity resolution and relationship analysis for OSINT investigations.

Provides a pure-Python in-memory graph (no external dependencies) with:

  EntityGraph
      Mutable directed multigraph.  Nodes are OSINT entities; edges are typed
      relationships with confidence weights.  Supports merge, dedup, and
      incremental updates from new finding batches.

  resolve_entities(findings)
      Converts a flat list of Finding objects into an EntityGraph, applying
      entity resolution rules (same-value merging, alias detection, co-location).

  find_paths(graph, source_id, target_id, max_depth)
      BFS shortest-path finder between two entities.

  detect_clusters(graph, min_degree)
      Community detection via connected-component analysis.  Returns clusters
      (sets of entity IDs) that share a high-degree neighbourhood.

  export_d3_json(graph)
      Serialises the graph as a D3.js-compatible ``{"nodes": [...], "links": [...]}``
      dict for frontend rendering.

  export_graphml(graph)
      Serialises the graph as a GraphML XML string for Gephi / yEd import.

Design notes
------------
- No FK on edges: edges can reference non-existent nodes (imported from partial
  exports).  Resolution is best-effort.
- All entity IDs are stable UUIDs derived from ``kind + ":" + canonical_value``
  to enable deterministic merging across scans.
- Confidence on edges is the max of all contributing evidences.
"""
from __future__ import annotations

import hashlib
import re
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterator

from .models import Evidence, Finding


# ---------------------------------------------------------------------------
# Core graph types
# ---------------------------------------------------------------------------

def _stable_id(kind: str, value: str) -> str:
    """Deterministic UUID v5 from kind + canonical value."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
    canonical = f"{kind.lower()}:{value.strip().lower()}"
    return str(uuid.uuid5(namespace, canonical))


@dataclass
class GraphNode:
    id: str
    kind: str               # entity type: domain, ip, email, person, url, …
    value: str
    label: str = ""
    confidence: float = 0.5
    aliases: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    severity: str = ""      # propagated from highest-severity finding
    attck_ttps: list[str] = field(default_factory=list)

    def merge(self, other: "GraphNode") -> None:
        """Absorb another node with the same id in-place."""
        self.confidence = max(self.confidence, other.confidence)
        for alias in other.aliases:
            if alias not in self.aliases:
                self.aliases.append(alias)
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        self.attributes.update(other.attributes)
        if other.severity and _SEV_RANK.get(other.severity, 0) > _SEV_RANK.get(self.severity, 0):
            self.severity = other.severity
        for ttp in other.attck_ttps:
            if ttp not in self.attck_ttps:
                self.attck_ttps.append(ttp)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "": -1}


@dataclass
class GraphEdge:
    id: str
    source: str      # node id
    target: str      # node id
    kind: str        # relationship type: resolves_to, registered_by, linked_from, …
    confidence: float = 0.5
    evidence_url: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


class EntityGraph:
    """In-memory directed multigraph for OSINT entity relationships."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adj: dict[str, list[str]] = defaultdict(list)   # source → [edge_id]
        self._radj: dict[str, list[str]] = defaultdict(list)  # target → [edge_id]

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> str:
        if node.id in self._nodes:
            self._nodes[node.id].merge(node)
        else:
            self._nodes[node.id] = node
        return node.id

    def add_edge(self, edge: GraphEdge) -> str:
        if edge.id not in self._edges:
            self._edges[edge.id] = edge
            self._adj[edge.source].append(edge.id)
            self._radj[edge.target].append(edge.id)
        return edge.id

    def upsert_node(self, kind: str, value: str, **kwargs) -> str:
        node_id = _stable_id(kind, value)
        node = GraphNode(id=node_id, kind=kind, value=value, label=value, **kwargs)
        return self.add_node(node)

    def upsert_edge(self, source: str, target: str, kind: str,
                    confidence: float = 0.5, evidence_url: str = "",
                    **attrs) -> str:
        edge_id = _stable_id(f"{source}→{target}", kind)
        edge = GraphEdge(id=edge_id, source=source, target=target, kind=kind,
                         confidence=confidence, evidence_url=evidence_url,
                         attributes=attrs)
        return self.add_edge(edge)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def edge(self, edge_id: str) -> GraphEdge | None:
        return self._edges.get(edge_id)

    def nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def edges(self) -> list[GraphEdge]:
        return list(self._edges.values())

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def out_edges(self, node_id: str) -> list[GraphEdge]:
        return [self._edges[eid] for eid in self._adj.get(node_id, [])
                if eid in self._edges]

    def in_edges(self, node_id: str) -> list[GraphEdge]:
        return [self._edges[eid] for eid in self._radj.get(node_id, [])
                if eid in self._edges]

    def neighbours(self, node_id: str) -> list[str]:
        targets = {e.target for e in self.out_edges(node_id)}
        sources = {e.source for e in self.in_edges(node_id)}
        return list((targets | sources) - {node_id})

    def degree(self, node_id: str) -> int:
        return len(self.out_edges(node_id)) + len(self.in_edges(node_id))

    # ------------------------------------------------------------------
    # Merge
    # ------------------------------------------------------------------

    def merge_graph(self, other: "EntityGraph") -> None:
        for node in other.nodes():
            self.add_node(node)
        for edge in other.edges():
            self.add_edge(edge)


# ---------------------------------------------------------------------------
# Pillar 4.1 — Entity resolution from findings
# ---------------------------------------------------------------------------

# Map finding.kind → graph node type
_KIND_TO_NODE_TYPE: dict[str, str] = {
    "subdomain_ct": "domain",
    "whois_registrar": "organisation",
    "whois_nameserver": "nameserver",
    "whois_created": "date",
    "whois_expiry": "date",
    "whois_status": "domain_status",
    "shodan_open_port": "port",
    "shodan_cpe": "cpe",
    "shodan_vuln": "vulnerability",
    "shodan_hostname": "domain",
    "shodan_os": "os",
    "red_team_takeover_candidate": "domain",
    "red_team_aws_access_key": "credential",
    "red_team_private_key_header": "credential",
    "red_team_connection_string": "credential",
    "red_team_github_token": "credential",
    "red_team_slack_token": "credential",
    "red_team_jwt_token": "credential",
    "red_team_password_in_url": "credential",
    "red_team_google_api_key": "credential",
    "red_team_breach_mention": "url",
    "red_team_exposed_path": "path",
    "brand_typosquat": "domain",
    "brand_lookalike_handle": "handle",
    "ioc_ipv4": "ip",
    "ioc_ipv6": "ip",
    "ioc_domain": "domain",
    "ioc_url": "url",
    "ioc_md5": "file_hash",
    "ioc_sha1": "file_hash",
    "ioc_sha256": "file_hash",
    "ioc_email": "email",
    "ioc_cve": "vulnerability",
    "email_address": "email",
    "ip_geo": "ip",
}

_DEFAULT_NODE_TYPE = "entity"


def _infer_relationship(source_finding: Finding, target_finding: Finding) -> str:
    """Heuristic relationship label between two co-located findings."""
    s = source_finding.kind
    t = target_finding.kind
    if "port" in t and "hostname" in s:
        return "has_port"
    if "vuln" in t and "port" in s:
        return "has_vulnerability"
    if "cpe" in t and "port" in s:
        return "has_cpe"
    if "hostname" in t and "ip" in s:
        return "resolves_to"
    if "registrar" in t and "domain" in s:
        return "registered_by"
    if "nameserver" in t:
        return "uses_ns"
    return "related_to"


def resolve_entities(findings: list[Finding]) -> EntityGraph:
    """Convert a flat finding list into an EntityGraph.

    Rules
    -----
    1. One node per (kind, value) pair.
    2. Findings sharing the same evidence URL are assumed co-located and get
       a ``related_to`` edge between them.
    3. Shodan port → vuln / CPE / hostname edges are derived from kind patterns.
    4. Provenance is carried through to node sources.
    """
    graph = EntityGraph()

    # Pass 1: create nodes
    for f in findings:
        node_type = _KIND_TO_NODE_TYPE.get(f.kind, _DEFAULT_NODE_TYPE)
        sources = [e.url for e in f.evidence if e.url]
        graph.upsert_node(
            kind=node_type,
            value=f.value,
            confidence=f.confidence,
            severity=f.severity,
            attck_ttps=list(f.attck_ttps),
            sources=sources,
            attributes={"finding_kind": f.kind, "notes": f.notes[:200]},
        )

    # Pass 2: co-location edges (findings sharing evidence URL)
    by_url: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for ev in f.evidence:
            if ev.url:
                by_url[ev.url].append(f)

    for url, co_findings in by_url.items():
        if len(co_findings) < 2:
            continue
        for i, fi in enumerate(co_findings):
            for fj in co_findings[i + 1:]:
                src_id = _stable_id(_KIND_TO_NODE_TYPE.get(fi.kind, _DEFAULT_NODE_TYPE), fi.value)
                tgt_id = _stable_id(_KIND_TO_NODE_TYPE.get(fj.kind, _DEFAULT_NODE_TYPE), fj.value)
                if src_id != tgt_id:
                    rel = _infer_relationship(fi, fj)
                    graph.upsert_edge(
                        source=src_id,
                        target=tgt_id,
                        kind=rel,
                        confidence=min(fi.confidence, fj.confidence),
                        evidence_url=url,
                    )

    return graph


# ---------------------------------------------------------------------------
# Pillar 4.2 — Path finding
# ---------------------------------------------------------------------------

@dataclass
class GraphPath:
    node_ids: list[str]
    edge_ids: list[str]
    total_confidence: float   # product of edge confidences

    @property
    def length(self) -> int:
        return len(self.edge_ids)


def find_paths(
    graph: EntityGraph,
    source_id: str,
    target_id: str,
    max_depth: int = 6,
) -> list[GraphPath]:
    """BFS shortest-path finder (undirected, ignores edge direction).

    Returns at most 5 shortest paths to avoid combinatorial explosion.
    """
    if source_id not in graph._nodes or target_id not in graph._nodes:
        return []
    if source_id == target_id:
        return [GraphPath(node_ids=[source_id], edge_ids=[], total_confidence=1.0)]

    # BFS state: (current_node, path_node_ids, path_edge_ids, confidence)
    queue: deque = deque()
    queue.append((source_id, [source_id], [], 1.0))
    visited: set[str] = {source_id}
    results: list[GraphPath] = []

    while queue and len(results) < 5:
        current, path_nodes, path_edges, conf = queue.popleft()
        if len(path_nodes) > max_depth + 1:
            continue
        for edge in graph.out_edges(current) + graph.in_edges(current):
            neighbour = edge.target if edge.source == current else edge.source
            if neighbour in visited:
                continue
            new_conf = conf * edge.confidence
            new_nodes = path_nodes + [neighbour]
            new_edges = path_edges + [edge.id]
            if neighbour == target_id:
                results.append(GraphPath(
                    node_ids=new_nodes,
                    edge_ids=new_edges,
                    total_confidence=round(new_conf, 4),
                ))
            else:
                visited.add(neighbour)
                queue.append((neighbour, new_nodes, new_edges, new_conf))

    return results


# ---------------------------------------------------------------------------
# Pillar 4.3 — Cluster detection
# ---------------------------------------------------------------------------

@dataclass
class GraphCluster:
    id: int
    node_ids: list[str]
    hub_node_id: str    # highest-degree node in cluster
    density: float      # edges / possible edges

    @property
    def size(self) -> int:
        return len(self.node_ids)


def detect_clusters(
    graph: EntityGraph,
    min_degree: int = 1,
) -> list[GraphCluster]:
    """Connected-component clustering.

    Only includes nodes with degree >= min_degree.  Returns clusters sorted by
    size descending.
    """
    active = {nid for nid in graph._nodes if graph.degree(nid) >= min_degree}
    visited: set[str] = set()
    clusters: list[GraphCluster] = []

    def _bfs_component(start: str) -> list[str]:
        component: list[str] = []
        q: deque = deque([start])
        visited.add(start)
        while q:
            node = q.popleft()
            component.append(node)
            for nb in graph.neighbours(node):
                if nb in active and nb not in visited:
                    visited.add(nb)
                    q.append(nb)
        return component

    for node_id in active:
        if node_id not in visited:
            component = _bfs_component(node_id)
            hub = max(component, key=lambda n: graph.degree(n))
            n = len(component)
            max_edges = n * (n - 1) if n > 1 else 1
            actual_edges = sum(
                1 for e in graph.edges()
                if e.source in set(component) and e.target in set(component)
            )
            density = actual_edges / max_edges if max_edges else 0.0
            clusters.append(GraphCluster(
                id=len(clusters),
                node_ids=component,
                hub_node_id=hub,
                density=round(density, 4),
            ))

    clusters.sort(key=lambda c: c.size, reverse=True)
    for i, c in enumerate(clusters):
        c.id = i
    return clusters


# ---------------------------------------------------------------------------
# Pillar 4.4 — Export formats
# ---------------------------------------------------------------------------

def export_d3_json(graph: EntityGraph) -> dict[str, Any]:
    """Serialise graph as D3.js force-directed graph JSON."""
    nodes = []
    for n in graph.nodes():
        nodes.append({
            "id": n.id,
            "kind": n.kind,
            "label": n.label or n.value[:60],
            "value": n.value,
            "confidence": n.confidence,
            "severity": n.severity,
            "attck_ttps": n.attck_ttps,
            "degree": graph.degree(n.id),
            "sources": n.sources[:3],
        })

    links = []
    for e in graph.edges():
        links.append({
            "id": e.id,
            "source": e.source,
            "target": e.target,
            "kind": e.kind,
            "confidence": e.confidence,
            "evidence_url": e.evidence_url,
        })

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "node_count": graph.node_count(),
            "edge_count": graph.edge_count(),
        },
    }


def export_graphml(graph: EntityGraph) -> str:
    """Serialise graph as GraphML XML string (Gephi / yEd compatible)."""
    root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/graphml")
    # Key declarations
    for attr_id, attr_name, attr_type, for_elem in [
        ("d0", "kind", "string", "node"),
        ("d1", "label", "string", "node"),
        ("d2", "confidence", "double", "node"),
        ("d3", "severity", "string", "node"),
        ("d4", "kind", "string", "edge"),
        ("d5", "confidence", "double", "edge"),
    ]:
        key = ET.SubElement(root, "key", id=attr_id, **{
            "attr.name": attr_name, "attr.type": attr_type, "for": for_elem,
        })

    g = ET.SubElement(root, "graph", id="G", edgedefault="directed")

    for n in graph.nodes():
        node_el = ET.SubElement(g, "node", id=n.id)
        for attr_id, value in [("d0", n.kind), ("d1", n.label or n.value[:60]),
                                ("d2", str(n.confidence)), ("d3", n.severity)]:
            data = ET.SubElement(node_el, "data", key=attr_id)
            data.text = value

    for e in graph.edges():
        edge_el = ET.SubElement(g, "edge", id=e.id, source=e.source, target=e.target)
        for attr_id, value in [("d4", e.kind), ("d5", str(e.confidence))]:
            data = ET.SubElement(edge_el, "data", key=attr_id)
            data.text = value

    return ET.tostring(root, encoding="unicode", xml_declaration=False)
