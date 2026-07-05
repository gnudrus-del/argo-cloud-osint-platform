"""Sync del grafo entità-relazioni verso Neo4j — via HTTP Transactional Cypher.

Usa l'endpoint HTTP di Neo4j (``/db/<db>/tx/commit``) con urllib puro: nessun
driver ``neo4j`` da installare, basta un'istanza Neo4j raggiungibile. Questo
mantiene la piattaforma base senza dipendenze aggiuntive (native-first).

Configurazione via env (nel .env sulla VM, non nel repo):
    NEO4J_HTTP_URL   base HTTP (es. http://127.0.0.1:7474)
    NEO4J_DATABASE   nome db (default: neo4j)
    NEO4J_USER       utente (default: neo4j)
    NEO4J_PASSWORD   password

Se URL o password mancano -> ``available() == False`` e ``sync_graph`` è no-op.
Nessuna eccezione propagata al chiamante: il sync è best-effort, non deve mai
rompere un job OSINT.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any


def _config() -> dict:
    return {
        "url": os.getenv("NEO4J_HTTP_URL", "").rstrip("/"),
        "db": os.getenv("NEO4J_DATABASE", "neo4j"),
        "user": os.getenv("NEO4J_USER", "neo4j"),
        "password": os.getenv("NEO4J_PASSWORD", ""),
    }


class Neo4jSync:
    """Client HTTP minimale per pushare un grafo Argo su Neo4j."""

    def __init__(self, config: dict | None = None):
        self.cfg = config or _config()

    def available(self) -> bool:
        return bool(self.cfg.get("url") and self.cfg.get("password"))

    def _auth_header(self) -> str:
        raw = f"{self.cfg['user']}:{self.cfg['password']}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _commit(self, statements: list[dict], timeout: int = 15) -> dict | None:
        url = f"{self.cfg['url']}/db/{self.cfg['db']}/tx/commit"
        body = json.dumps({"statements": statements}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "argo-osint/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    def health_check(self) -> bool:
        if not self.available():
            return False
        res = self._commit([{"statement": "RETURN 1 AS ok", "parameters": {}}])
        return bool(res and not res.get("errors"))

    def sync_graph(self, graph: dict, *, case_id: str = "") -> dict:
        """Pusha nodi e archi (formato export_d3_json) su Neo4j via MERGE.

        MERGE garantisce idempotenza: rieseguire lo stesso caso non duplica.
        Ritorna un dict di esito ({synced, nodes, rels, error}).
        """
        if not self.available():
            return {"synced": False, "reason": "Neo4j non configurato (NEO4J_HTTP_URL/PASSWORD)."}

        nodes = graph.get("nodes") or []
        links = graph.get("links") or []
        statements: list[dict] = []

        for n in nodes:
            statements.append({
                "statement": (
                    "MERGE (e:Entity {id: $id}) "
                    "SET e.kind = $kind, e.value = $value, e.label = $label, "
                    "e.confidence = $confidence, e.severity = $severity, "
                    "e.case_id = $case_id"
                ),
                "parameters": {
                    "id": n.get("id"), "kind": n.get("kind", ""),
                    "value": n.get("value", ""), "label": n.get("label", ""),
                    "confidence": n.get("confidence", 0.0),
                    "severity": n.get("severity", ""), "case_id": case_id,
                },
            })
        for e in links:
            statements.append({
                "statement": (
                    "MATCH (a:Entity {id: $source}), (b:Entity {id: $target}) "
                    "MERGE (a)-[r:REL {kind: $kind}]->(b) "
                    "SET r.confidence = $confidence, r.evidence_url = $evidence_url, "
                    "r.case_id = $case_id"
                ),
                "parameters": {
                    "source": e.get("source"), "target": e.get("target"),
                    "kind": e.get("kind", "related-to"),
                    "confidence": e.get("confidence", 0.0),
                    "evidence_url": e.get("evidence_url", ""), "case_id": case_id,
                },
            })

        if not statements:
            return {"synced": True, "nodes": 0, "rels": 0, "note": "grafo vuoto"}

        # Neo4j HTTP accetta più statement in un commit atomico.
        res = self._commit(statements)
        if res is None:
            return {"synced": False, "reason": "commit HTTP fallito o Neo4j irraggiungibile."}
        errors = res.get("errors") or []
        if errors:
            return {"synced": False, "reason": str(errors[0])[:300]}
        return {"synced": True, "nodes": len(nodes), "rels": len(links)}


def sync_investigation_graph(graph: dict, *, case_id: str = "") -> dict:
    """Helper best-effort: costruisce il client dall'env e sincronizza.

    Non solleva mai: il sync verso Neo4j è opzionale e non deve interrompere
    la pipeline OSINT.
    """
    try:
        client = Neo4jSync()
        if not client.available():
            return {"synced": False, "reason": "Neo4j non configurato."}
        return client.sync_graph(graph, case_id=case_id)
    except Exception as exc:  # pragma: no cover
        return {"synced": False, "reason": f"eccezione: {exc}"}


def capabilities() -> dict[str, Any]:
    cfg = _config()
    return {"configured": bool(cfg.get("url") and cfg.get("password")),
            "url": cfg.get("url", "")}
