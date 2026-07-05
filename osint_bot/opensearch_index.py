"""Indicizzazione full-text dei findings su OpenSearch — via REST + urllib.

Usa l'API REST di OpenSearch (bulk index + _search) con urllib puro: nessun
client ``opensearch-py`` da installare, basta un cluster raggiungibile. Questo
abilita ricerca full-text cross-caso sui findings senza aggiungere dipendenze.

Configurazione via env (nel .env sulla VM, non nel repo):
    OPENSEARCH_URL       base URL (es. https://127.0.0.1:9200)
    OPENSEARCH_INDEX     nome indice (default: argo-findings)
    OPENSEARCH_USER      utente (opzionale)
    OPENSEARCH_PASSWORD  password (opzionale)
    OPENSEARCH_VERIFY    "0" per disabilitare TLS verify (self-signed dev)

Se URL manca -> ``available() == False`` e le operazioni sono no-op.
Best-effort: nessuna eccezione propagata (l'indicizzazione non deve rompere un job).
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any


def _config() -> dict:
    return {
        "url": os.getenv("OPENSEARCH_URL", "").rstrip("/"),
        "index": os.getenv("OPENSEARCH_INDEX", "argo-findings"),
        "user": os.getenv("OPENSEARCH_USER", ""),
        "password": os.getenv("OPENSEARCH_PASSWORD", ""),
        "verify": os.getenv("OPENSEARCH_VERIFY", "1") != "0",
    }


class OpenSearchIndex:
    """Client REST minimale per indicizzare/ricercare findings su OpenSearch."""

    def __init__(self, config: dict | None = None):
        self.cfg = config or _config()

    def available(self) -> bool:
        return bool(self.cfg.get("url"))

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json",
             "User-Agent": "argo-osint/1.0"}
        if self.cfg.get("user"):
            raw = f"{self.cfg['user']}:{self.cfg['password']}".encode("utf-8")
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return h

    def _ssl_ctx(self):
        if self.cfg.get("verify"):
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, body: bytes | None = None,
                 timeout: int = 15) -> dict | None:
        url = f"{self.cfg['url']}{path}"
        req = urllib.request.Request(url, data=body, method=method, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx()) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8", errors="replace"))
            except Exception:
                return None
        except Exception:
            return None

    def health_check(self) -> bool:
        if not self.available():
            return False
        res = self._request("GET", "/_cluster/health")
        return bool(res and res.get("status") in ("green", "yellow", "red"))

    def ensure_index(self) -> bool:
        """Crea l'indice con un mapping minimale se non esiste (idempotente)."""
        if not self.available():
            return False
        exists = self._request("GET", f"/{self.cfg['index']}")
        if exists and not exists.get("error"):
            return True
        mapping = {
            "mappings": {
                "properties": {
                    "job_id": {"type": "keyword"},
                    "case_id": {"type": "keyword"},
                    "kind": {"type": "keyword"},
                    "value": {"type": "text"},
                    "notes": {"type": "text"},
                    "confidence": {"type": "float"},
                    "source_reliability": {"type": "keyword"},
                    "info_credibility": {"type": "integer"},
                    "target": {"type": "keyword"},
                    "indexed_at": {"type": "date"},
                }
            }
        }
        res = self._request("PUT", f"/{self.cfg['index']}",
                            json.dumps(mapping).encode("utf-8"))
        return bool(res and not res.get("error"))

    def index_findings(self, job_id: str, inv: dict, *, case_id: str = "",
                       indexed_at: str = "") -> dict:
        """Indicizza i findings dell'investigation via _bulk. Doc id deterministico
        (job_id + posizione) per idempotenza."""
        if not self.available():
            return {"indexed": False, "reason": "OpenSearch non configurato (OPENSEARCH_URL)."}
        self.ensure_index()
        findings = inv.get("findings") or []
        if not findings:
            return {"indexed": True, "count": 0, "note": "nessun finding"}

        target = inv.get("target", "")
        lines: list[str] = []
        for i, f in enumerate(findings):
            doc_id = f"{job_id}:{i}"
            lines.append(json.dumps({"index": {"_index": self.cfg["index"], "_id": doc_id}}))
            lines.append(json.dumps({
                "job_id": job_id, "case_id": case_id,
                "kind": f.get("kind", ""), "value": str(f.get("value", "")),
                "notes": f.get("notes", ""), "confidence": f.get("confidence", 0.0),
                "source_reliability": f.get("source_reliability", "F"),
                "info_credibility": f.get("info_credibility", 6),
                "target": target, "indexed_at": indexed_at or None,
            }, ensure_ascii=False))
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        res = self._request("POST", "/_bulk", payload)
        if res is None:
            return {"indexed": False, "reason": "bulk fallito o cluster irraggiungibile."}
        if res.get("errors"):
            return {"indexed": False, "reason": "alcuni documenti hanno errori di indicizzazione.",
                    "count": len(findings)}
        return {"indexed": True, "count": len(findings)}

    def search(self, query: str, *, size: int = 25, case_id: str = "") -> dict:
        """Ricerca full-text su value+notes, opzionalmente filtrata per caso."""
        if not self.available():
            return {"hits": [], "reason": "OpenSearch non configurato."}
        must: list[dict] = [{"multi_match": {"query": query, "fields": ["value^2", "notes", "kind"]}}]
        filt: list[dict] = []
        if case_id:
            filt.append({"term": {"case_id": case_id}})
        body = {"size": size, "query": {"bool": {"must": must, "filter": filt}}}
        res = self._request("POST", f"/{self.cfg['index']}/_search",
                            json.dumps(body).encode("utf-8"))
        if res is None or res.get("error"):
            return {"hits": [], "reason": "ricerca fallita."}
        hits = [{"id": h.get("_id"), "score": h.get("_score"), **(h.get("_source") or {})}
                for h in (((res.get("hits") or {}).get("hits")) or [])]
        return {"hits": hits, "total": ((res.get("hits") or {}).get("total") or {}).get("value", len(hits))}


def index_investigation(job_id: str, inv: dict, *, case_id: str = "", indexed_at: str = "") -> dict:
    """Helper best-effort: costruisce il client dall'env e indicizza. Mai solleva."""
    try:
        client = OpenSearchIndex()
        if not client.available():
            return {"indexed": False, "reason": "OpenSearch non configurato."}
        return client.index_findings(job_id, inv, case_id=case_id, indexed_at=indexed_at)
    except Exception as exc:  # pragma: no cover
        return {"indexed": False, "reason": f"eccezione: {exc}"}


def capabilities() -> dict[str, Any]:
    cfg = _config()
    return {"configured": bool(cfg.get("url")), "index": cfg.get("index", "")}
