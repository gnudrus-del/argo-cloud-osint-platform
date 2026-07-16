"""Connector: cloud storage bucket enumeration (S3/GCS/Azure).

Genera permutazioni plausibili del nome bucket a partire dal target (dominio o
nome azienda) e sonda tre provider cloud con richieste HEAD/GET standard sui
loro endpoint pubblici:

  * S3:    https://{candidate}.s3.amazonaws.com/
  * GCS:   https://{candidate}.storage.googleapis.com/
  * Azure: https://{candidate}.blob.core.windows.net/

Nessun bypass di autenticazione: solo endpoint HTTP pubblici documentati dai
provider. Se il bucket esiste ed e' listabile (risponde con un XML/JSON di
listing), si tratta di un'esposizione critica (chiunque puo' enumerare il
contenuto). Se esiste ma non e' listabile (richiede firma/param specifico),
resta comunque un segnale di esposizione (nome confermato, superficie
d'attacco nota). Se risponde 403 il bucket esiste ma e' privato — nessun
rischio confermato, solo un segnale informativo a bassa confidenza.

ATTIVO (action-gated): genera fino a qualche decina di candidati x 3 provider
di richieste HTTP verso servizi di terzi → richiede scope autorizzato del
caso, come port_scan/content_discovery.

Input: ``domain`` | ``company``.
"""
from __future__ import annotations

import concurrent.futures as _cf
import urllib.error

from .. import _safe_http
from ..connector import (
    ACTION_ACTIVE_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="cloud_buckets",
    label="Cloud storage bucket enumeration (S3/GCS/Azure)",
    action_class=ACTION_ACTIVE_GATED,
    input_types=("domain", "company"),
    output_categories=("cloud_exposure",),
    required_key="",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=5, per_day=200, burst=1),
    legal_note="cloud_buckets.legal_note",
    health_check_url="",
)

# Prefissi/suffissi ad alto valore OSINT per la ricognizione di bucket cloud.
# Il prodotto cartesiano completo (6 x 15) esploderebbe a 90 candidati per
# provider (270 richieste totali) — troppo per un rate-limit prudente.
# Generiamo invece: stem nudo + ogni suffisso + ogni prefisso (combinazioni
# lineari, non incrociate), ~20 candidati totali.
_PREFIXES = ["", "backup-", "assets-", "static-", "dev-", "prod-"]
_SUFFIXES = [
    "", "-backup", "-assets", "-static", "-media", "-data", "-uploads",
    "-dev", "-prod", "-staging", "-logs", "-private", "-public", "-dump",
    "-archive",
]

# Tetto esplicito e indipendente dalla lunghezza di prefissi/suffissi: anche
# se le liste sopra crescono in futuro, un singolo _fetch() non deve mai
# superare questo numero di candidati (ognuno costa fino a 2 richieste per
# provider x 3 provider = 6 richieste HTTP).
_MAX_CANDIDATES = 30

_PROVIDERS = (
    ("s3", "https://{c}.s3.amazonaws.com/"),
    ("gcs", "https://{c}.storage.googleapis.com/"),
    ("azure", "https://{c}.blob.core.windows.net/"),
)

_LISTING_MARKERS = (
    "<listbucketresult", "<contents>", "<enumerationresults", "<blobs>",
)


def _stem(target: str) -> str:
    """Deriva uno "stem" minuscolo, alfanumerico+trattino, dal target.

    Dominio (``acme.com``) → primo label (``acme``). Nome azienda
    (``Acme Corporation``) → normalizzato (``acme-corporation``): spazi e
    punteggiatura diventano trattini, tutto il resto viene scartato.
    """
    t = (target or "").strip().lower()
    if not t:
        return ""
    if "." in t and " " not in t:
        # Sembra un dominio: usa solo il primo label (es. "acme" da "acme.com").
        t = t.split(".")[0]
    out_chars: list[str] = []
    for ch in t:
        if ch.isalnum():
            out_chars.append(ch)
        elif ch in (" ", "-", "_", "."):
            out_chars.append("-")
    stem = "".join(out_chars).strip("-")
    while "--" in stem:
        stem = stem.replace("--", "-")
    return stem


def _candidate_names(target: str) -> list[str]:
    """Genera i nomi bucket candidati per *target* (deduplicati, capped)."""
    stem = _stem(target)
    if not stem:
        return []
    candidates: list[str] = []

    def _add(name: str) -> None:
        if name and name not in candidates:
            candidates.append(name)

    _add(stem)
    for suf in _SUFFIXES:
        if suf:
            _add(f"{stem}{suf}")
    for pre in _PREFIXES:
        if pre:
            _add(f"{pre}{stem}")
    return candidates[:_MAX_CANDIDATES]


def _looks_like_listing(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in _LISTING_MARKERS)


def _classify_candidate(candidate: str, provider: str, url_template: str, timeout: int) -> dict | None:
    """Sonda un singolo (candidate, provider). Ritorna None se non esiste
    (404) o se la richiesta fallisce (rete/timeout/SSRF-blocked)."""
    url = url_template.format(c=candidate)
    try:
        status, _body, _headers = _safe_http.open_url(url, method="HEAD", timeout=timeout)
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception:
        # Include _safe_http.SSRFBlocked, timeout, DNS failure, ecc. — salta
        # questo singolo candidato/provider, continua con gli altri.
        return None

    if status == 404:
        return None
    if status == 403:
        return {"candidate": candidate, "provider": provider, "url": url, "cls": "private"}
    if status not in (200, 301):
        # Status inatteso (4xx/5xx diverso da 403/404): nessun segnale chiaro.
        return None

    # Esiste (200/301): verifica se il GET espone un listing.
    try:
        _g_status, g_body, _g_headers = _safe_http.open_url(url, method="GET", timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            g_body = exc.read() or b""
        except Exception:
            g_body = b""
    except Exception:
        g_body = b""

    text = g_body[:8192].decode("utf-8", errors="replace")
    cls = "listable" if _looks_like_listing(text) else "exists"
    return {"candidate": candidate, "provider": provider, "url": url, "cls": cls}


def _probe_candidate(candidate: str, timeout: int) -> list[dict]:
    """Prova i 3 provider in sequenza per un candidato."""
    hits: list[dict] = []
    for provider, url_template in _PROVIDERS:
        try:
            hit = _classify_candidate(candidate, provider, url_template, timeout)
        except Exception:
            hit = None
        if hit:
            hits.append(hit)
    return hits


def _finding_from_hit(hit: dict, lang: str) -> Finding:
    candidate, provider, url = hit["candidate"], hit["provider"], hit["url"]
    if hit["cls"] == "listable":
        return Finding(
            kind="public_cloud_bucket_listable",
            value=f"{provider}:{candidate}",
            confidence=0.95,
            source_reliability="A", info_credibility=1,
            evidence=[Evidence(url=url, title=f"{provider} bucket listing")],
            notes=_t("cloud_buckets.listable", lang, provider=provider, candidate=candidate),
            severity="critical",
        )
    if hit["cls"] == "exists":
        return Finding(
            kind="public_cloud_bucket_exists",
            value=f"{provider}:{candidate}",
            confidence=0.75,
            source_reliability="A", info_credibility=2,
            evidence=[Evidence(url=url, title=f"{provider} bucket")],
            notes=_t("cloud_buckets.exists", lang, provider=provider, candidate=candidate),
            severity="high",
        )
    # private (403): esiste ma non e' un rischio confermato.
    return Finding(
        kind="cloud_bucket_private",
        value=f"{provider}:{candidate}",
        confidence=0.35,
        source_reliability="B", info_credibility=3,
        evidence=[Evidence(url=url, title=f"{provider} bucket (privato)")],
        notes=_t("cloud_buckets.private", lang, provider=provider, candidate=candidate),
        severity="info",
    )


class CloudBucketsConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("cloud_buckets.empty_target", context.lang))

        candidates = _candidate_names(target)
        if not candidates:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("cloud_buckets.empty_target", context.lang))

        per_req_timeout = min(context.timeout, 6)
        findings: list[Finding] = []
        with _cf.ThreadPoolExecutor(max_workers=6) as ex:
            futures = [ex.submit(_probe_candidate, c, per_req_timeout) for c in candidates]
            for f in _cf.as_completed(futures):
                try:
                    hits = f.result()
                except Exception:
                    continue
                for hit in hits:
                    findings.append(_finding_from_hit(hit, context.lang))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"candidates": len(candidates), "providers": len(_PROVIDERS), "hits": len(findings)},
        )

    def health_check(self) -> bool:
        return True
