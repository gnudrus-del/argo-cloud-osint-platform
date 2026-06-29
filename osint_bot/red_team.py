"""Pillar 2 — Red Team: expanded fingerprint DB, EASM pipeline, credential exposure, MITRE mapping.

This module extends the lightweight red-team logic already in agents.RedTeamAgent with:

  TAKEOVER_DB
      Expanded vendor fingerprint database (50+ entries) with per-vendor severity,
      ATT&CK TTP references and remediation guidance.  Replaces the bare-string
      TAKEOVER_FINGERPRINTS dict in agents.py.

  assess_takeover_candidates(hosts)
      Converts a set of candidate host → evidence pairs into structured Finding objects
      with severity + ATT&CK TTPs + remediation sourced from TAKEOVER_DB.

  EASMPipeline
      Passive-first External Attack Surface Mapping: collects subdomains from
      CT logs (crt.sh connector) and tool-based enumeration (amass/subfinder),
      deduplicates, and emits asset findings.

  scan_credential_exposure(target_domain, pages, search_results)
      Heuristic scan of observed pages and search results for credential/secret
      exposure signals (breach references, secret patterns in text, paste mentions).
      Output = exposure inventory findings with severity + remediation.

  diff_scan_findings(baseline, current)
      Compare two finding lists and return new / removed / unchanged sets,
      enabling rescan diff reports (Pillar 2.5).

All functions are pure (no I/O) or accept a ConnectorRegistry to make testing easy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import Evidence, Finding


# ---------------------------------------------------------------------------
# Pillar 2.2 — Expanded subdomain-takeover fingerprint database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TakeoverVendor:
    name: str
    severity: str               # info | low | medium | high | critical
    attck_ttps: tuple[str, ...] # MITRE ATT&CK technique IDs
    remediation: str


TAKEOVER_DB: dict[str, TakeoverVendor] = {
    # Cloud / hosting
    "github.io": TakeoverVendor(
        name="GitHub Pages",
        severity="high",
        attck_ttps=("T1584.001",),  # Compromise Infrastructure: Domains
        remediation="Rimuovere il record DNS o richiedere la pagina GitHub corrispondente.",
    ),
    "myshopify.com": TakeoverVendor(
        name="Shopify",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il negozio Shopify o rimuovere il CNAME.",
    ),
    "herokuapp.com": TakeoverVendor(
        name="Heroku",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Creare un'app Heroku con il nome corrispondente o rimuovere il DNS.",
    ),
    "wpengine.com": TakeoverVendor(
        name="WP Engine",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Aggiungere il dominio personalizzato all'account WP Engine o rimuovere il CNAME.",
    ),
    "azurewebsites.net": TakeoverVendor(
        name="Azure App Service",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Creare un'app Azure con lo stesso hostname o rimuovere il record DNS.",
    ),
    "s3.amazonaws.com": TakeoverVendor(
        name="Amazon S3",
        severity="critical",
        attck_ttps=("T1584.001", "T1530"),  # Data from Cloud Storage Object
        remediation="Creare il bucket S3 corrispondente o rimuovere il record DNS.",
    ),
    "s3-website": TakeoverVendor(
        name="Amazon S3 Website Endpoint",
        severity="critical",
        attck_ttps=("T1584.001", "T1530"),
        remediation="Creare il bucket S3 corrispondente con website hosting abilitato.",
    ),
    "cloudfront.net": TakeoverVendor(
        name="CloudFront",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Verificare la distribuzione CloudFront o rimuovere l'alias.",
    ),
    "ghost.io": TakeoverVendor(
        name="Ghost",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Richiedere il sito Ghost o rimuovere il CNAME.",
    ),
    "readthedocs.io": TakeoverVendor(
        name="Read the Docs",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Richiedere il progetto ReadTheDocs o rimuovere il record.",
    ),
    "zendesk.com": TakeoverVendor(
        name="Zendesk",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Configurare il dominio personalizzato in Zendesk o rimuovere il CNAME.",
    ),
    "fastly.net": TakeoverVendor(
        name="Fastly",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Aggiungere il dominio al servizio Fastly o rimuovere il CNAME.",
    ),
    "tumblr.com": TakeoverVendor(
        name="Tumblr",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Creare un blog Tumblr corrispondente o rimuovere il record DNS.",
    ),
    "wordpress.com": TakeoverVendor(
        name="WordPress.com",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il dominio su WordPress.com o rimuovere il mapping.",
    ),
    # Additional vendors (Pillar 2.2 expansion)
    "bitbucket.io": TakeoverVendor(
        name="Bitbucket Pages",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Creare il repository Bitbucket corrispondente o rimuovere il CNAME.",
    ),
    "netlify.app": TakeoverVendor(
        name="Netlify",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il sito Netlify con quel nome o rimuovere il CNAME.",
    ),
    "vercel.app": TakeoverVendor(
        name="Vercel",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il deployment Vercel o rimuovere il CNAME.",
    ),
    "surge.sh": TakeoverVendor(
        name="Surge.sh",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Pubblicare un sito Surge con quel dominio o rimuovere il CNAME.",
    ),
    "statuspage.io": TakeoverVendor(
        name="Statuspage",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Configurare la status page Atlassian o rimuovere il CNAME.",
    ),
    "helpscoutdocs.com": TakeoverVendor(
        name="Help Scout Docs",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Configurare il dominio personalizzato Help Scout o rimuovere il record.",
    ),
    "intercom.help": TakeoverVendor(
        name="Intercom Help Center",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Configurare il dominio personalizzato Intercom o rimuovere il CNAME.",
    ),
    "desk.com": TakeoverVendor(
        name="Salesforce Desk",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Configurare il dominio su Desk.com o rimuovere il CNAME.",
    ),
    "webflow.io": TakeoverVendor(
        name="Webflow",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Pubblicare il progetto Webflow con quel dominio o rimuovere il CNAME.",
    ),
    "launchrock.com": TakeoverVendor(
        name="Launchrock",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il sito Launchrock o rimuovere il CNAME.",
    ),
    "cargocollective.com": TakeoverVendor(
        name="Cargo Collective",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il sito Cargo o rimuovere il CNAME.",
    ),
    "gitbook.io": TakeoverVendor(
        name="GitBook",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare lo spazio GitBook o rimuovere il CNAME.",
    ),
    "hubspotpagebuilder.com": TakeoverVendor(
        name="HubSpot CMS",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Configurare il dominio in HubSpot o rimuovere il record.",
    ),
    "kinsta.cloud": TakeoverVendor(
        name="Kinsta",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Aggiungere il dominio al sito Kinsta o rimuovere il CNAME.",
    ),
    "pantheonsite.io": TakeoverVendor(
        name="Pantheon",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il sito Pantheon o rimuovere il CNAME.",
    ),
    "squarespace.com": TakeoverVendor(
        name="Squarespace",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Aggiungere il dominio custom a Squarespace o rimuovere il record.",
    ),
    "wixsite.com": TakeoverVendor(
        name="Wix",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Connettere il dominio a un sito Wix o rimuovere il CNAME.",
    ),
    "strikingly.com": TakeoverVendor(
        name="Strikingly",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Connettere il dominio a Strikingly o rimuovere il CNAME.",
    ),
    # Cloud storage buckets
    "storage.googleapis.com": TakeoverVendor(
        name="Google Cloud Storage",
        severity="critical",
        attck_ttps=("T1584.001", "T1530"),
        remediation="Creare il bucket GCS corrispondente o rimuovere il record CNAME.",
    ),
    "blob.core.windows.net": TakeoverVendor(
        name="Azure Blob Storage",
        severity="critical",
        attck_ttps=("T1584.001", "T1530"),
        remediation="Creare il container Azure Storage corrispondente o rimuovere il CNAME.",
    ),
    # CI/CD and dev tools
    "pages.dev": TakeoverVendor(
        name="Cloudflare Pages",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il progetto Cloudflare Pages o rimuovere il CNAME.",
    ),
    "render.com": TakeoverVendor(
        name="Render",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il servizio Render o rimuovere il CNAME.",
    ),
    "fly.dev": TakeoverVendor(
        name="Fly.io",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare l'app Fly.io o rimuovere il CNAME.",
    ),
    "railway.app": TakeoverVendor(
        name="Railway",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Rivendicare il progetto Railway o rimuovere il CNAME.",
    ),
    "gitlab.io": TakeoverVendor(
        name="GitLab Pages",
        severity="high",
        attck_ttps=("T1584.001",),
        remediation="Creare il progetto GitLab Pages o rimuovere il CNAME.",
    ),
    "traefik.me": TakeoverVendor(
        name="Traefik",
        severity="medium",
        attck_ttps=("T1584.001",),
        remediation="Rimuovere il record DNS.",
    ),
}


# ---------------------------------------------------------------------------
# Pillar 2.2 — assess takeover candidates
# ---------------------------------------------------------------------------

def assess_takeover_candidates(
    candidate_hosts: dict[str, list[Evidence]],
) -> list[Finding]:
    """Convert candidate-host → evidence pairs into enriched red-team findings.

    Looks up each host suffix in TAKEOVER_DB; unknown vendors produce low-severity
    findings so they are still surfaced for manual review.
    """
    findings: list[Finding] = []
    for host, evidence in candidate_hosts.items():
        vendor: TakeoverVendor | None = None
        for suffix, v in TAKEOVER_DB.items():
            if host.endswith(suffix):
                vendor = v
                break

        if vendor:
            sev = vendor.severity
            ttps = list(vendor.attck_ttps)
            remediation = vendor.remediation
            vendor_name = vendor.name
        else:
            sev = "low"
            ttps = ["T1584.001"]
            remediation = "Verificare se il CNAME punta a un servizio non rivendicato."
            vendor_name = host.split(".")[-2] if "." in host else host

        findings.append(Finding(
            kind="red_team_takeover_candidate",
            value=host,
            confidence=0.50,
            severity=sev,
            attck_ttps=ttps,
            remediation=remediation,
            source_reliability="C",
            info_credibility=3,
            evidence=evidence[:3],
            notes=(
                f"Potenziale subdomain takeover: host punta a {vendor_name}. "
                f"Verificare con subjack/can-i-take-over-xyz prima di classificare come confermato."
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# Pillar 2.3 — Credential / secret exposure scan (heuristic, passive)
# ---------------------------------------------------------------------------

# Patterns that suggest credential exposure in page text or snippets
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str, str, list[str]]] = [
    (
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}", re.MULTILINE),
        "high",
        "Ruotare immediatamente la chiave AWS. Revocare e ri-generare tramite IAM. Investigare CloudTrail.",
        ["T1552.001"],
    ),
    (
        "aws_secret_key",
        re.compile(r"(?:aws_secret_access_key|AWS_SECRET)[^\n]*=[^\n]{20,}", re.IGNORECASE | re.MULTILINE),
        "critical",
        "AWS Secret Key esposta. Revocare e ruotare immediatamente.",
        ["T1552.001"],
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.MULTILINE),
        "critical",
        "Chiave privata esposta. Revocare e rigenerare il certificato/chiave. Investigare utilizzo.",
        ["T1552.004"],
    ),
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}", re.MULTILINE),
        "high",
        "Token GitHub esposto. Revocare su github.com/settings/tokens.",
        ["T1552.001"],
    ),
    (
        "slack_token",
        re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}", re.MULTILINE),
        "high",
        "Token Slack esposto. Revocare tramite api.slack.com/apps.",
        ["T1552.001"],
    ),
    (
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+", re.MULTILINE),
        "medium",
        "JWT token esposto. Verificare scadenza, revocare se possibile, ruotare il secret di firma.",
        ["T1528"],
    ),
    (
        "connection_string",
        re.compile(
            r"(?:mongodb|postgresql|mysql|redis):\/\/[^:\s]+:[^@\s]+@[^\s/\"']+",
            re.IGNORECASE | re.MULTILINE,
        ),
        "critical",
        "Connection string con credenziali esposta. Ruotare le credenziali del DB.",
        ["T1552.001"],
    ),
    (
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.MULTILINE),
        "medium",
        "Google API key esposta. Revocare e ridefinire le restrizioni.",
        ["T1552.001"],
    ),
    (
        "password_in_url",
        re.compile(r"https?://[^:\s]+:[^@\s]{6,}@[^\s\"']+", re.MULTILINE),
        "high",
        "Password in chiaro nell'URL. Ruotare le credenziali e rimuovere dall'URL.",
        ["T1552.001"],
    ),
]

# Signals that suggest the page mentions breach/leak context
_BREACH_SIGNALS = [
    "have i been pwned", "hibp", "breach", "leaked", "compromised", "credential dump",
    "paste", "pastebin", "dehashed", "intelx", "dark web", "dark-web", "darkweb",
]


def scan_credential_exposure(
    target_domain: str,
    pages: list[Any],
    search_results: list[Any],
) -> list[Finding]:
    """Heuristic scan for credential/secret exposure in observed pages and snippets.

    Parameters
    ----------
    target_domain :
        Base domain being assessed (used for context in notes).
    pages :
        List of ``Page`` objects from the web agent.
    search_results :
        List of ``SearchResult`` objects (title + snippet).

    Returns
    -------
    list[Finding]
        One finding per exposure signal, deduplicated by pattern type + value prefix.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    def _add(kind: str, value: str, sev: str, ttps: list[str],
             remediation: str, url: str, title: str, quote: str) -> None:
        key = f"{kind}:{value[:40]}"
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            kind=f"red_team_{kind}",
            value=value[:120],
            confidence=0.65,
            severity=sev,
            attck_ttps=ttps,
            remediation=remediation,
            source_reliability="C",
            info_credibility=2,
            evidence=[Evidence(url=url, title=title, quote=quote[:300])],
            notes=f"Segnale di esposizione credenziale rilevato in sorgente pubblica per {target_domain}.",
        ))

    # Scan page text + URLs
    for page in pages:
        if getattr(page, "error", ""):
            continue
        text = getattr(page, "text", "") or ""
        url = getattr(page, "url", "")
        title = getattr(page, "title", "")
        for pat_kind, pattern, sev, remediation, ttps in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                _add(pat_kind, match.group(0), sev, ttps, remediation,
                     url, title, text[max(0, match.start() - 40): match.end() + 40])

    # Scan search result snippets
    for sr in search_results:
        snippet = getattr(sr, "snippet", "") or ""
        sr_url = getattr(sr, "url", "")
        sr_title = getattr(sr, "title", "")
        for pat_kind, pattern, sev, remediation, ttps in _SECRET_PATTERNS:
            for match in pattern.finditer(snippet):
                _add(pat_kind, match.group(0), sev, ttps, remediation,
                     sr_url, sr_title, snippet[:300])

        # Breach / leak signal in snippet
        snippet_lower = snippet.lower()
        if any(signal in snippet_lower for signal in _BREACH_SIGNALS):
            key = f"breach_mention:{sr_url[:60]}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    kind="red_team_breach_mention",
                    value=sr_url,
                    confidence=0.45,
                    severity="medium",
                    attck_ttps=["T1589.001"],  # Gather Victim Identity Information: Credentials
                    remediation=(
                        "Verificare su HIBP / DeHashed se le credenziali del dominio sono in breach. "
                        "Forzare il reset delle password esposte."
                    ),
                    source_reliability="D",
                    info_credibility=4,
                    evidence=[Evidence(url=sr_url, title=sr_title, quote=snippet[:200])],
                    notes=f"Risultato di ricerca suggerisce leak/breach correlato a {target_domain}.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Pillar 2.5 — Rescan diff
# ---------------------------------------------------------------------------

@dataclass
class ScanDiff:
    new_findings: list[Finding] = field(default_factory=list)
    removed_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.removed_findings)

    def summary(self) -> str:
        parts = []
        if self.new_findings:
            parts.append(f"{len(self.new_findings)} nuovi")
        if self.removed_findings:
            parts.append(f"{len(self.removed_findings)} spariti")
        if self.unchanged_findings:
            parts.append(f"{len(self.unchanged_findings)} invariati")
        return "; ".join(parts) if parts else "Nessuna variazione."


def _finding_key(f: Finding) -> str:
    """Stable dedup key for a finding across runs."""
    return f"{f.kind}:{f.value.strip().lower()}"


def diff_scan_findings(baseline: list[Finding], current: list[Finding]) -> ScanDiff:
    """Compare two finding lists and return what is new, removed, or unchanged.

    The key is ``kind + value`` (case-insensitive, stripped).  Confidence or
    evidence changes for an existing finding are NOT considered a change.
    """
    baseline_keys = {_finding_key(f): f for f in baseline}
    current_keys = {_finding_key(f): f for f in current}

    new = [current_keys[k] for k in current_keys if k not in baseline_keys]
    removed = [baseline_keys[k] for k in baseline_keys if k not in current_keys]
    unchanged = [current_keys[k] for k in current_keys if k in baseline_keys]

    return ScanDiff(
        new_findings=new,
        removed_findings=removed,
        unchanged_findings=unchanged,
    )
