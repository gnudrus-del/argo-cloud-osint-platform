from __future__ import annotations

import ipaddress
import os
import re
import urllib.parse
from dataclasses import dataclass

from .media import analyze_media_file
from .models import AgentResult, Evidence, Finding, Page, SearchResult
from .patterns import BTC_RE, ETH_RE
from .plugins import PluginContext, run_plugins_parallel
from .red_team import (
    assess_takeover_candidates,
    scan_credential_exposure,
)
from .safety import assert_darkweb_allowed, redact_phone

COORD_RE = re.compile(r"\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:1[0-7]\d(?:\.\d+)?|\d{1,2}(?:\.\d+)?|180(?:\.0+)?)\b")
MAP_HOST_RE = re.compile(r"\b(?:maps\.google|openstreetmap|osm\.org|waze\.com)\b", re.IGNORECASE)
SECRET_PATTERNS = {
    "possible_aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "possible_private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "possible_token": re.compile(r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
}
MEDIA_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm")
SOCIAL_HOSTS = {
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "tiktok.com",
    "medium.com",
    "substack.com",
}


@dataclass
class AgentContext:
    target: str
    target_type: str
    confirm_authorization: bool
    include_contact: bool
    allow_network_scan: bool
    search_results: list[SearchResult]
    pages: list[Page]
    external_tools: list[str]
    timeout: int
    allow_darkweb: bool = False
    # Pillar 0.2: identity + case carrying the active RoE.
    case_id: str | None = None
    actor: str = ""


class BaseAgent:
    name = "base"

    def run(self, context: AgentContext) -> AgentResult:
        raise NotImplementedError


class PlannerAgent(BaseAgent):
    name = "planner"

    def run(self, context: AgentContext) -> AgentResult:
        tasks = [
            "web: raccogliere fonti pubbliche citabili",
            "correlation: separare evidenze osservate da inferenze",
            "review: verificare omonimie, attribuzione e attualita",
        ]
        if context.target_type in {"handle", "email"}:
            tasks.append("socmint: controllare solo profili pubblici e redigere dati non necessari")
        if context.target_type in {"domain", "ip"}:
            tasks.append("network: enumerare solo asset propri o autorizzati")
        if context.target_type == "crypto":
            tasks.append("crypto: consultare explorer pubblici e annotare transazioni senza attribuzioni non verificate")

        return AgentResult(
            name=self.name,
            status="ok",
            summary="Piano investigativo generato con guardrail difensivi.",
            notes=tasks,
        )


class WebAgent(BaseAgent):
    name = "web"

    def run(self, context: AgentContext) -> AgentResult:
        ok_pages = [page for page in context.pages if not page.error]
        failed_pages = [page for page in context.pages if page.error]
        finding = Finding(
            kind="agent_web_coverage",
            value=f"{len(ok_pages)} pagine lette, {len(failed_pages)} non disponibili",
            confidence=0.8 if ok_pages else 0.35,
            evidence=[Evidence(page.url, page.title, page.description[:200]) for page in ok_pages[:5]],
            notes="Copertura web basata su fonti pubbliche e URL seed/API.",
        )
        return AgentResult(
            name=self.name,
            status="ok",
            summary="Copertura web sintetizzata.",
            findings=[finding],
        )


class ExternalToolAgent(BaseAgent):
    name = "external_tools"

    def run(self, context: AgentContext) -> AgentResult:
        findings: list[Finding] = []
        notes: list[str] = []
        status = "skipped"

        plugin_context = PluginContext(
            target=context.target,
            target_type=context.target_type,
            confirm_authorization=context.confirm_authorization,
            include_contact=context.include_contact,
            allow_network_scan=context.allow_network_scan,
            timeout=context.timeout,
            case_id=context.case_id,
            actor=context.actor,
        )
        for result in run_plugins_parallel(context.external_tools, plugin_context):
            if result.status == "ok" and status == "skipped":
                status = "ok"
            elif result.status != "ok":
                status = "partial"
            notes.append(f"{result.plugin}: {result.status} ({result.duration_ms} ms).")
            if result.error:
                notes.append(f"{result.plugin} errore: {one_line(result.error)}")
            stderr = str(result.output.get("stderr", "")) if result.output else ""
            if stderr:
                notes.append(f"{result.plugin} stderr: {one_line(stderr)}")
            findings.extend(result.findings)

        if not context.external_tools:
            notes.append("Nessun tool esterno selezionato. Usa --external-tool con tool installati localmente.")
        return AgentResult(
            name=self.name,
            status=status,
            summary="Integrazioni esterne eseguite o annotate secondo policy.",
            findings=findings,
            notes=notes,
        )


class OpsecAgent(BaseAgent):
    name = "opsec"

    def run(self, context: AgentContext) -> AgentResult:
        findings: list[Finding] = []
        for page in context.pages:
            if page.error:
                continue
            text = f"{page.title}\n{page.description}\n{page.text}"
            for kind, pattern in SECRET_PATTERNS.items():
                match = pattern.search(text)
                if match:
                    findings.append(
                        Finding(
                            kind=f"opsec_{kind}",
                            value=kind,
                            confidence=0.65,
                            evidence=[Evidence(page.url, page.title, quote=near(text, match.start(), match.end()))],
                            notes="Possibile esposizione pubblica; confermare manualmente e ruotare eventuali segreti reali.",
                        )
                    )
            for link in page.links:
                path = urllib.parse.urlparse(link).path.casefold()
                if any(marker in path for marker in ("/.git", ".env", "backup", "dump", "credentials")):
                    findings.append(
                        Finding(
                            kind="opsec_sensitive_path_reference",
                            value=link,
                            confidence=0.45,
                            evidence=[Evidence(page.url, page.title)],
                            notes="Riferimento pubblico a path potenzialmente sensibile; non scaricare dati non autorizzati.",
                        )
                    )

        summary = f"{len(findings)} segnali OPSEC pubblici rilevati."
        notes = [
            "OPSEC: privilegiare remediation difensiva, rotazione segreti e riduzione esposizione.",
            "Non eseguire download o accessi a risorse che non sono chiaramente pubbliche e autorizzate.",
        ]
        return AgentResult(name=self.name, status="ok", summary=summary, findings=findings[:25], notes=notes)


class CryptoAgent(BaseAgent):
    name = "crypto"

    def run(self, context: AgentContext) -> AgentResult:
        findings: list[Finding] = []
        seen: set[str] = set()

        for value, evidence in crypto_candidates(context):
            if value in seen:
                continue
            seen.add(value)
            chain = "ethereum" if value.startswith("0x") else "bitcoin"
            findings.append(
                Finding(
                    kind="crypto_address",
                    value=value,
                    confidence=0.75,
                    evidence=[evidence],
                    notes=f"Address {chain} rilevato. Attribuzione a persone/entita richiede fonti indipendenti.",
                )
            )

        return AgentResult(
            name=self.name,
            status="ok",
            summary=f"{len(findings)} address crypto candidati rilevati.",
            findings=findings,
        )


class MediaAgent(BaseAgent):
    name = "media"

    def run(self, context: AgentContext) -> AgentResult:
        findings: list[Finding] = []
        notes: list[str] = []
        if os.path.isfile(context.target):
            metadata = analyze_media_file(context.target)
            dimensions = f" {metadata.width}x{metadata.height}" if metadata.width and metadata.height else ""
            findings.append(
                Finding(
                    kind="media_file_metadata",
                    value=f"{metadata.filename} {metadata.media_type}{dimensions}".strip(),
                    confidence=0.85,
                    evidence=[Evidence(url=f"file://{metadata.filename}", title=metadata.sha256[:16])],
                    notes=f"SHA256 {metadata.sha256}; size {metadata.size_bytes} bytes. Metadati avanzati via exiftool/ffprobe.",
                )
            )
            notes.extend(metadata.notes or [])

        urls = [result.url for result in context.search_results]
        for page in context.pages:
            urls.extend(page.links)
        for url in sorted(set(urls)):
            parsed = urllib.parse.urlparse(url)
            if parsed.path.casefold().endswith(MEDIA_EXTENSIONS):
                findings.append(
                    Finding(
                        kind="public_media_reference",
                        value=url,
                        confidence=0.55,
                        evidence=[Evidence(url=url)],
                        notes="File media pubblico individuato; verificare diritti, contesto e metadati solo se autorizzato.",
                    )
                )

        if not findings:
            notes.append("Nessun file media locale o riferimento media pubblico analizzato.")
        return AgentResult(name=self.name, status="ok", summary=f"{len(findings)} evidenze media/metadati.", findings=findings[:30], notes=notes)


class GeoAgent(BaseAgent):
    name = "geo"

    def run(self, context: AgentContext) -> AgentResult:
        findings: list[Finding] = []
        if context.target_type == "ip":
            findings.append(ip_geo_finding(context.target))

        for page in context.pages:
            for match in COORD_RE.finditer(page.text):
                findings.append(
                    Finding(
                        kind="geo_coordinate_mention",
                        value=match.group(0),
                        confidence=0.55,
                        evidence=[Evidence(page.url, page.title, quote=near(page.text, match.start(), match.end()))],
                        notes="Coordinate citate in una fonte pubblica; non assumere presenza fisica di una persona.",
                    )
                )
            for link in page.links:
                if MAP_HOST_RE.search(link):
                    findings.append(
                        Finding(
                            kind="geo_map_link",
                            value=link,
                            confidence=0.55,
                            evidence=[Evidence(page.url, page.title)],
                            notes="Link mappa pubblico rilevato; interpretare nel contesto della pagina sorgente.",
                        )
                    )

        return AgentResult(
            name=self.name,
            status="ok",
            summary=f"{len(findings)} segnali geografici pubblici rilevati.",
            findings=findings[:20],
        )


class SocmintAgent(BaseAgent):
    name = "socmint"

    def run(self, context: AgentContext) -> AgentResult:
        urls = [result.url for result in context.search_results]
        for page in context.pages:
            urls.extend(page.links)

        findings: list[Finding] = []
        for url in sorted(set(urls)):
            host = host_of(url).removeprefix("www.")
            base_host = ".".join(host.split(".")[-2:])
            if host in SOCIAL_HOSTS or base_host in SOCIAL_HOSTS:
                findings.append(
                    Finding(
                        kind="socmint_public_profile_reference",
                        value=url,
                        confidence=0.5,
                        evidence=[Evidence(url=url)],
                        notes="Profilo/pagina pubblica candidata. Non assumere identita o attribuzione senza conferme indipendenti.",
                    )
                )

        notes = [
            "SOCMINT limitata a contenuti pubblici, citabili e verificabili.",
            "Non raccogliere follower, contatti privati, dati di minori o contenuti dietro login.",
        ]
        return AgentResult(name=self.name, status="ok", summary=f"{len(findings)} riferimenti social pubblici.", findings=findings[:25], notes=notes)


class PhoneAgent(BaseAgent):
    name = "phone"

    def run(self, context: AgentContext) -> AgentResult:
        if context.target_type != "phone":
            return AgentResult(name=self.name, status="skipped", summary="Target non telefonico.")

        digits = re.sub(r"\D+", "", context.target)
        redacted = redact_phone(context.target)
        notes = ["Non effettua lookup intestatario, indirizzo o data di nascita."]
        confidence = 0.65 if 7 <= len(digits) <= 15 else 0.25
        findings = [
            Finding(
                kind="phone_format",
                value=redacted,
                confidence=confidence,
                evidence=[],
                notes="Normalizzazione minima del numero; usare fonti autorizzate per qualunque verifica ulteriore.",
            )
        ]
        return AgentResult(name=self.name, status="ok", summary="Numero trattato con minimizzazione.", findings=findings, notes=notes)


class DarkwebAgent(BaseAgent):
    name = "darkweb"

    def run(self, context: AgentContext) -> AgentResult:
        assert_darkweb_allowed(context.allow_darkweb)
        findings: list[Finding] = []
        urls = [result.url for result in context.search_results]
        for page in context.pages:
            urls.append(page.url)
            urls.extend(page.links)
        for url in sorted(set(urls)):
            if ".onion" in url.casefold():
                findings.append(
                    Finding(
                        kind="darkweb_onion_reference",
                        value=url,
                        confidence=0.45,
                        evidence=[Evidence(url=url)],
                        notes="Riferimento onion osservato. Non accedere a mercati, credenziali, dati rubati o contenuti illegali.",
                    )
                )
        notes = [
            "Deep/dark web limitato a monitoraggio difensivo e fonti seed autorizzate.",
            "Per produzione usare feed di threat intelligence o ambienti isolati con logging e procedure legali.",
        ]
        return AgentResult(name=self.name, status="ok", summary=f"{len(findings)} riferimenti dark/deep web.", findings=findings, notes=notes)


class ReverseAccountAgent(BaseAgent):
    """Trace where an email or phone is registered across social platforms.

    Runs the dedicated reverse-account toolchain (holehe, h8mail, ghunt,
    mosint for emails; phoneinfoga, phunter for phones) and aggregates their
    findings into a single ranked list. Each finding keeps a per-tool
    attribution so the analyst can verify.
    """

    name = "reverse_account"

    EMAIL_TOOLS = ("holehe", "h8mail", "ghunt", "mosint", "socialscan")
    PHONE_TOOLS = ("phoneinfoga", "phunter")

    def run(self, context: AgentContext) -> AgentResult:
        if context.target_type not in {"email", "phone"}:
            return AgentResult(name=self.name, status="skipped", summary="Target non email/telefono.")
        if not context.confirm_authorization:
            return AgentResult(
                name=self.name,
                status="skipped",
                summary="Ricerca account associati a contatti personali richiede autorizzazione.",
            )

        selected = list(self.EMAIL_TOOLS if context.target_type == "email" else self.PHONE_TOOLS)
        plugin_context = PluginContext(
            target=context.target,
            target_type=context.target_type,
            confirm_authorization=context.confirm_authorization,
            include_contact=context.include_contact,
            allow_network_scan=context.allow_network_scan,
            timeout=context.timeout,
            case_id=context.case_id,
            actor=context.actor,
        )
        results = run_plugins_parallel(selected, plugin_context)

        findings: list[Finding] = []
        platforms_by_tool: dict[str, set[str]] = {}
        for result in results:
            tool_platforms: set[str] = set()
            for finding in result.findings:
                # Findings that look like profile URLs get re-categorised so the
                # report groups them under "reverse account" instead of "external".
                if finding.value.startswith(("http://", "https://")):
                    host = urllib.parse.urlparse(finding.value).netloc.casefold().removeprefix("www.")
                    platform = ".".join(host.split(".")[-2:]) if host else "unknown"
                    tool_platforms.add(platform)
                    findings.append(
                        Finding(
                            kind="reverse_account_match",
                            value=finding.value,
                            confidence=max(finding.confidence, 0.6),
                            evidence=finding.evidence,
                            notes=f"Possibile registrazione su {platform} via {result.plugin}. Verificare prima di attribuire.",
                        )
                    )
                else:
                    findings.append(finding)
            platforms_by_tool[result.plugin] = tool_platforms

        summary_bits = []
        for tool, platforms in platforms_by_tool.items():
            if platforms:
                summary_bits.append(f"{tool}: {', '.join(sorted(platforms))}")
        summary = (
            "Account associati a contatto: " + "; ".join(summary_bits)
            if summary_bits
            else "Nessuna registrazione social pubblica trovata dai tool disponibili."
        )
        status = "ok" if any(r.status == "ok" for r in results) else "partial"

        notes = [
            "Risultati derivati da tool esterni di reverse-account; non costituiscono prova di identita.",
            "Confermare manualmente cross-referenziando il profilo e l'utilizzo storico del contatto.",
        ]
        for result in results:
            notes.append(f"{result.plugin}: {result.status} ({result.duration_ms} ms).")

        return AgentResult(name=self.name, status=status, summary=summary, findings=findings[:40], notes=notes)


TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "myshopify.com": "Shopify",
    "herokuapp.com": "Heroku",
    "wpengine.com": "WP Engine",
    "azurewebsites.net": "Azure App Service",
    "s3.amazonaws.com": "Amazon S3",
    "cloudfront.net": "CloudFront",
    "ghost.io": "Ghost",
    "readthedocs.io": "Read the Docs",
    "zendesk.com": "Zendesk",
    "fastly.net": "Fastly",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
}
EXPOSED_PATH_HINTS = (
    ("/.git/config", "Git config esposto"),
    ("/.env", "File .env esposto"),
    ("/.ds_store", ".DS_Store esposto"),
    ("/server-status", "Apache server-status esposto"),
    ("/phpinfo", "phpinfo() esposto"),
    ("/wp-config.php", "Backup wp-config esposto"),
    ("/_next/static", "Build Next.js — verificare source map"),
    ("/static/admin", "Admin Django esposto"),
)


class RedTeamAgent(BaseAgent):
    """Authorised offensive recon helper.

    Surfaces hints from the raw web crawl (subdomain-takeover candidates,
    exposed path patterns, dev/backup endpoints) and runs the dedicated
    offensive toolchain (subjack, cloud_enum, gitleaks/trufflehog where the
    target is a local path) under the existing safety gate.
    """

    name = "red_team"

    def run(self, context: AgentContext) -> AgentResult:
        if not context.confirm_authorization:
            return AgentResult(
                name=self.name,
                status="skipped",
                summary="Red team richiede --confirm-authorization e target di propria competenza.",
            )

        findings: list[Finding] = []
        notes: list[str] = []

        # 1. Subdomain-takeover hints from observed links (Pillar 2.2 — enriched DB).
        candidate_hosts: dict[str, list[Evidence]] = {}
        for page in context.pages:
            sources = [page.url, *page.links]
            for url in sources:
                host = urllib.parse.urlparse(url).netloc.casefold()
                # Quick pre-filter: must contain a dot and a known cloud-ish TLD suffix.
                if "." not in host:
                    continue
                from .red_team import TAKEOVER_DB
                for suffix in TAKEOVER_DB:
                    if host.endswith(suffix):
                        candidate_hosts.setdefault(host, []).append(
                            Evidence(page.url, page.title, quote=f"{suffix} fingerprint nel link {url[:200]}")
                        )
                        break
        findings.extend(assess_takeover_candidates(candidate_hosts))

        # 1b. Credential / secret exposure scan (Pillar 2.3).
        cred_findings = scan_credential_exposure(
            target_domain=context.target,
            pages=context.pages,
            search_results=context.search_results,
        )
        findings.extend(cred_findings)

        # 2. Exposed path references from the raw text.
        for page in context.pages:
            if page.error:
                continue
            haystack = f"{page.text}\n{' '.join(page.links)}"
            for marker, label in EXPOSED_PATH_HINTS:
                if marker in haystack.casefold():
                    findings.append(
                        Finding(
                            kind="red_team_exposed_path",
                            value=label,
                            confidence=0.5,
                            evidence=[Evidence(page.url, page.title)],
                            notes=f"Riferimento pubblico a {marker}. Validare manualmente che sia ancora raggiungibile e in scope.",
                        )
                    )

        # 3. Dedicated offensive toolchain (only valid types).
        if context.target_type in {"domain", "company"}:
            tools = []
            if context.target_type == "domain":
                tools.extend(["subjack", "amass", "subfinder", "spiderfoot"])
            tools.append("cloud_enum")
            plugin_context = PluginContext(
                target=context.target,
                target_type=context.target_type,
                confirm_authorization=context.confirm_authorization,
                include_contact=context.include_contact,
                allow_network_scan=context.allow_network_scan,
                timeout=context.timeout,
                case_id=context.case_id,
                actor=context.actor,
            )
            for result in run_plugins_parallel(tools, plugin_context):
                notes.append(f"{result.plugin}: {result.status} ({result.duration_ms} ms).")
                findings.extend(result.findings)

        summary = f"{len(findings)} segnali red-team rilevati."
        if not findings:
            summary = "Nessun segnale red-team forte; aumentare copertura o eseguire tool dedicati."
        notes.append("I red-team findings sono indicativi: validare in scope, autorizzato e con writeup.")
        return AgentResult(name=self.name, status="ok", summary=summary, findings=findings[:40], notes=notes)


class HumintAgent(BaseAgent):
    name = "humint"

    def run(self, context: AgentContext) -> AgentResult:
        notes = [
            "HUMINT supportato solo come preparazione etica: obiettivo, consenso, domande aperte, verifica incrociata.",
            "Niente pretesti, pressione psicologica, impersonificazione o raccolta di dati personali non necessari.",
            "Separare dichiarazioni dirette, inferenze dell'analista e fonti documentali.",
        ]
        finding = Finding(
            kind="humint_interview_plan",
            value="consent_based_open_questions",
            confidence=0.8,
            notes="Usare per interviste consensuali o analisi di fonti pubbliche, non per elicitazione ingannevole.",
        )
        return AgentResult(name=self.name, status="ok", summary="Piano HUMINT etico generato.", findings=[finding], notes=notes)


def run_agents(context: AgentContext, requested_agents: list[str]) -> list[AgentResult]:
    registry: dict[str, BaseAgent] = {
        "planner": PlannerAgent(),
        "web": WebAgent(),
        "external": ExternalToolAgent(),
        "opsec": OpsecAgent(),
        "crypto": CryptoAgent(),
        "media": MediaAgent(),
        "geo": GeoAgent(),
        "socmint": SocmintAgent(),
        "phone": PhoneAgent(),
        "darkweb": DarkwebAgent(),
        "humint": HumintAgent(),
        "reverse_account": ReverseAccountAgent(),
        "red_team": RedTeamAgent(),
    }
    selected = list(registry) if "all" in requested_agents else requested_agents
    # Defense in depth: drop the darkweb agent before dispatch when the
    # explicit gate flag is missing, so partial pipelines never trigger
    # dark/deep web behaviour. DarkwebAgent.run() still re-checks.
    if not context.allow_darkweb:
        selected = [name for name in selected if name != "darkweb"]
    results: list[AgentResult] = []
    for name in selected:
        agent = registry.get(name)
        if agent:
            results.append(agent.run(context))
    return results


def crypto_candidates(context: AgentContext) -> list[tuple[str, Evidence]]:
    candidates: list[tuple[str, Evidence]] = []
    for pattern in (BTC_RE, ETH_RE):
        for match in pattern.finditer(context.target):
            candidates.append((match.group(0), Evidence(url="target://input", title="target")))
        for page in context.pages:
            for match in pattern.finditer(page.text):
                candidates.append((match.group(0), Evidence(page.url, page.title, quote=near(page.text, match.start(), match.end()))))
    return candidates


def ip_geo_finding(value: str) -> Finding:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return Finding(
            kind="ip_classification",
            value=value,
            confidence=0.2,
            notes="Target non e un indirizzo IP valido.",
        )
    labels = []
    if ip.is_private:
        labels.append("private")
    if ip.is_global:
        labels.append("global")
    if ip.is_reserved:
        labels.append("reserved")
    if ip.is_loopback:
        labels.append("loopback")
    return Finding(
        kind="ip_classification",
        value=f"{value} ({', '.join(labels) or 'unclassified'})",
        confidence=0.8,
        notes="Classificazione IP locale. Geolocalizzazione precisa richiede fonti pubbliche affidabili e verifica manuale.",
    )


def near(text: str, start: int, end: int) -> str:
    left = max(0, start - 90)
    right = min(len(text), end + 120)
    return " ".join(text[left:right].split())


def one_line(value: str) -> str:
    return " ".join(value.split())[:1200]


def host_of(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.casefold()
