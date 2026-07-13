from __future__ import annotations

import re
import urllib.parse
from collections import Counter, defaultdict

from .models import Evidence, Finding, Page, SearchResult
from .safety import redact_email

TECH_PATTERNS = {
    "Cloudflare": re.compile(r"\bcloudflare\b", re.IGNORECASE),
    "GitHub": re.compile(r"\bgithub\b", re.IGNORECASE),
    "Google Analytics": re.compile(r"\bgoogle analytics|gtag\(", re.IGNORECASE),
    "Shopify": re.compile(r"\bshopify\b", re.IGNORECASE),
    "WordPress": re.compile(r"\bwordpress|wp-content\b", re.IGNORECASE),
    "Zendesk": re.compile(r"\bzendesk\b", re.IGNORECASE),
}
YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
SOCIAL_HOSTS = {
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "medium.com",
    "substack.com",
}
DOCUMENT_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv")
OBSERVED_RESULT_PROVIDERS = {"manual", "bing", "brave", "serper"}


def analyze(
    target: str,
    target_type: str,
    search_results: list[SearchResult],
    pages: list[Page],
    include_contact: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    observed_page_list = observed_pages(pages)
    findings.extend(presence_findings(search_results, observed_page_list))
    findings.extend(profile_findings(search_results, observed_page_list))
    findings.extend(document_findings(search_results, observed_page_list))
    findings.extend(technology_findings(observed_page_list))
    findings.extend(email_findings(observed_page_list, include_contact))
    findings.extend(timeline_findings(observed_page_list))

    if target_type == "domain":
        findings.extend(domain_findings(target, search_results, observed_page_list))

    return sorted(findings, key=lambda item: (item.kind, -item.confidence, item.value.casefold()))


def presence_findings(search_results: list[SearchResult], pages: list[Page]) -> list[Finding]:
    hosts = Counter()
    evidence_by_host: dict[str, list[Evidence]] = defaultdict(list)
    for result in observed_results(search_results):
        host = host_of(result.url)
        if not host:
            continue
        hosts[host] += 1
        evidence_by_host[host].append(Evidence(result.url, result.title, result.snippet[:240]))
    for page in pages:
        host = host_of(page.url)
        if not host:
            continue
        hosts[host] += 1
        evidence_by_host[host].append(Evidence(page.url, page.title, page.description[:240]))

    return [
        Finding(
            kind="web_presence",
            value=host,
            confidence=confidence(count),
            evidence=evidence_by_host[host][:4],
            notes=f"{count} evidenze raccolte su questo host.",
        )
        for host, count in hosts.most_common(12)
    ]


def profile_findings(search_results: list[SearchResult], pages: list[Page]) -> list[Finding]:
    urls = [result.url for result in observed_results(search_results)]
    for page in pages:
        urls.extend(page.links)

    profile_urls: dict[str, list[Evidence]] = defaultdict(list)
    for url in urls:
        host = host_of(url).removeprefix("www.")
        base_host = ".".join(host.split(".")[-2:])
        if host in SOCIAL_HOSTS or base_host in SOCIAL_HOSTS:
            profile_urls[url].append(Evidence(url=url, title=social_label(url)))

    return [
        Finding(
            kind="possible_profile",
            value=url,
            confidence=0.55,
            evidence=evidence[:2],
            notes="Profilo o pagina social rilevata da link pubblici; verificare manualmente attribuzione e contesto.",
        )
        for url, evidence in list(profile_urls.items())[:20]
    ]


def document_findings(search_results: list[SearchResult], pages: list[Page]) -> list[Finding]:
    urls = [result.url for result in observed_results(search_results)]
    for page in pages:
        urls.extend(page.links)

    findings: list[Finding] = []
    for url in sorted(set(urls)):
        path = urllib.parse.urlparse(url).path.casefold()
        if path.endswith(DOCUMENT_EXTENSIONS):
            findings.append(
                Finding(
                    kind="public_document",
                    value=url,
                    confidence=0.7,
                    evidence=[Evidence(url=url)],
                    notes="Documento pubblico individuato; aprire e valutare metadati/sensibilita solo se autorizzato.",
                )
            )
    return findings[:25]


def technology_findings(pages: list[Page]) -> list[Finding]:
    evidence: dict[str, list[Evidence]] = defaultdict(list)
    for page in pages:
        haystack = f"{page.title}\n{page.description}\n{page.text}"
        for tech, pattern in TECH_PATTERNS.items():
            if pattern.search(haystack):
                evidence[tech].append(Evidence(page.url, page.title, quote=snippet_for(haystack, pattern)))

    return [
        Finding(
            kind="technology_mention",
            value=tech,
            confidence=confidence(len(items)),
            evidence=items[:3],
            notes="Mention tecnologica rilevata nel testo pubblico; non equivale da sola a conferma di utilizzo.",
        )
        for tech, items in evidence.items()
    ]


def email_findings(pages: list[Page], include_contact: bool) -> list[Finding]:
    emails: dict[str, list[Evidence]] = defaultdict(list)
    for page in pages:
        for email in page.emails:
            value = email if include_contact else redact_email(email)
            emails[value].append(Evidence(page.url, page.title))

    kind = "contact_email" if include_contact else "redacted_contact_email"
    notes = (
        "Contatto pubblico incluso perche --include-contact e attivo."
        if include_contact
        else "Contatto pubblico redatto per minimizzazione dati; usa --include-contact solo quando necessario e autorizzato."
    )
    return [
        Finding(
            kind=kind,
            value=email,
            confidence=confidence(len(items)),
            evidence=items[:3],
            notes=notes,
        )
        for email, items in sorted(emails.items())
    ]


def timeline_findings(pages: list[Page]) -> list[Finding]:
    years: dict[str, list[Evidence]] = defaultdict(list)
    for page in pages:
        for year in sorted(set(YEAR_RE.findall(page.text))):
            years[year].append(Evidence(page.url, page.title, quote=snippet_for(page.text, re.compile(year))))

    return [
        Finding(
            kind="timeline_year_mention",
            value=year,
            confidence=min(0.8, 0.35 + len(items) * 0.08),
            evidence=items[:3],
            notes="Anno menzionato in fonti pubbliche; usare come spunto per costruire una timeline verificata.",
        )
        for year, items in sorted(years.items(), reverse=True)[:12]
    ]


def domain_findings(target: str, search_results: list[SearchResult], pages: list[Page]) -> list[Finding]:
    target = target.lower().removeprefix("www.")
    related: dict[str, list[Evidence]] = defaultdict(list)
    urls = [result.url for result in observed_results(search_results)]
    for page in pages:
        urls.append(page.url)
        urls.extend(page.links)

    for url in urls:
        host = host_of(url).removeprefix("www.")
        if host == target or host.endswith(f".{target}"):
            related[host].append(Evidence(url=url))

    return [
        Finding(
            kind="related_domain",
            value=host,
            confidence=confidence(len(items)),
            evidence=items[:4],
            notes="Dominio o sottodominio rilevato da fonti pubbliche.",
        )
        for host, items in sorted(related.items())
    ]


def host_of(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.casefold()


def observed_results(search_results: list[SearchResult]) -> list[SearchResult]:
    return [result for result in search_results if result.provider in OBSERVED_RESULT_PROVIDERS]


def observed_pages(pages: list[Page]) -> list[Page]:
    return [
        page
        for page in pages
        if not page.error
        and 200 <= page.status < 400
        and (page.title or page.description or page.text or page.links or page.emails)
    ]


def confidence(evidence_count: int) -> float:
    return min(0.95, 0.4 + evidence_count * 0.15)


def social_label(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.netloc}{parsed.path}".strip("/")


def snippet_for(text: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    start = max(0, match.start() - 80)
    end = min(len(text), match.end() + 120)
    return " ".join(text[start:end].split())
