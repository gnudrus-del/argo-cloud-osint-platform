from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field

from .grading import better_grade
from .models import Entity, Evidence, Finding, Investigation, Relationship
from .patterns import BTC_RE, EMAIL_RE, ETH_RE, IP_RE, PHONE_RE
from .safety import redact_email, redact_phone

ENTITY_TYPE_BY_TARGET = {
    "company": "organization",
    "org": "organization",
    "domain": "domain",
    "email": "email",
    "handle": "username",
    "person": "person",
    "phone": "phone",
    "ip": "ip",
    "crypto": "wallet",
    "media": "media",
}


@dataclass
class EntityGraphBuilder:
    entities: dict[str, Entity] = field(default_factory=dict)
    relationships: dict[tuple[str, str, str, str], Relationship] = field(default_factory=dict)

    def add_entity(
        self,
        entity_type: str,
        value: str,
        *,
        confidence: float = 0.5,
        source: str = "",
        attributes: dict | None = None,
        source_reliability: str = "F",
        info_credibility: int = 6,
    ) -> Entity:
        normalized = normalize_value(entity_type, value)
        entity_id = entity_key(entity_type, normalized)
        display_value = safe_display(entity_type, normalized)
        existing = self.entities.get(entity_id)
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            # Pillar 0.5: keep the BEST grade seen across all findings that
            # mentioned this entity — that's how a graded source set works.
            best = better_grade(
                existing.source_reliability, existing.info_credibility,
                source_reliability, info_credibility,
            )
            existing.source_reliability, existing.info_credibility = best
            if source and source not in existing.sources:
                existing.sources.append(source)
            if attributes:
                existing.attributes.update(attributes)
            return existing

        entity = Entity(
            id=entity_id,
            type=entity_type,
            value=normalized,
            display_value=display_value,
            confidence=confidence,
            sources=[source] if source else [],
            attributes=attributes or {},
            source_reliability=source_reliability,
            info_credibility=info_credibility,
        )
        self.entities[entity_id] = entity
        return entity

    def relate(
        self,
        source: Entity,
        target: Entity,
        kind: str,
        *,
        confidence: float = 0.5,
        evidence_url: str = "",
    ) -> None:
        if source.id == target.id:
            return
        key = (source.id, target.id, kind, evidence_url)
        existing = self.relationships.get(key)
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            return
        self.relationships[key] = Relationship(
            source=source.id,
            target=target.id,
            kind=kind,
            confidence=confidence,
            evidence_url=evidence_url,
        )


def enrich_investigation_entities(investigation: Investigation) -> None:
    builder = build_entity_graph(investigation)
    investigation.entities = sorted(builder.entities.values(), key=lambda item: (item.type, item.value))
    investigation.relationships = sorted(
        builder.relationships.values(),
        key=lambda item: (item.source, item.kind, item.target, item.evidence_url),
    )


def build_entity_graph(investigation: Investigation) -> EntityGraphBuilder:
    builder = EntityGraphBuilder()
    root = builder.add_entity(
        ENTITY_TYPE_BY_TARGET.get(investigation.target_type, investigation.target_type or "target"),
        investigation.target,
        confidence=0.9,
        source="target://input",
        attributes={"role": "target"},
    )

    for result in investigation.search_results:
        url_entity = add_url_entities(builder, result.url, result.provider)
        if url_entity:
            builder.relate(root, url_entity, "searched_or_seeded", confidence=0.35, evidence_url=result.url)

    for page in investigation.pages:
        url_entity = add_url_entities(builder, page.url, "page")
        if url_entity:
            builder.relate(root, url_entity, "observed_page", confidence=0.5, evidence_url=page.url)
        for email in page.emails:
            email_entity = builder.add_entity("email", email, confidence=0.65, source=page.url)
            if url_entity:
                builder.relate(url_entity, email_entity, "mentions", confidence=0.65, evidence_url=page.url)
        for link in page.links[:100]:
            linked = add_url_entities(builder, link, "page_link")
            if url_entity and linked:
                builder.relate(url_entity, linked, "links_to", confidence=0.35, evidence_url=page.url)

    for finding in investigation.findings:
        add_finding_entities(builder, root, finding)

    return builder


def add_url_entities(builder: EntityGraphBuilder, url: str, source: str) -> Entity | None:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    url_entity = builder.add_entity("url", normalize_url(url), confidence=0.45, source=source)
    host = parsed.netloc.casefold().removeprefix("www.")
    domain_entity = builder.add_entity("domain", host, confidence=0.5, source=url)
    builder.relate(url_entity, domain_entity, "hosted_on", confidence=0.5, evidence_url=url)
    return url_entity


def add_finding_entities(builder: EntityGraphBuilder, root: Entity, finding: Finding) -> None:
    evidence_url = first_evidence_url(finding.evidence)
    mapped_type = entity_type_for_finding(finding)
    if mapped_type:
        entity = builder.add_entity(
            mapped_type, finding.value,
            confidence=finding.confidence, source=evidence_url,
            source_reliability=finding.source_reliability,
            info_credibility=finding.info_credibility,
        )
        builder.relate(root, entity, "has_finding", confidence=finding.confidence, evidence_url=evidence_url)

    # Run the broad extractors over finding value/notes and evidence URLs only.
    # Evidence quotes are arbitrary text from third-party pages and produce false
    # phone/ip entities when scanned with permissive regexes.
    structured_haystack = " ".join(
        [finding.value, finding.notes, *[evidence.url for evidence in finding.evidence]]
    )
    for entity_type, value in extract_entities_from_text(structured_haystack):
        entity = builder.add_entity(
            entity_type, value,
            confidence=max(0.4, finding.confidence), source=evidence_url,
            source_reliability=finding.source_reliability,
            info_credibility=finding.info_credibility,
        )
        builder.relate(root, entity, "mentions", confidence=max(0.4, finding.confidence), evidence_url=evidence_url)


def entity_type_for_finding(finding: Finding) -> str:
    kind = finding.kind
    if kind in {"related_domain", "web_presence"}:
        return "domain"
    if kind in {"contact_email", "redacted_contact_email"}:
        return "email"
    if kind in {"phone_format"}:
        return "phone"
    if "profile" in kind or "socmint" in kind:
        return "url" if finding.value.startswith("http") else "username"
    if "crypto" in kind:
        return "wallet"
    if "geo" in kind:
        return "location"
    if "media" in kind:
        return "media"
    return ""


def extract_entities_from_text(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in EMAIL_RE.finditer(text):
        found.append(("email", match.group(0)))
    for match in IP_RE.finditer(text):
        token = match.group(0)
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue  # rejects 999.0.0.1, 1.2.3.4 in versions, etc.
        found.append(("ip", token))
    for pattern, entity_type in ((ETH_RE, "wallet"), (BTC_RE, "wallet")):
        found.extend((entity_type, match.group(0)) for match in pattern.finditer(text))
    for match in PHONE_RE.finditer(text):
        digits = re.sub(r"\D+", "", match.group(0))
        if 7 <= len(digits) <= 15:
            found.append(("phone", match.group(0)))
    return found


def first_evidence_url(evidence: list[Evidence]) -> str:
    for item in evidence:
        if item.url:
            return item.url
    return ""


def entity_key(entity_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()[:16]
    return f"{entity_type}:{digest}"


_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
_TRACKING_PARAM_PREFIXES = ("utm_",)
_TRACKING_PARAMS = {"gclid", "fbclid", "yclid", "mc_eid", "mc_cid"}


def normalize_value(entity_type: str, value: str) -> str:
    cleaned = " ".join(str(value).strip().split())
    if entity_type in {"domain", "email", "ip", "url", "wallet", "username"}:
        cleaned = cleaned.casefold()
    if entity_type == "domain":
        cleaned = cleaned.removeprefix("www.").strip(".")
        cleaned = _to_punycode_host(cleaned)
    if entity_type == "email":
        cleaned = _canonicalize_email(cleaned)
    if entity_type == "phone":
        return _canonicalize_phone(cleaned)
    if entity_type == "url":
        return normalize_url(cleaned)
    return cleaned


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return url.strip()
    netloc = _to_punycode_host(parsed.netloc.casefold())
    path = parsed.path or "/"
    query = _strip_tracking_params(parsed.query)
    normalized = parsed._replace(netloc=netloc, path=path, query=query, fragment="")
    return urllib.parse.urlunparse(normalized).rstrip("/")


def _to_punycode_host(host: str) -> str:
    if not host or all(ord(ch) < 128 for ch in host):
        return host
    # Preserve port if present.
    name, sep, port = host.partition(":")
    try:
        encoded = name.encode("idna").decode("ascii")
    except UnicodeError:
        return host
    return f"{encoded}{sep}{port}" if sep else encoded


def _canonicalize_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return value
    domain = domain.casefold()
    if domain == "googlemail.com":
        domain = "gmail.com"
    if domain in _GMAIL_DOMAINS:
        local = local.split("+", 1)[0].replace(".", "")
    return f"{local}@{domain}"


def _canonicalize_phone(value: str) -> str:
    cleaned = value.strip()
    has_plus = cleaned.startswith("+")
    digits = re.sub(r"\D+", "", cleaned)
    if not digits:
        return cleaned
    if has_plus and 7 <= len(digits) <= 15:
        return f"+{digits}"
    return digits


def _strip_tracking_params(query: str) -> str:
    if not query:
        return query
    kept: list[tuple[str, str]] = []
    for key, raw_value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        lowered = key.casefold()
        if any(lowered.startswith(prefix) for prefix in _TRACKING_PARAM_PREFIXES):
            continue
        if lowered in _TRACKING_PARAMS:
            continue
        kept.append((key, raw_value))
    return urllib.parse.urlencode(kept, doseq=True)


def safe_display(entity_type: str, value: str) -> str:
    if entity_type == "email":
        return redact_email(value)
    if entity_type == "phone":
        return redact_phone(value)
    return value
