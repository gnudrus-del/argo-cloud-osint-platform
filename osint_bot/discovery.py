from __future__ import annotations

import re
import urllib.parse

from .models import SearchResult

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def automatic_seed_results(target: str, target_type: str) -> list[SearchResult]:
    if target_type not in {"domain", "company", "org"}:
        return []
    domain = normalize_domain(target)
    if not domain:
        return []

    urls = [
        f"https://{domain}/",
        f"https://www.{domain}/",
        f"https://{domain}/about",
        f"https://{domain}/about-us",
        f"https://{domain}/contact",
        f"https://{domain}/privacy",
        f"https://{domain}/terms",
        f"https://{domain}/careers",
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/.well-known/security.txt",
        f"https://crt.sh/?q=%25.{domain}",
        f"https://urlscan.io/search/#domain:{domain}",
    ]
    return [
        SearchResult(
            title=label_for(url, domain),
            url=url,
            snippet="Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.",
            provider="seed",
        )
        for url in urls
    ]


def normalize_domain(target: str) -> str:
    value = target.strip().lower()
    if value.startswith(("http://", "https://")):
        value = urllib.parse.urlparse(value).netloc
    value = value.removeprefix("www.").strip("/")
    return value if DOMAIN_RE.match(value) else ""


def label_for(url: str, domain: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc == "crt.sh":
        return f"Certificate Transparency per {domain}"
    if parsed.netloc == "urlscan.io":
        return f"URLScan per {domain}"
    path = parsed.path.strip("/") or "home"
    return f"{domain} - {path}"

