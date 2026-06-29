from __future__ import annotations

import urllib.parse

from .models import SearchResult


def service_link_results(target: str, target_type: str) -> list[SearchResult]:
    encoded = urllib.parse.quote_plus(target)
    results: list[SearchResult] = []

    if target_type in {"domain", "ip"}:
        results.extend(
            [
                link("Shodan", f"https://www.shodan.io/search?query={encoded}", "shodan_link", target),
                link("Censys Hosts", f"https://search.censys.io/search?resource=hosts&q={encoded}", "censys_link", target),
                link("IntelligenceX", f"https://intelx.io/?s={encoded}", "intelx_link", target),
                link("Wayback Machine", f"https://web.archive.org/web/*/{target}", "wayback_link", target),
            ]
        )
        if target_type == "domain":
            results.append(link("Hunter.io", f"https://hunter.io/search/{encoded}", "hunter_link", target))

    if target_type in {"email", "handle", "phone"}:
        results.extend(
            [
                link("Epieos", f"https://epieos.com/?q={encoded}", "epieos_link", target),
                link("IntelligenceX", f"https://intelx.io/?s={encoded}", "intelx_link", target),
            ]
        )
    if target_type == "email":
        results.append(link("Have I Been Pwned", f"https://haveibeenpwned.com/account/{encoded}", "hibp_link", target))

    return results


def link(title: str, url: str, provider: str, target: str) -> SearchResult:
    return SearchResult(
        title=f"{title}: {target}",
        url=url,
        snippet="Fonte servizio generata automaticamente; aprire manualmente o configurare API key per integrazione piu profonda.",
        provider=provider,
    )
