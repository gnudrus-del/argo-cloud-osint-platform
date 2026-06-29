from __future__ import annotations

import urllib.parse

from .models import SearchResult


def build_dorks(target: str, target_type: str, depth: int) -> list[str]:
    quoted = f'"{target}"'
    dorks = [quoted]

    if target_type == "domain":
        dorks.extend(
            [
                f"site:{target}",
                f"site:{target} filetype:pdf",
                f"site:{target} filetype:xls OR filetype:xlsx",
                f"site:{target} intitle:index.of",
                f"site:{target} inurl:admin OR inurl:login",
                f"site:{target} intext:\"api_key\" OR intext:\"token\" OR intext:\"secret\"",
                f"site:github.com {quoted}",
                f"site:crt.sh {quoted}",
            ]
        )
    elif target_type in {"company", "org"}:
        dorks.extend(
            [
                f"{quoted} official",
                f"{quoted} privacy policy",
                f"{quoted} contact email",
                f"{quoted} filetype:pdf",
                f"{quoted} site:linkedin.com/company",
                f"{quoted} site:github.com",
            ]
        )
    elif target_type in {"handle", "username"}:
        handle = target.lstrip("@")
        dorks.extend(
            [
                f'"{handle}" site:github.com',
                f'"{handle}" site:gitlab.com',
                f'"{handle}" site:linkedin.com',
                f'"{handle}" site:x.com OR site:twitter.com',
                f'"{handle}" site:instagram.com',
                f'"{handle}" site:tiktok.com',
                f'"{handle}" email OR contact',
            ]
        )
    elif target_type == "email":
        domain = target.split("@")[-1] if "@" in target else target
        dorks.extend(
            [
                f'"{target}"',
                f'"{target}" breach OR leak',
                f'"{target}" site:github.com',
                f"site:{domain} contact",
            ]
        )
    elif target_type == "phone":
        dorks.extend([quoted, f"{quoted} contact", f"{quoted} company"])
    elif target_type == "crypto":
        dorks.extend([f"{quoted} explorer", f"{quoted} scam", f"{quoted} github", f"{quoted} transaction"])
    elif target_type == "ip":
        dorks.extend([f"{quoted} shodan", f"{quoted} censys", f"{quoted} abuse", f"{quoted} certificate"])
    elif target_type == "media":
        dorks.extend([f"{quoted} exif", f"{quoted} metadata", f"{quoted} reverse image"])

    if depth >= 3:
        dorks.extend([f"{quoted} archive", f"{quoted} cache", f"{quoted} site:webcache.googleusercontent.com"])
    return dedupe(dorks)


def dork_results(dorks: list[str]) -> list[SearchResult]:
    results: list[SearchResult] = []
    engines = [
        ("google_dork", "https://www.google.com/search?q={query}"),
        ("bing_dork", "https://www.bing.com/search?q={query}"),
        ("duckduckgo_dork", "https://duckduckgo.com/?q={query}"),
        ("yandex_dork", "https://yandex.com/search/?text={query}"),
    ]
    for dork in dorks:
        encoded = urllib.parse.quote_plus(dork)
        for provider, template in engines:
            results.append(
                SearchResult(
                    title=f"{provider.replace('_', ' ')}: {dork}",
                    url=template.format(query=encoded),
                    snippet="Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.",
                    provider=provider,
                )
            )
    return results


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        key = value.casefold().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(value)
    return unique
