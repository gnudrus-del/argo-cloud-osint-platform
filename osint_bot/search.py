from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .models import SearchResult


class SearchError(RuntimeError):
    pass


@dataclass(frozen=True)
class SearchConfig:
    provider: str = "all"
    max_results: int = 10
    timeout: int = 12
    # Per-user API keys resolved by the caller (web.resolve_api_key). When
    # a provider's key is missing here we fall back to the env var so the
    # CLI keeps working unchanged.
    api_keys: dict[str, str] = field(default_factory=dict)


def _key_for(provider: str, config: SearchConfig) -> str:
    """Resolve the key for *provider*: user-set first, env var second."""
    if config.api_keys.get(provider):
        return config.api_keys[provider]
    env_by_provider = {
        "bing": "BING_SEARCH_API_KEY",
        "brave": "BRAVE_SEARCH_API_KEY",
        "serper": "SERPER_API_KEY",
    }
    return os.getenv(env_by_provider.get(provider, ""), "") or ""


def build_queries(target: str, target_type: str, depth: int) -> list[str]:
    quoted = f'"{target}"'
    base = [target, quoted]

    if target_type == "domain":
        extra = [
            f"site:{target}",
            f"{target} security.txt",
            f"{target} privacy policy",
            f"{target} filetype:pdf",
        ]
    elif target_type in {"company", "org"}:
        extra = [
            f"{quoted} official",
            f"{quoted} news",
            f"{quoted} leadership",
            f"{quoted} careers",
            f"{quoted} privacy policy",
        ]
    elif target_type in {"handle", "username"}:
        handle = target.lstrip("@")
        extra = [
            f'"{handle}" GitHub',
            f'"{handle}" LinkedIn',
            f'"{handle}" social',
        ]
    elif target_type == "email":
        domain = target.split("@")[-1] if "@" in target else target
        extra = [
            f'"{target}"',
            f"site:{domain}",
            f"{domain} contact",
        ]
    elif target_type == "phone":
        extra = [
            f'"{target}"',
            f'"{target}" contact',
            f'"{target}" company',
        ]
    elif target_type == "crypto":
        extra = [
            f'"{target}" blockchain',
            f'"{target}" explorer',
            f'"{target}" scam report',
        ]
    elif target_type == "ip":
        extra = [
            f'"{target}"',
            f'"{target}" abuse',
            f'"{target}" security',
        ]
    elif target_type == "media":
        extra = [
            f'"{target}" image metadata',
            f'"{target}" video metadata',
            f'"{target}" EXIF',
        ]
    elif target_type == "person":
        extra = [
            f"{quoted} professional profile",
            f"{quoted} publication",
            f"{quoted} organization",
        ]
    else:
        extra = [f"{quoted} official", f"{quoted} news"]

    if depth >= 2:
        extra.extend([f"{quoted} report", f"{quoted} archive", f"{quoted} filetype:pdf"])
    if depth >= 3:
        extra.extend([f"{quoted} filetype:doc", f"{quoted} filetype:xls", f"{quoted} site:github.com"])

    return dedupe([*base, *extra])


def search_many(queries: list[str], config: SearchConfig) -> list[SearchResult]:
    results: list[SearchResult] = []
    if config.provider == "all":
        providers = [provider for provider in ("bing", "brave", "serper") if _key_for(provider, config)]
        for query in queries:
            for provider in providers:
                results.extend(search(query, SearchConfig(provider=provider, max_results=config.max_results, timeout=config.timeout, api_keys=config.api_keys)))
        return dedupe_results(results)[: config.max_results * max(1, len(queries), len(providers))]
    for query in queries:
        results.extend(search(query, config))
    return dedupe_results(results)[: config.max_results * max(1, len(queries))]


def search(query: str, config: SearchConfig) -> list[SearchResult]:
    provider = resolve_provider(config.provider, config)
    if provider in {"none", "all"}:
        return []
    if provider_requires_key(provider) and not _key_for(provider, config):
        return []
    if provider == "bing":
        return bing_search(query, config)
    if provider == "brave":
        return brave_search(query, config)
    if provider == "serper":
        return serper_search(query, config)
    raise SearchError(f"Provider di ricerca non supportato: {provider}")


def resolve_provider(provider: str, config: SearchConfig | None = None) -> str:
    if provider in {"all", "none", "bing", "brave", "serper"}:
        return provider
    if provider != "auto":
        return provider
    cfg = config or SearchConfig()
    for candidate in ("bing", "brave", "serper"):
        if _key_for(candidate, cfg):
            return candidate
    return "none"


def provider_requires_key(provider: str) -> bool:
    return provider in {"bing", "brave", "serper"}


def provider_has_key(provider: str, actor: str = "") -> bool:
    """Check if a key is available for a provider, looking at both the actor's
    saved keys (DB) and the process-wide env vars.

    When actor is empty (e.g. server-wide checks), only env vars are inspected.
    """
    key_map = {
        "bing": "BING_SEARCH_API_KEY",
        "brave": "BRAVE_SEARCH_API_KEY",
        "serper": "SERPER_API_KEY",
    }
    env_name = key_map.get(provider)
    if env_name and os.getenv(env_name):
        return True
    if actor:
        # Lazy import to avoid circular: search → web → search
        try:
            from .web import resolve_api_key
            return bool(resolve_api_key(provider, actor))
        except Exception:
            return False
    return False


def bing_search(query: str, config: SearchConfig) -> list[SearchResult]:
    api_key = _key_for("bing", config)
    if not api_key:
        raise SearchError("Chiave Bing non configurata.")

    params = urllib.parse.urlencode({"q": query, "count": min(config.max_results, 50), "responseFilter": "Webpages"})
    request = urllib.request.Request(
        f"https://api.bing.microsoft.com/v7.0/search?{params}",
        headers={
            "Accept": "application/json",
            "Ocp-Apim-Subscription-Key": api_key,
            "User-Agent": "osint-bot/0.2",
        },
    )
    payload = get_json(request, config.timeout)
    return [
        SearchResult(
            title=item.get("name", ""),
            url=item.get("url", ""),
            snippet=item.get("snippet", ""),
            provider="bing",
        )
        for item in payload.get("webPages", {}).get("value", [])
        if item.get("url")
    ]


def brave_search(query: str, config: SearchConfig) -> list[SearchResult]:
    api_key = _key_for("brave", config)
    if not api_key:
        raise SearchError("Chiave Brave non configurata.")

    params = urllib.parse.urlencode({"q": query, "count": min(config.max_results, 20)})
    request = urllib.request.Request(
        f"https://api.search.brave.com/res/v1/web/search?{params}",
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
            "User-Agent": "osint-bot/0.1",
        },
    )
    payload = get_json(request, config.timeout)
    web_results = payload.get("web", {}).get("results", [])
    return [
        SearchResult(
            title=item.get("title", ""),
            url=item.get("url", ""),
            snippet=item.get("description", ""),
            provider="brave",
        )
        for item in web_results
        if item.get("url")
    ]


def serper_search(query: str, config: SearchConfig) -> list[SearchResult]:
    api_key = _key_for("serper", config)
    if not api_key:
        raise SearchError("Chiave Serper non configurata.")

    body = json.dumps({"q": query, "num": min(config.max_results, 20)}).encode("utf-8")
    request = urllib.request.Request(
        "https://google.serper.dev/search",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": api_key,
            "User-Agent": "osint-bot/0.1",
        },
    )
    payload = get_json(request, config.timeout)
    return [
        SearchResult(
            title=item.get("title", ""),
            url=item.get("link", ""),
            snippet=item.get("snippet", ""),
            provider="serper",
        )
        for item in payload.get("organic", [])
        if item.get("link")
    ]


def get_json(request: urllib.request.Request, timeout: int) -> dict:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise SearchError(f"Errore provider ricerca HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise SearchError(f"Errore rete provider ricerca: {exc.reason}") from exc


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        key = item.strip().casefold()
        if key and key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def dedupe_results(results: list[SearchResult]) -> list[SearchResult]:
    seen: set[str] = set()
    unique: list[SearchResult] = []
    for result in results:
        key = result.url.rstrip("/").casefold()
        if key and key not in seen:
            seen.add(key)
            unique.append(result)
    return unique
