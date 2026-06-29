from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from dataclasses import dataclass, field

from .extract import EMAIL_RE, extract_html, normalize_url
from .models import Page


@dataclass
class RobotsCache:
    user_agent: str
    timeout: int
    parsers: dict[str, urllib.robotparser.RobotFileParser] = field(default_factory=dict)

    def allowed(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.parsers:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(urllib.parse.urljoin(origin, "/robots.txt"))
            try:
                parser.read()
            except Exception:
                return True
            self.parsers[origin] = parser
        return self.parsers[origin].can_fetch(self.user_agent, url)


@dataclass
class FetchConfig:
    timeout: int = 12
    user_agent: str = "osint-bot/0.1 (+defensive public-source research)"
    min_delay_seconds: float = 1.0
    max_bytes: int = 1_000_000
    proxy_url: str = ""


class Fetcher:
    def __init__(self, config: FetchConfig):
        self.config = config
        self.robots = RobotsCache(config.user_agent, config.timeout)
        self.last_seen_by_host: dict[str, float] = {}
        if config.proxy_url:
            self.opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": config.proxy_url, "https": config.proxy_url})
            )
        else:
            self.opener = urllib.request.build_opener()

    def fetch(self, url: str) -> Page:
        normalized = normalize_url(url)
        if not normalized:
            return Page(url=url, status=0, error="URL non supportato.")
        if not self.robots.allowed(normalized):
            return Page(url=normalized, status=0, error="Bloccato da robots.txt.")

        self._respect_rate_limit(normalized)
        request = urllib.request.Request(normalized, headers={"User-Agent": self.config.user_agent})
        try:
            with self.opener.open(request, timeout=self.config.timeout) as response:
                status = getattr(response, "status", 200)
                content_type = response.headers.get("Content-Type", "")
                raw = response.read(self.config.max_bytes)
        except urllib.error.HTTPError as exc:
            return Page(url=normalized, status=exc.code, error=f"HTTP {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return Page(url=normalized, status=0, error=f"Errore rete: {exc.reason}")

        if "text/html" not in content_type and "application/xhtml" not in content_type:
            if is_text_content(content_type, normalized):
                text = raw.decode("utf-8", errors="replace")
                return Page(
                    url=normalized,
                    status=status,
                    title=urllib.parse.urlparse(normalized).path.rsplit("/", 1)[-1] or normalized,
                    text=text[:150_000],
                    emails=sorted(set(EMAIL_RE.findall(text))),
                )
            return Page(url=normalized, status=status, error=f"Contenuto non HTML: {content_type}")

        body = raw.decode("utf-8", errors="replace")
        title, description, text, links, emails = extract_html(body, normalized)
        return Page(
            url=normalized,
            status=status,
            title=title,
            description=description,
            text=text[:150_000],
            links=links,
            emails=emails,
        )

    def _respect_rate_limit(self, url: str) -> None:
        host = urllib.parse.urlparse(url).netloc.casefold()
        now = time.monotonic()
        last = self.last_seen_by_host.get(host)
        if last is not None:
            wait = self.config.min_delay_seconds - (now - last)
            if wait > 0:
                time.sleep(wait)
        self.last_seen_by_host[host] = time.monotonic()


def is_text_content(content_type: str, url: str) -> bool:
    lowered = content_type.lower()
    if any(kind in lowered for kind in ("text/plain", "text/xml", "application/xml", "application/json")):
        return True
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith((".txt", ".xml", ".json", ".csv"))
