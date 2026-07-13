from __future__ import annotations

import html
import re
import urllib.parse
from html.parser import HTMLParser

from .patterns import EMAIL_RE

SPACE_RE = re.compile(r"\s+")


class HTMLTextExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self._skip_depth = 0
        self._capture_title = False
        self.title = ""
        self.description = ""
        self.parts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1
            return
        if tag == "title":
            self._capture_title = True
        if tag == "meta":
            name = attrs_dict.get("name", "").lower()
            prop = attrs_dict.get("property", "").lower()
            if name == "description" or prop == "og:description":
                self.description = compact(attrs_dict.get("content", ""))
        if tag == "a" and attrs_dict.get("href"):
            link = normalize_url(urllib.parse.urljoin(self.base_url, attrs_dict["href"]))
            if link:
                self.links.append(link)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._capture_title = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        cleaned = compact(data)
        if not cleaned:
            return
        if self._capture_title:
            self.title += f" {cleaned}"
        else:
            self.parts.append(cleaned)

    @property
    def text(self) -> str:
        return compact(" ".join(self.parts))


def extract_html(html_body: str, base_url: str) -> tuple[str, str, str, list[str], list[str]]:
    parser = HTMLTextExtractor(base_url)
    parser.feed(html_body)
    text = html.unescape(parser.text)
    title = compact(html.unescape(parser.title))
    description = compact(html.unescape(parser.description))
    emails = sorted(set(EMAIL_RE.findall(text)))
    links = dedupe(parser.links)
    return title, description, text, links, emails


def compact(value: str) -> str:
    return SPACE_RE.sub(" ", value).strip()


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    parsed = parsed._replace(fragment="")
    return urllib.parse.urlunparse(parsed)


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        key = value.rstrip("/").casefold()
        if key and key not in seen:
            seen.add(key)
            unique.append(value)
    return unique

