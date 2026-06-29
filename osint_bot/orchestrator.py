from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field

from .patterns import (
    BTC_RE,
    DOMAIN_RE,
    EMAIL_RE,
    ETH_RE,
    HANDLE_RE,
    PHONE_LOOSE_RE as PHONE_RE,
    URL_RE,
)


@dataclass
class RunProfile:
    command: str
    target: str
    target_type: str
    agents: list[str] = field(default_factory=list)
    external_tools: list[str] = field(default_factory=list)
    seed_urls: list[str] = field(default_factory=list)
    depth: int = 2
    max_pages: int = 12
    notes: list[str] = field(default_factory=list)


def plan_from_command(
    command: str,
    *,
    target: str = "",
    target_type: str = "",
    selected_modules: list[str] | None = None,
    search_engine: str = "all",
    source_route: str = "standard",
    intensity: str = "meticulous",
    confirm_authorization: bool = False,
    allow_network_scan: bool = False,
    allow_darkweb: bool = False,
    include_external_tools: bool = True,
) -> RunProfile:
    text = command.strip()
    inferred_target = target.strip() or infer_target(text)
    inferred_type = target_type.strip() or infer_target_type(inferred_target, text)
    seed_urls = URL_RE.findall(text)
    modules = selected_modules or []
    if any(word in text.casefold() for word in ("red team", "red-team", "offensivo", "offensiva")) and "red_team" not in modules:
        modules = [*modules, "red_team"]
    agents = choose_agents(text, inferred_type, allow_darkweb, modules)
    external_tools = choose_external_tools(
        text,
        inferred_type,
        modules=modules,
        confirm_authorization=confirm_authorization,
        allow_network_scan=allow_network_scan,
        include_external_tools=include_external_tools,
    )
    if external_tools and "external" not in agents:
        agents.append("external")
    notes = explain_plan(text, inferred_type, agents, external_tools, allow_darkweb, search_engine, source_route, intensity)

    return RunProfile(
        command=command,
        target=inferred_target,
        target_type=inferred_type,
        agents=agents,
        external_tools=external_tools,
        seed_urls=seed_urls,
        depth=3 if intensity in {"meticulous", "deep"} or wants_deep_search(text) else 2,
        max_pages=35 if intensity == "deep" else 24 if intensity == "meticulous" or wants_deep_search(text) else 12,
        notes=notes,
    )


def infer_target(text: str) -> str:
    if match := URL_RE.search(text):
        parsed = urllib.parse.urlparse(match.group(0))
        return parsed.netloc or match.group(0)
    if match := EMAIL_RE.search(text):
        return match.group(0)
    if match := ETH_RE.search(text):
        return match.group(0)
    if match := BTC_RE.search(text):
        return match.group(0)
    if match := HANDLE_RE.search(text):
        return match.group(1)
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(token)
            return token
        except ValueError:
            pass
    if match := PHONE_RE.search(text):
        digits = re.sub(r"\D+", "", match.group(0))
        if 7 <= len(digits) <= 15:
            return match.group(0).strip()
    if match := DOMAIN_RE.search(text):
        return match.group(0).strip().rstrip(".")
    return text[:160].strip()


def infer_target_type(target: str, text: str) -> str:
    lower = text.casefold()
    if "immagin" in lower or "video" in lower or "metadata" in lower or "metadati" in lower or "exif" in lower:
        return "media"
    if EMAIL_RE.fullmatch(target):
        return "email"
    if ETH_RE.fullmatch(target) or BTC_RE.fullmatch(target) or "wallet" in lower or "blockchain" in lower:
        return "crypto"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    if "telefono" in lower or "phone" in lower:
        return "phone"
    if "username" in lower or "handle" in lower or target.startswith("@"):
        return "handle"
    if "persona" in lower or "socmint" in lower or "human" in lower:
        return "person"
    if DOMAIN_RE.fullmatch(target):
        return "domain"
    if "azienda" in lower or "company" in lower or "societa" in lower:
        return "company"
    return "company"


def choose_agents(text: str, target_type: str, allow_darkweb: bool, modules: list[str] | None = None) -> list[str]:
    lower = text.casefold()
    agents = ["planner", "web", "opsec"]
    selected = set(modules or [])

    if target_type in {"domain", "ip", "company", "org"} or "company_domain" in selected:
        agents.extend(["geo"])
    if "red_team" in selected:
        agents.extend(["geo", "external", "red_team"])
    if target_type in {"handle", "person", "email", "phone"} or "socmint" in lower or "socmint" in selected:
        agents.extend(["socmint"])
    if target_type == "phone" or "phone_email" in selected:
        agents.append("phone")
    # Reverse-account discovery: only when target is email/phone and the user
    # said this is authorised. The agent itself re-checks confirm_authorization.
    if target_type in {"email", "phone"} and "phone_email" in selected:
        agents.append("reverse_account")
    if target_type == "crypto" or "crypto" in lower or "blockchain" in lower or "wallet" in lower or "crypto" in selected:
        agents.append("crypto")
    if target_type == "media" or "immagin" in lower or "video" in lower or "metadat" in lower or "exif" in lower or "media" in selected:
        agents.append("media")
    if "geo" in lower or "geolocal" in lower or "map" in lower or "geo" in selected:
        agents.append("geo")
    if "dark web" in lower or "darkweb" in lower or "deep web" in lower or ".onion" in lower or "darkweb" in selected:
        agents.append("darkweb")
    if "humint" in lower or "humanit" in lower or "elicit" in lower or "intervista" in lower or "humint" in selected:
        agents.append("humint")
    if "tool" in lower or "sherlock" in lower or "maigret" in lower or "holehe" in lower or "nmap" in lower:
        agents.append("external")
    if "external" in selected:
        agents.append("external")
    if allow_darkweb and "darkweb" not in agents and (".onion" in lower):
        agents.append("darkweb")

    return unique(agents)


def choose_external_tools(
    text: str,
    target_type: str,
    *,
    modules: list[str] | None = None,
    confirm_authorization: bool,
    allow_network_scan: bool,
    include_external_tools: bool,
) -> list[str]:
    if not include_external_tools:
        return []
    lower = text.casefold()
    selected: list[str] = []
    explicit = {
        "sherlock": "sherlock",
        "maigret": "maigret",
        "holehe": "holehe",
        "h8mail": "h8mail",
        "social-analyzer": "social_analyzer",
        "social analyzer": "social_analyzer",
        "phoneinfoga": "phoneinfoga",
        "ghunt": "ghunt",
        "toutatis": "toutatis",
        "osintgram": "osintgram",
        "spiderfoot": "spiderfoot",
        "recon-ng": "recon_ng",
        "recon_ng": "recon_ng",
        "singlefile": "singlefile",
        "single-file": "singlefile",
        "shodan": "shodan",
        "censys": "censys",
        "nmap": "nmap",
        "exiftool": "exiftool",
        "ffprobe": "ffprobe",
    }
    for keyword, tool in explicit.items():
        if keyword in lower:
            selected.append(tool)

    auto_requested = "auto" in lower or "scegli" in lower or "automatic" in lower or "tool" in lower
    module_set = set(modules or [])
    if auto_requested or module_set:
        if target_type == "handle" and confirm_authorization:
            selected.extend(["sherlock", "maigret", "socialscan", "social_analyzer", "toutatis", "osintgram"])
            if "phone_email" in module_set or "socmint" in module_set:
                selected.append("socialscan")
        if target_type == "email" and confirm_authorization and (
            auto_requested or "phone_email" in module_set or not module_set
        ):
            selected.extend(["holehe", "socialscan", "h8mail", "ghunt", "mosint"])
        if target_type == "phone" and confirm_authorization:
            selected.extend(["phoneinfoga", "phunter"])
        if target_type in {"domain", "ip"} and confirm_authorization and allow_network_scan:
            selected.append("nmap")
        if target_type == "domain" and ("company_domain" in module_set or "opsec" in module_set or "red_team" in module_set):
            selected.extend(["theharvester", "amass", "subfinder", "waybackurls", "gau",
                              "spiderfoot", "recon_ng", "shodan", "censys",
                              "dnsx", "dnstwist", "whatweb", "httpx", "katana",
                              "gospider", "hakrawler", "metagoofil", "wafw00f", "testssl"])
            if confirm_authorization and allow_network_scan:
                selected.extend(["nmap", "naabu", "nuclei"])
        if target_type in {"company", "org"} and ("company_domain" in module_set or "opsec" in module_set):
            selected.extend(["spiderfoot", "recon_ng", "theharvester", "dnstwist"])
        if target_type == "ip" and ("company_domain" in module_set or "opsec" in module_set or "red_team" in module_set):
            selected.extend(["spiderfoot", "shodan", "censys", "naabu", "nuclei", "whatweb"])
        if target_type == "media" or "media" in module_set:
            selected.extend(["exiftool", "ffprobe"])

    return unique(selected)


def explain_plan(
    text: str,
    target_type: str,
    agents: list[str],
    external_tools: list[str],
    allow_darkweb: bool,
    search_engine: str,
    source_route: str,
    intensity: str,
) -> list[str]:
    notes = [
        f"Tipo di obiettivo stimato: {target_type}.",
        f"Agenti selezionati: {', '.join(agents)}.",
        f"Motori/provider ricerca: {search_engine}. In modalita all usa tutte le API configurate e genera dork verificabili.",
        f"Percorso sorgenti/browser: {source_route}.",
        f"Intensita: {intensity}.",
    ]
    if external_tools:
        notes.append(f"Strumenti esterni selezionati: {', '.join(external_tools)}.")
    if source_route == "tor":
        notes.append("Tor richiesto: usare solo proxy/browser isolato configurato; le API search ricevono comunque le query se usate.")
    if source_route == "firefox":
        notes.append("Mozilla/Firefox dedicato richiesto: usare profilo separato senza account personali, sync o cookie preesistenti.")
    if source_route == "multi":
        notes.append("Multi-provider: usa API configurate, dork verificabili, seed e tool compatibili; le fonti vanno confermate manualmente.")
    if any(agent in agents for agent in {"socmint", "phone", "humint"}):
        notes.append("Identificatori personali trattati con minimizzazione, verifica manuale e report redatti.")
    if "darkweb" in agents:
        if allow_darkweb:
            notes.append("Dark/deep web abilitato solo per fonti seed e monitoraggio difensivo.")
        else:
            notes.append("Dark/deep web pianificato ma richiede abilitazione esplicita.")
    if "elicit" in text.casefold():
        notes.append("Elicitazione convertita in preparazione HUMINT etica: consenso, domande aperte, niente inganno.")
    return notes


def wants_deep_search(text: str) -> bool:
    lower = text.casefold()
    return any(word in lower for word in ("approfond", "deep", "completo", "investigativo", "full"))


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
