"""Connector package — all Pillar 1 + Phase 8 + Phase 9 + Phase 10 connector implementations.

Usage:
    from osint_bot.connectors import build_default_registry
    registry = build_default_registry()
"""
from __future__ import annotations

import os

from ..connector import ConnectorRegistry
# Pillar 1 (existing)
from . import abuseipdb, crt_sh, github_search, hibp, hunter, leakix, rdap, shodan, urlscan, virustotal, wayback
# Phase 8 (new)
from . import (
    phishtank, openphish, nominatim, gdelt,
    securitytrails, greynoise, otx, emailrep, ipinfo, etherscan,
    opencorporates, sec_edgar, companies_house,
    brave_search_api, google_pse,
)
# Phase 9 — external platforms (bridged via local API)
from . import flowsint
# Phase 10 — native no-key enrichers (Option C: reimplementano localmente
# le stesse fonti pubbliche che usa FlowSINT, senza dipendenza esterna).
from . import dns_query, tls_cert, gravatar, common_crawl, web_fingerprint
# Phase 11 — native port di funzionalita' oggi coperte da tool CLI esterni.
from . import asn_lookup, sherlock_lite, phone_meta
# Phase 12 — threat-intel & geo no-key + bridge MISP.
from . import shodan_internetdb, overpass, threatfox, misp_client
# Phase 13 — sostituti nativi di tool CLI esterni (recon attivo/passivo).
from . import (
    content_discovery, port_scan, subdomain_enum, dnstwist_native,
    secret_scan, url_harvest, holehe_native,
)
# Phase 14 — Maigret completo integrato come motore username primario.
from . import maigret
# Phase 15 — holehe completo integrato come motore email primario.
from . import holehe
# Phase 16 — theHarvester: raccolta email/host da dominio (OSINT aziendale).
from . import theharvester
# Phase 17 — reverse lookup (telefono/social → email/registrazione).
from . import phone_footprint, ignorant, ghunt, toutatis
# Phase 18 — socid-extractor (URL profilo → ID/metadata social).
from . import socid_extractor as socid_extractor_mod
# Phase 19 — Telegram (numero → account) + LinkedIn2Username (azienda → username).
from . import telegram_checker, linkedin2username
# Phase 20 — Influencers Club (BYOK, username → email verificata).
from . import influencers_club
# Phase 21 — legit_scorer aggregatore nativo (SION-like).
from . import legit_scorer
# Phase 22 — darkweb_scan (leggero, sostituto onesto di Prying Deep archived).
from . import darkweb_scan

__all__ = [
    "abuseipdb", "crt_sh", "github_search", "hibp", "hunter",
    "leakix", "rdap", "shodan", "urlscan", "virustotal", "wayback",
    "phishtank", "openphish", "nominatim", "gdelt",
    "securitytrails", "greynoise", "otx", "emailrep", "ipinfo", "etherscan",
    "opencorporates", "sec_edgar", "companies_house",
    "brave_search_api", "google_pse",
    "flowsint",
    "dns_query", "tls_cert", "gravatar", "common_crawl", "web_fingerprint",
    "asn_lookup", "sherlock_lite", "phone_meta",
    "shodan_internetdb", "overpass", "threatfox", "misp_client",
    "content_discovery", "port_scan", "subdomain_enum", "dnstwist_native",
    "secret_scan", "url_harvest", "holehe_native", "maigret", "holehe",
    "theharvester",
    "phone_footprint", "ignorant", "ghunt", "toutatis", "socid_extractor",
    "telegram_checker", "linkedin2username", "influencers_club", "legit_scorer",
    "darkweb_scan",
    "build_default_registry",
]


def build_default_registry() -> ConnectorRegistry:
    """Build and return a pre-populated ConnectorRegistry with all bundled connectors."""
    reg = ConnectorRegistry()
    # Pillar 1
    reg.register(crt_sh.CrtShConnector())
    reg.register(rdap.RdapConnector())
    reg.register(shodan.ShodanConnector())
    reg.register(virustotal.VirusTotalConnector())
    reg.register(urlscan.URLScanConnector())
    reg.register(wayback.WaybackConnector())
    reg.register(hibp.HIBPConnector())
    reg.register(hunter.HunterConnector())
    reg.register(github_search.GitHubSearchConnector())
    reg.register(leakix.LeakIXConnector())
    reg.register(abuseipdb.AbuseIPDBConnector())
    # Phase 8 — no-key
    reg.register(phishtank.PhishTankConnector())
    reg.register(openphish.OpenPhishConnector())
    reg.register(nominatim.NominatimConnector())
    reg.register(gdelt.GDELTConnector())
    # Phase 8 — BYOK
    reg.register(securitytrails.SecurityTrailsConnector())
    reg.register(greynoise.GreyNoiseConnector())
    reg.register(otx.OTXConnector())
    reg.register(emailrep.EmailRepConnector())
    reg.register(ipinfo.IPinfoConnector())
    reg.register(etherscan.EtherscanConnector())
    # Phase 8 — corporate registries
    reg.register(opencorporates.OpenCorporatesConnector())
    reg.register(sec_edgar.SECEdgarConnector())
    reg.register(companies_house.CompaniesHouseConnector())
    # Phase 8 — search engines (BYOK)
    reg.register(brave_search_api.BraveSearchAPIConnector())
    reg.register(google_pse.GooglePSEConnector())
    # Phase 9 — external platforms (bridged via local API)
    # FlowSINT è disattivato di default: la sua funzionalità è stata sostituita
    # dai connettori nativi Phase 10-13. Lo si può riabilitare impostando
    # FLOWSINT_ENABLE=1 nel .env (utile solo se si tiene lo stack Docker).
    if os.getenv("FLOWSINT_ENABLE", "0") == "1":
        reg.register(flowsint.FlowSINTConnector())
    # Phase 10 — native no-key enrichers
    reg.register(dns_query.DNSQueryConnector())
    reg.register(tls_cert.TLSCertConnector())
    reg.register(gravatar.GravatarConnector())
    reg.register(common_crawl.CommonCrawlConnector())
    reg.register(web_fingerprint.WebFingerprintConnector())
    # Phase 11 — native port di tool CLI esterni
    reg.register(asn_lookup.ASNLookupConnector())
    reg.register(sherlock_lite.SherlockLiteConnector())
    reg.register(phone_meta.PhoneMetaConnector())
    # Phase 12 — threat-intel & geo no-key + bridge MISP
    reg.register(shodan_internetdb.ShodanInternetDBConnector())
    reg.register(overpass.OverpassConnector())
    reg.register(threatfox.ThreatFoxConnector())
    reg.register(misp_client.MISPConnector())
    # Phase 13 — sostituti nativi di tool CLI esterni
    reg.register(content_discovery.ContentDiscoveryConnector())
    reg.register(port_scan.PortScanConnector())
    reg.register(subdomain_enum.SubdomainEnumConnector())
    reg.register(dnstwist_native.DNSTwistNativeConnector())
    reg.register(secret_scan.SecretScanConnector())
    reg.register(url_harvest.URLHarvestConnector())
    reg.register(holehe_native.HoleheNativeConnector())
    # Phase 14 — Maigret completo (motore username primario)
    reg.register(maigret.MaigretConnector())
    # Phase 15 — holehe completo (motore email primario)
    reg.register(holehe.HoleheConnector())
    # Phase 16 — theHarvester (dominio → email/host)
    reg.register(theharvester.TheHarvesterConnector())
    # Phase 17 — reverse lookup (telefono/social → email/registrazione)
    reg.register(phone_footprint.PhoneFootprintConnector())
    reg.register(ignorant.IgnorantConnector())
    reg.register(ghunt.GHuntConnector())
    reg.register(toutatis.ToutatisConnector())
    # Phase 18 — socid-extractor (URL → ID social)
    reg.register(socid_extractor_mod.SocidExtractorConnector())
    # Phase 19 — Telegram + LinkedIn2Username
    reg.register(telegram_checker.TelegramCheckerConnector())
    reg.register(linkedin2username.LinkedIn2UsernameConnector())
    # Phase 20 — Influencers Club (BYOK)
    reg.register(influencers_club.InfluencersClubConnector())
    # Phase 21 — legit_scorer nativo (SION-like): aggrega altri connettori.
    scorer = legit_scorer.LegitScorerConnector()
    scorer.bind_registry(reg)
    reg.register(scorer)
    # Phase 22 — darkweb_scan (Ahmia index, darkweb-gated).
    reg.register(darkweb_scan.DarkwebScanConnector())
    return reg
