"""Connector package — all Pillar 1 connector implementations.

Usage:
    from osint_bot.connectors import build_default_registry
    registry = build_default_registry()
"""
from __future__ import annotations
from ..connector import ConnectorRegistry
from . import abuseipdb, crt_sh, github_search, hibp, hunter, leakix, rdap, shodan, urlscan, virustotal, wayback

__all__ = [
    "abuseipdb", "crt_sh", "github_search", "hibp", "hunter",
    "leakix", "rdap", "shodan", "urlscan", "virustotal", "wayback",
    "build_default_registry",
]


def build_default_registry() -> ConnectorRegistry:
    """Build and return a pre-populated ConnectorRegistry with all bundled connectors."""
    reg = ConnectorRegistry()
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
    return reg
