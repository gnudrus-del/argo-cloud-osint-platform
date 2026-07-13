"""Connector: crt.sh — Certificate Transparency log search.

Queries the public crt.sh JSON API to enumerate subdomains and certificate
metadata for a domain.  No API key required; free and passive.

Output: ``subdomain_ct`` findings, one per unique FQDN found in CT logs.
Action class: passive.
"""
from __future__ import annotations

import json
import re
import urllib.request

from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="crt_sh",
    label="crt.sh (Certificate Transparency)",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("network_identifiers",),
    required_key="",
    cache_ttl=3600,  # 1 h — CT logs change slowly
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=3),
    legal_note="Public Certificate Transparency logs. No ToS restrictions for passive lookup.",
    health_check_url="https://crt.sh/?q=example.com&output=json",
)

# Pattern to detect wildcards and keep only real FQDNs
_WILDCARD_RE = re.compile(r"^\*\.")


class CrtShConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = context.target.lower().strip()
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Argo-OSINT/1.0 (passive CT lookup)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error", error=str(exc))

        if not isinstance(data, list):
            return ConnectorResult(
                connector=self.spec.name,
                status="error",
                error="crt.sh returned unexpected format",
                raw={"response": str(data)[:200]},
            )

        # Extract unique FQDNs (skip wildcards, skip the base domain itself)
        seen: set[str] = set()
        findings: list[Finding] = []
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower()
                if not name or _WILDCARD_RE.match(name) or name == target:
                    continue
                if not name.endswith(f".{target}") and name != target:
                    continue
                if name in seen:
                    continue
                seen.add(name)
                findings.append(
                    Finding(
                        kind="subdomain_ct",
                        value=name,
                        confidence=0.80,  # FIRM: CT log entry = direct observation
                        source_reliability="C",   # C = fairly reliable (public registry)
                        info_credibility=2,       # 2 = probably true
                        evidence=[Evidence(
                            url=f"https://crt.sh/?q={name}",
                            title="crt.sh CT log",
                            quote=f"issuer_ca={entry.get('issuer_ca_id','?')} not_before={entry.get('not_before','')}",
                        )],
                        notes=f"Rilevato in Certificate Transparency logs. Cert emesso da CA {entry.get('issuer_ca_id','?')}.",
                    )
                )
                if len(findings) >= 500:
                    break
            if len(findings) >= 500:
                break

        return ConnectorResult(
            connector=self.spec.name,
            status="ok",
            findings=findings,
            raw={"count": len(data), "unique_fqdns": len(seen)},
        )

    def health_check(self) -> bool:
        try:
            req = urllib.request.Request(
                "https://crt.sh/?q=example.com&output=json",
                headers={"User-Agent": "Argo-OSINT/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False
