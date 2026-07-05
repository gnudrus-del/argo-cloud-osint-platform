"""Connector: UK Companies House — official UK companies register.

Requires free API key (HTTP basic auth username = key, no password).

Action class: passive. Input: ``company``.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
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
    name="companies_house",
    label="UK Companies House",
    action_class=ACTION_PASSIVE,
    input_types=("company",),
    output_categories=("corporate_registry",),
    required_key="companies_house",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=20, per_day=600, burst=3),
    legal_note="Companies House: registro ufficiale aziende UK.",
    health_check_url="https://api.company-information.service.gov.uk/",
)


class CompaniesHouseConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="Companies House richiede API key (free).")
        q = urllib.parse.quote(context.target.strip())
        url = f"https://api.company-information.service.gov.uk/search/companies?q={q}&items_per_page=5"
        auth = base64.b64encode(f"{context.api_key}:".encode("ascii")).decode("ascii")
        req = urllib.request.Request(url, headers={
            "Authorization": f"Basic {auth}", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Companies House: {exc}")
        items = (data or {}).get("items") or []
        findings: list[Finding] = []
        for it in items[:5]:
            num = it.get("company_number", "")
            name = it.get("title", "")
            ev = [Evidence(
                url=f"https://find-and-update.company-information.service.gov.uk/company/{num}",
                title="Companies House")]
            findings.append(Finding(
                kind="company_record", value=f"{name} (UK {num})",
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"Companies House: status={it.get('company_status', '?')}, "
                      f"creata={it.get('date_of_creation', '?')}, "
                      f"address={it.get('address_snippet', '')}",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"total": len(items)})

    def health_check(self) -> bool:
        return False
