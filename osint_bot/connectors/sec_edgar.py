"""Connector: SEC EDGAR — US Securities and Exchange Commission company search.

Free, no key, but requires identifying User-Agent (SEC ToS).
"""
from __future__ import annotations

import urllib.parse

from .. import _safe_http
from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="sec_edgar",
    label="SEC EDGAR",
    action_class=ACTION_PASSIVE,
    input_types=("company",),
    output_categories=("corporate_registry",),
    required_key="",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=2),
    legal_note="sec_edgar.legal_note",
    health_check_url="https://efts.sec.gov/LATEST/search-index?q=apple&dateRange=custom&forms=10-K",
)


class SECEdgarConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        q = context.target.strip()
        url = (
            "https://efts.sec.gov/LATEST/search-index?"
            + urllib.parse.urlencode({"q": q, "hits": 5})
        )
        try:
            data = _safe_http.get_json(url, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang, service="SEC EDGAR", error=exc))
        hits = ((data or {}).get("hits") or {}).get("hits") or []
        findings: list[Finding] = []
        for h in hits[:5]:
            src = h.get("_source") or {}
            entities = src.get("display_names") or []
            forms = src.get("forms") or []
            cik = src.get("ciks") or []
            ev = [Evidence(
                url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik[0] if cik else ''}",
                title="SEC EDGAR")]
            findings.append(Finding(
                kind="sec_filing", value=" / ".join(entities[:2]),
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"SEC EDGAR: forms={forms}, CIK={cik}, file_date={src.get('file_date', '?')}",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"hits": len(hits)})

    def health_check(self) -> bool:
        return True
