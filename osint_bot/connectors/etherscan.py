"""Connector: Etherscan — Ethereum wallet basic info.

Free key (BYOK). Returns balance + tx count.

Action class: passive. Input: ``wallet`` (Ethereum address, 0x...).
"""
from __future__ import annotations

import re

from .. import _safe_http
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
    name="etherscan",
    label="Etherscan",
    action_class=ACTION_PASSIVE,
    input_types=("crypto", "wallet"),
    output_categories=("crypto_chain",),
    required_key="etherscan",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=5, per_day=100_000, burst=2),
    legal_note="Etherscan: dati pubblici on-chain Ethereum. Solo lettura.",
    health_check_url="https://api.etherscan.io/api",
)

_ETH_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class EtherscanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = context.target.strip()
        if not _ETH_ADDR_RE.match(target):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Etherscan: indirizzo ETH non valido (0x + 40 hex).")
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="Etherscan richiede API key (free).")
        findings: list[Finding] = []
        ev = [Evidence(url=f"https://etherscan.io/address/{target}", title="Etherscan")]
        for module, action, kind in [
            ("account", "balance", "eth_balance"),
            ("account", "txlist",  "eth_tx_count"),
        ]:
            url = (f"https://api.etherscan.io/api?module={module}&action={action}"
                   f"&address={target}&tag=latest&apikey={context.api_key}&offset=1&page=1")
            try:
                data = _safe_http.get_json(url, timeout=context.timeout)
            except Exception as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=f"Etherscan: {exc}")
            if action == "balance":
                wei = int(data.get("result", "0") or 0)
                eth = wei / 1e18
                findings.append(Finding(
                    kind=kind, value=f"{eth:.6f} ETH",
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=ev,
                    notes=f"Etherscan: balance corrente = {eth:.6f} ETH ({wei} wei)",
                ))
            else:
                result = data.get("result") or []
                findings.append(Finding(
                    kind=kind, value=str(len(result) > 0),
                    confidence=0.90, source_reliability="A", info_credibility=1,
                    evidence=ev,
                    notes=f"Etherscan: wallet ha {'transazioni' if result else 'NESSUNA transazione'}.",
                ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={})

    def health_check(self) -> bool:
        return False
