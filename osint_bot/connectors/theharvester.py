"""Connector: theHarvester — raccolta passiva email/host/IP da un dominio.

A differenza di holehe (email->siti), theHarvester parte da un DOMINIO e
raccoglie da fonti pubbliche: email, sottodomini/host, IP, URL interessanti.
Integrato come connettore dominio (motore "OSINT aziendale").

Usa solo sorgenti SENZA API key per default (crt.sh, hackertarget, rapiddns,
certspotter, anubis, duckduckgo, urlscan, threatminer, ...). Passivo.

Config via env (nel .env sulla VM):
    THEHARVESTER_CMD      path eseguibile theHarvester (es. /opt/argo-theharvester/.venv/bin/theHarvester)
    THEHARVESTER_PYTHON   in alternativa, python del venv (usa -m theHarvester)
    THEHARVESTER_SOURCES  sorgenti separate da virgola (default: set no-key)
    THEHARVESTER_TIMEOUT_S  timeout processo (default 180s)

Se né CMD né PYTHON sono settati -> status="missing_key" (la piattaforma
continua con gli altri connettori dominio: crt_sh, subdomain_enum, dns_query).

Input: ``domain``. Passivo.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import tempfile

from ..i18n import t as _t
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
    name="theharvester",
    label="theHarvester (dominio → email/host)",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("emails", "subdomains", "hosts"),
    required_key="",  # tool locale via env; usa sorgenti no-key
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=4, per_day=200, burst=1),
    legal_note="theharvester.legal_note",
    health_check_url="",
)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
# Solo sorgenti VALIDE e no-key (verificate contro `theHarvester -h`).
# NB: nomi non validi fanno fallire l'INTERO run → qui teniamo solo quelli certi.
_DEFAULT_SOURCES = ("crtsh,hackertarget,rapiddns,certspotter,duckduckgo,urlscan,"
                    "subdomaincenter,subdomainfinderc99,dnsdumpster,commoncrawl,"
                    "waybackarchive,threatcrowd")
_FALLBACK_SOURCE = "crtsh"  # universale: usato se il run con la lista fallisce


def _config() -> dict:
    return {
        "cmd": os.getenv("THEHARVESTER_CMD", ""),
        "python": os.getenv("THEHARVESTER_PYTHON", ""),
        "sources": os.getenv("THEHARVESTER_SOURCES", _DEFAULT_SOURCES),
        "timeout_s": int(os.getenv("THEHARVESTER_TIMEOUT_S", "180") or "180"),
    }


def _build_argv(cfg: dict, domain: str, out_base: str) -> list[str]:
    base = [cfg["cmd"]] if cfg["cmd"] else [cfg["python"], "-m", "theHarvester"]
    return base + ["-d", domain, "-b", cfg["sources"], "-f", out_base]


def _parse_report(path: str) -> dict:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    def _as_list(key):
        v = data.get(key)
        return [str(x) for x in v] if isinstance(v, list) else []

    return {
        "emails": _as_list("emails"),
        "hosts": _as_list("hosts"),
        "ips": _as_list("ips"),
        "urls": _as_list("interesting_urls") or _as_list("urls"),
    }


class TheHarvesterConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"] and not cfg["python"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=_t("theharvester.not_configured", context.lang),
            )
        domain = (context.target or "").strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(domain):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("theharvester.invalid_domain", context.lang))

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        def _run(sources: str, tmp: str) -> tuple[dict, str]:
            out_base = os.path.join(tmp, "th")
            cfg2 = dict(cfg); cfg2["sources"] = sources
            argv = _build_argv(cfg2, domain, out_base)
            try:
                proc = subprocess.run(argv, env=env, cwd=tmp, capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=cfg["timeout_s"], check=False)
                out = (proc.stdout or "") + (proc.stderr or "")
            except subprocess.TimeoutExpired:
                out = "timeout"
            except (OSError, ValueError) as exc:
                return {}, f"__EXEC_ERROR__:{exc}"
            reports = glob.glob(os.path.join(tmp, "*.json"))
            return (_parse_report(reports[0]) if reports else {}), out

        with tempfile.TemporaryDirectory(prefix="argo-theharvester-") as tmp:
            env["HOME"] = tmp  # config/api-keys opzionali confinati qui
            parsed, out = _run(cfg["sources"], tmp)
            if out.startswith("__EXEC_ERROR__:"):
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("theharvester.exec_failed", context.lang, error=out.split(':', 1)[1]))
            # Fallback: se una sorgente non valida ha invalidato il run, riprova con crtsh.
            if not parsed and ("invalid source" in out.lower() or not glob.glob(os.path.join(tmp, "*.json"))):
                with tempfile.TemporaryDirectory(prefix="argo-th-fb-") as tmp2:
                    env["HOME"] = tmp2
                    parsed, _ = _run(_FALLBACK_SOURCE, tmp2)

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://crt.sh/?q=%25.{domain}", title="fonti passive")]
        for email in parsed.get("emails", [])[:100]:
            if "@" in email:
                findings.append(Finding(
                    kind="email", value=email,
                    confidence=0.8, source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=_t("theharvester.email_public", context.lang, domain=domain),
                    why_linked=[_t("theharvester.email_why", context.lang, domain=domain)],
                ))
        for host in parsed.get("hosts", [])[:200]:
            findings.append(Finding(
                kind="subdomain", value=host,
                confidence=0.75, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("theharvester.host_note", context.lang, domain=domain),
            ))
        for ip in parsed.get("ips", [])[:100]:
            findings.append(Finding(
                kind="ip", value=ip,
                confidence=0.7, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("theharvester.ip_note", context.lang, domain=domain),
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"emails": len(parsed.get("emails", [])),
                 "hosts": len(parsed.get("hosts", [])),
                 "ips": len(parsed.get("ips", [])),
                 "sources": cfg["sources"], "engine": "theHarvester"},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["cmd"] or cfg["python"])
