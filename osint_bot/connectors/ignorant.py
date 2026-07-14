"""Connector: ignorant — numero di telefono → siti dove è REGISTRATO.

Gemello di holehe (stesso autore, megadose): dato un numero, verifica su quali
servizi (Instagram, Amazon, Snapchat, ...) esiste un account registrato con quel
numero, interrogando gli endpoint pubblici di reset/registrazione. No API key.

Config via env (nel .env sulla VM):
    IGNORANT_CMD      path eseguibile ignorant (es. /opt/argo-ignorant/.venv/bin/ignorant)
    IGNORANT_PYTHON   in alternativa, python del venv (usa -m ignorant)
    IGNORANT_TIMEOUT_S  timeout processo (default 90s)

Se non configurato -> status="missing_key".
Input: ``phone`` (E.164 preferibile). Passivo.
"""
from __future__ import annotations

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
    name="ignorant",
    label="ignorant (telefono → siti)",
    action_class=ACTION_PASSIVE,
    input_types=("phone",),
    output_categories=("phone_footprint",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=300, burst=1),
    legal_note="ignorant.legal_note",
    health_check_url="",
)

# Riga risultato: "[+] instagram.com". Guardia sul dominio (con punto) per
# escludere la legenda "[+] Phone used, ...".
_HIT_RE = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\s*$", re.IGNORECASE)


def _config() -> dict:
    return {
        "cmd": os.getenv("IGNORANT_CMD", ""),
        "python": os.getenv("IGNORANT_PYTHON", ""),
        "timeout_s": int(os.getenv("IGNORANT_TIMEOUT_S", "90") or "90"),
    }


def _split_number(raw: str) -> tuple[str, str] | None:
    """Ritorna (country_code, national_number) via libphonenumber. None se invalido."""
    try:
        import phonenumbers
        p = phonenumbers.parse(raw, "IT")
        if not phonenumbers.is_valid_number(p):
            return None
        return str(p.country_code), str(p.national_number)
    except Exception:
        return None


def _parse_stdout(text: str) -> list[str]:
    domains, seen = [], set()
    for line in (text or "").splitlines():
        m = _HIT_RE.match(line.strip())
        if m:
            d = m.group(1).lower()
            if d not in seen and d != "phone":
                seen.add(d)
                domains.append(d)
    return domains


class IgnorantConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"] and not cfg["python"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=_t("ignorant.not_configured", context.lang),
            )
        split = _split_number((context.target or "").strip())
        if not split:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("ignorant.invalid_number", context.lang))
        cc, nsn = split

        base = [cfg["cmd"]] if cfg["cmd"] else [cfg["python"], "-m", "ignorant"]
        argv = base + [cc, nsn, "--only-used", "--no-clear", "--no-color"]
        env = dict(os.environ); env["PYTHONUTF8"] = "1"; env["PYTHONIOENCODING"] = "utf-8"

        with tempfile.TemporaryDirectory(prefix="argo-ignorant-") as tmp:
            env["HOME"] = tmp
            try:
                proc = subprocess.run(argv, env=env, cwd=tmp, capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=cfg["timeout_s"], check=False)
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error", error=_t("ignorant.timeout", context.lang))
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("ignorant.execution_failed", context.lang, error=exc))

        domains = _parse_stdout(proc.stdout)
        findings = [Finding(
            kind="phone_registered", value=d,
            confidence=0.8, source_reliability="B", info_credibility=2,
            evidence=[Evidence(url=f"https://{d}", title=f"{d} (numero registrato)")],
            notes=_t("ignorant.registered_on", context.lang, domain=d),
            why_linked=[_t("ignorant.why_linked", context.lang, domain=d)],
        ) for d in domains]
        return ConnectorResult(
            connector=self.spec.name, status="ok", findings=findings,
            raw={"country_code": cc, "registered_on": domains, "count": len(domains), "engine": "ignorant"},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["cmd"] or cfg["python"])
