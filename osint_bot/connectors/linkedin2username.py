"""Connector: linkedin2username (initstring) — azienda → username aziendali.

Data un'azienda LinkedIn e un dominio, genera una lista di **probabili
username aziendali** (prima.cognome / p.cognome / ecc.) partendo dai profili
LinkedIn pubblici. Utile per OSINT su target aziendali.

Richiede il login LinkedIn dell'INVESTIGATORE (username+password del proprio
account); lo strumento naviga LinkedIn come utente autenticato.

Config via env:
    LINKEDIN2U_PYTHON        python del venv (obbligatorio)
    LINKEDIN2U_SCRIPT        path linkedin2username.py (obbligatorio)
    LINKEDIN_USER            email/username LinkedIn dell'investigatore
    LINKEDIN_PASS            password LinkedIn dell'investigatore
    LINKEDIN2U_TIMEOUT_S     default 240s

Senza tool o senza credenziali -> missing_key.
Input: ``company`` nel formato "AcmeCorp" oppure "AcmeCorp|acme.com" (nome LinkedIn | dominio email).
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile

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
    name="linkedin2username",
    label="LinkedIn2Username (azienda → username)",
    action_class=ACTION_PASSIVE,
    input_types=("company", "domain"),
    output_categories=("username_lists",),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=1, per_day=20, burst=1),
    legal_note="Naviga LinkedIn come utente autenticato dell'investigatore. Solo profili pubblici della company.",
    health_check_url="",
)

_COMPANY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-\. ]{0,60}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


def _config() -> dict:
    return {
        "python": os.getenv("LINKEDIN2U_PYTHON", ""),
        "script": os.getenv("LINKEDIN2U_SCRIPT", ""),
        "user": os.getenv("LINKEDIN_USER", ""),
        "password": os.getenv("LINKEDIN_PASS", ""),
        "timeout_s": int(os.getenv("LINKEDIN2U_TIMEOUT_S", "240") or "240"),
    }


class LinkedIn2UsernameConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not (cfg["python"] and cfg["script"]):
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="linkedin2username non configurato (LINKEDIN2U_PYTHON/SCRIPT).")
        if not (cfg["user"] and cfg["password"]):
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="Credenziali LinkedIn mancanti (LINKEDIN_USER/LINKEDIN_PASS).")

        raw = (context.target or "").strip()
        if "|" in raw:
            company, _, domain = raw.partition("|")
            company, domain = company.strip(), domain.strip()
        else:
            company, domain = raw, ""
        if not _COMPANY_RE.match(company):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Nome azienda non valido (max 60 char alfanumerici).")
        if domain and not _DOMAIN_RE.match(domain):
            return ConnectorResult(connector=self.spec.name, status="error", error="Dominio non valido.")

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"; env["PYTHONIOENCODING"] = "utf-8"

        with tempfile.TemporaryDirectory(prefix="argo-l2u-") as tmp:
            env["HOME"] = tmp
            argv = [cfg["python"], cfg["script"], "-c", company, "-o", tmp]
            if domain:
                argv += ["-n", domain]
            # linkedin2username chiede user/pass su stdin
            try:
                proc = subprocess.run(argv, env=env, cwd=tmp,
                                      input=f"{cfg['user']}\n{cfg['password']}\n",
                                      capture_output=True, text=True,
                                      encoding="utf-8", errors="replace",
                                      timeout=cfg["timeout_s"], check=False)
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error", error="linkedin2username timeout.")
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=f"Esecuzione linkedin2username fallita: {exc}")

            low = (proc.stdout + proc.stderr).lower()
            if "login" in low and ("failed" in low or "invalid" in low):
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error="Login LinkedIn fallito o account bloccato (challenge?).")

            # linkedin2username scrive più liste (.txt); leggo tutti gli username unici.
            unames: set[str] = set()
            for path in glob.glob(os.path.join(tmp, "*.txt")):
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            u = line.strip()
                            if u and " " not in u and "@" not in u:
                                unames.add(u)
                except Exception:
                    continue

        ev = [Evidence(url=f"https://www.linkedin.com/company/{company}", title=f"LinkedIn/{company}")]
        findings = [Finding(
            kind="probable_username", value=u,
            confidence=0.6, source_reliability="B", info_credibility=3,
            evidence=ev,
            notes=(f"Username candidato per {company} (probabile). Da confermare con maigret/holehe."),
        ) for u in sorted(unames)[:300]]
        return ConnectorResult(
            connector=self.spec.name, status="ok", findings=findings,
            raw={"engine": "linkedin2username", "company": company, "domain": domain,
                 "count": len(unames)},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["python"] and cfg["script"] and cfg["user"] and cfg["password"])
