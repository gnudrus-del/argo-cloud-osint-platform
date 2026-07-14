"""Connector: GHunt — email Gmail/Google → profilo account Google.

Dato un indirizzo Google, GHunt recupera: nome, Gaia ID, foto, servizi Google
usati, recensioni Maps pubbliche, ecc. Richiede l'AUTENTICAZIONE Google
dell'investigatore (GHunt salva le cred con ``ghunt login``).

Config via env (nel .env sulla VM):
    GHUNT_CMD      path eseguibile ghunt (es. /opt/argo-ghunt/.venv/bin/ghunt)
    GHUNT_PYTHON   in alternativa, python del venv (usa -m ghunt)
    GHUNT_HOME     dir usata come HOME (deve contenere le cred: .malfrats/ghunt/creds.m)
    GHUNT_TIMEOUT_S  timeout processo (default 60s)

Senza CMD/PYTHON -> missing_key. Senza cred valide GHunt fallirà: lo segnaliamo.
Input: ``email``. Passivo.
"""
from __future__ import annotations

import glob
import json
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
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="ghunt",
    label="GHunt (email → account Google)",
    action_class=ACTION_PASSIVE,
    input_types=("email",),
    output_categories=("google_account",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="ghunt.legal_note",
    health_check_url="",
)

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _config() -> dict:
    return {
        "cmd": os.getenv("GHUNT_CMD", ""),
        "python": os.getenv("GHUNT_PYTHON", ""),
        "home": os.getenv("GHUNT_HOME", ""),
        "timeout_s": int(os.getenv("GHUNT_TIMEOUT_S", "60") or "60"),
    }


class GHuntConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"] and not cfg["python"]:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("ghunt.not_configured", context.lang))
        if not cfg["home"]:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("ghunt.home_missing", context.lang))
        email = (context.target or "").strip().lower()
        if not _EMAIL_RE.match(email):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.invalid_email", context.lang))

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"; env["PYTHONIOENCODING"] = "utf-8"
        env["HOME"] = cfg["home"]  # GHunt legge .malfrats/ghunt/creds.m da HOME

        with tempfile.TemporaryDirectory(prefix="argo-ghunt-") as tmp:
            out_json = os.path.join(tmp, "ghunt.json")
            base = [cfg["cmd"]] if cfg["cmd"] else [cfg["python"], "-m", "ghunt"]
            argv = base + ["email", email, "--json", out_json]
            try:
                proc = subprocess.run(argv, env=env, cwd=tmp, capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=cfg["timeout_s"], check=False)
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("ghunt.timeout", context.lang))
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("ghunt.exec_failed", context.lang, error=str(exc)))

            data = {}
            files = glob.glob(os.path.join(tmp, "*.json"))
            if files:
                try:
                    data = json.load(open(files[0], encoding="utf-8"))
                except Exception:
                    data = {}
            if not data:
                # Nessun JSON: cred mancanti/scadute o account inesistente.
                low = (proc.stdout + proc.stderr).lower()
                if "login" in low or "cookies" in low or "creds" in low:
                    return ConnectorResult(connector=self.spec.name, status="error",
                                           error=_t("ghunt.creds_expired", context.lang))
                return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                       raw={"note": _t("ghunt.no_data", context.lang)})

        findings: list[Finding] = []
        ev = [Evidence(url="https://mail.google.com", title="Google account")]
        name = (data.get("PROFILE_CONTAINER") or {}).get("profile", {}).get("names") if isinstance(data, dict) else None
        # Best-effort: struttura GHunt varia per versione; estraggo campi comuni.
        def _dig(d, *keys):
            for k in keys:
                if isinstance(d, dict) and k in d:
                    d = d[k]
                else:
                    return None
            return d
        gaia = _dig(data, "PROFILE_CONTAINER", "profile", "personId") or data.get("gaiaID")
        if gaia:
            findings.append(Finding(kind="google_gaia_id", value=str(gaia), confidence=0.9,
                                    source_reliability="A", info_credibility=1, evidence=ev,
                                    notes=f"Gaia ID Google per {email}."))
        display = None
        if isinstance(name, list) and name:
            display = name[0].get("fullname") if isinstance(name[0], dict) else None
        display = display or data.get("name")
        if display:
            findings.append(Finding(kind="display_name", value=str(display), confidence=0.85,
                                    source_reliability="A", info_credibility=2, evidence=ev,
                                    notes="Nome dal profilo Google."))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "ghunt", "has_data": bool(findings)})

    def health_check(self) -> bool:
        cfg = _config()
        if not ((cfg["cmd"] or cfg["python"]) and cfg["home"]):
            return False
        # 'ok' solo se le credenziali esistono (ghunt login completato).
        import glob
        return bool(glob.glob(os.path.join(cfg["home"], "**", "creds.m"), recursive=True))
