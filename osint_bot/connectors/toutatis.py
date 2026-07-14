"""Connector: Toutatis — account Instagram → email/telefono (offuscati) + dati.

Dato uno username Instagram, Toutatis usa l'API mobile IG per estrarre: email
di recupero offuscata, telefono offuscato, obfuscated info, user id, ecc.
Richiede il ``sessionid`` di un account Instagram dell'INVESTIGATORE.

Config via env (nel .env sulla VM):
    TOUTATIS_CMD      path eseguibile toutatis (es. /opt/argo-toutatis/.venv/bin/toutatis)
    TOUTATIS_PYTHON   in alternativa, python del venv (usa -m toutatis)
    TOUTATIS_SESSION  sessionid Instagram dell'investigatore
    TOUTATIS_TIMEOUT_S  timeout processo (default 60s)

Senza CMD/PYTHON o senza SESSION -> missing_key.
Input: ``handle`` / ``username`` (username Instagram). Passivo.
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
    name="toutatis",
    label="Toutatis (Instagram → email/telefono)",
    action_class=ACTION_PASSIVE,
    input_types=("handle", "username"),
    output_categories=("email_footprint", "phone_footprint"),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="toutatis.legal_note",
    health_check_url="",
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,30}$")
# Righe tipiche dell'output Toutatis
_FIELD_RES = {
    "email_obfuscated": re.compile(r"Obfuscated email\s*:\s*(.+)", re.IGNORECASE),
    "phone_obfuscated": re.compile(r"Obfuscated phone\s*:\s*(.+)", re.IGNORECASE),
    "email": re.compile(r"(?<!Obfuscated )Email\s*:\s*(\S+@\S+)", re.IGNORECASE),
    "phone": re.compile(r"(?<!Obfuscated )Phone\s*(?:number)?\s*:\s*(\+?[\d ().\-]{5,})", re.IGNORECASE),
    "user_id": re.compile(r"(?:User ?ID|Id)\s*:\s*(\d+)", re.IGNORECASE),
    "full_name": re.compile(r"Full ?name\s*:\s*(.+)", re.IGNORECASE),
}


def _config() -> dict:
    return {
        "cmd": os.getenv("TOUTATIS_CMD", ""),
        "python": os.getenv("TOUTATIS_PYTHON", ""),
        "session": os.getenv("TOUTATIS_SESSION", ""),
        "timeout_s": int(os.getenv("TOUTATIS_TIMEOUT_S", "60") or "60"),
    }


def _parse(text: str) -> dict:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        for key, rx in _FIELD_RES.items():
            if key in out:
                continue
            m = rx.search(line)
            if m:
                out[key] = m.group(1).strip()
    return out


class ToutatisConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"] and not cfg["python"]:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("toutatis.not_configured", context.lang))
        if not cfg["session"]:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("toutatis.session_missing", context.lang))
        username = (context.target or "").strip().lstrip("@")
        if not _USERNAME_RE.match(username):
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("toutatis.invalid_username", context.lang))

        base = [cfg["cmd"]] if cfg["cmd"] else [cfg["python"], "-m", "toutatis"]
        argv = base + ["-u", username, "-s", cfg["session"]]
        env = dict(os.environ); env["PYTHONUTF8"] = "1"; env["PYTHONIOENCODING"] = "utf-8"

        with tempfile.TemporaryDirectory(prefix="argo-toutatis-") as tmp:
            env["HOME"] = tmp
            try:
                proc = subprocess.run(argv, env=env, cwd=tmp, capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=cfg["timeout_s"], check=False)
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error", error=_t("toutatis.timeout", context.lang))
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("toutatis.exec_failed", context.lang, exc=exc))

        parsed = _parse(proc.stdout)
        low = (proc.stdout + proc.stderr).lower()
        # Il tool è crashato (es. KeyError 'user' = IG non autentica la sessione,
        # o toutatis disallineato con l'API IG). NON è un "ok senza dati".
        if not parsed and (proc.returncode != 0 or "traceback" in low or "keyerror" in low):
            reason = ("sessione IG non valida/scaduta o toutatis non compatibile "
                      "con l'attuale API Instagram")
            if "rate" in low:
                reason = "rate-limit Instagram"
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Toutatis non funzionante: {reason}.")
        if not parsed and ("session" in low or "login" in low or "rate" in low):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Toutatis: sessione IG non valida o rate-limit.")

        ev = [Evidence(url=f"https://www.instagram.com/{username}/", title=f"Instagram @{username}")]
        findings: list[Finding] = []
        for key, kind, note in [
            ("email", "email", "Email associata all'account IG (Toutatis)."),
            ("email_obfuscated", "email_recovery_hint", "Email di recupero offuscata (IG)."),
            ("phone", "phone", "Telefono associato all'account IG (Toutatis)."),
            ("phone_obfuscated", "phone_recovery_hint", "Telefono di recupero offuscato (IG)."),
            ("full_name", "display_name", "Nome dal profilo IG."),
            ("user_id", "instagram_user_id", "User ID Instagram."),
        ]:
            if parsed.get(key):
                findings.append(Finding(
                    kind=kind, value=parsed[key],
                    confidence=0.85 if key in ("email", "phone", "user_id") else 0.7,
                    source_reliability="B", info_credibility=2, evidence=ev, notes=note,
                    why_linked=[f"Estratto da Instagram @{username} via Toutatis"],
                ))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "toutatis", "fields": list(parsed.keys())})

    def health_check(self) -> bool:
        cfg = _config()
        return bool((cfg["cmd"] or cfg["python"]) and cfg["session"])
