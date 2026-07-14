"""Connector: holehe — motore email COMPLETO (~121 siti) sulla piattaforma.

Come per gli username con Maigret, per le email il programma completo affidabile
è holehe: verifica su quali servizi un'email risulta REGISTRATA interrogando gli
endpoint pubblici di reset/registrazione. Questo connettore lo integra via
subprocess, così diventa il motore email primario di Argo (``holehe_native``
resta il fallback veloce: Gravatar/MX/disposable/canonical).

Config via env (nel .env sulla VM):
    HOLEHE_CMD       path dell'eseguibile holehe (es. /opt/argo-holehe/.venv/bin/holehe)
    HOLEHE_PYTHON    in alternativa, python del venv holehe (usa -m holehe)
    HOLEHE_TIMEOUT_S timeout complessivo del processo (default 120s)

Se né HOLEHE_CMD né HOLEHE_PYTHON sono settati -> status="missing_key"
(la piattaforma continua col fallback holehe_native).

Input: ``email``. Passivo.
"""
from __future__ import annotations

import csv
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
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="holehe",
    label="holehe (email, completo)",
    action_class=ACTION_PASSIVE,
    input_types=("email",),
    output_categories=("email_footprint",),
    required_key="",  # tool locale via env, non BYOK
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=300, burst=1),
    legal_note="holehe.legal_note",
    health_check_url="",
)

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Riga di risultato holehe: "[+] amazon.com". Richiedo un dominio (con punto)
# per escludere la legenda "[+] Email used, ...".
_HIT_RE = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\s*$", re.IGNORECASE)


def _config() -> dict:
    return {
        "cmd": os.getenv("HOLEHE_CMD", ""),
        "python": os.getenv("HOLEHE_PYTHON", ""),
        "timeout_s": int(os.getenv("HOLEHE_TIMEOUT_S", "120") or "120"),
    }


def _build_argv(cfg: dict, email: str) -> list[str]:
    if cfg["cmd"]:
        base = [cfg["cmd"]]
    else:
        base = [cfg["python"], "-m", "holehe"]
    # -C esporta anche un CSV (con colonne emailrecovery/phoneNumber) che parsiamo
    # per gli hint di recupero, oltre alle righe [+] su stdout per i siti usati.
    return base + [email, "--only-used", "--no-clear", "--no-color", "-C"]


def _parse_recovery_csv(csv_dir: str) -> list[dict]:
    """Estrae hint di recupero dal CSV holehe: righe con emailrecovery/phoneNumber."""
    hits: list[dict] = []
    for path in glob.glob(os.path.join(csv_dir, "*.csv")):
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.DictReader(fh):
                    exists = str(row.get("exists", "")).strip().lower() == "true"
                    if not exists:
                        continue
                    domain = (row.get("domain") or row.get("name") or "").strip()
                    er = (row.get("emailrecovery") or "").strip()
                    pr = (row.get("phoneNumber") or "").strip()
                    if er and er.lower() not in ("none", "false", ""):
                        hits.append({"domain": domain, "kind": "email_recovery_hint", "value": er})
                    if pr and pr.lower() not in ("none", "false", ""):
                        hits.append({"domain": domain, "kind": "phone_recovery_hint", "value": pr})
        except Exception:
            continue
    return hits


def _parse_stdout(text: str) -> list[str]:
    """Estrae i domini dove l'email risulta usata dalle righe '[+] dominio'."""
    domains: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        m = _HIT_RE.match(line.strip())
        if m:
            d = m.group(1).lower()
            if d not in seen and d != "email":  # guardia extra sulla legenda
                seen.add(d)
                domains.append(d)
    return domains


class HoleheConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"] and not cfg["python"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=_t("holehe.not_configured", context.lang),
            )
        email = (context.target or "").strip().lower()
        if not _EMAIL_RE.match(email):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.invalid_email", context.lang))

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        with tempfile.TemporaryDirectory(prefix="argo-holehe-") as tmp:
            env["HOME"] = tmp  # difensivo: eventuali scritture restano confinate
            argv = _build_argv(cfg, email)
            try:
                proc = subprocess.run(
                    argv, env=env, cwd=tmp, capture_output=True,
                    text=True, encoding="utf-8", errors="replace",
                    timeout=cfg["timeout_s"], check=False,
                )
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("holehe.timeout", context.lang))
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("holehe.execution_failed", context.lang, error=str(exc)))

            domains = _parse_stdout(proc.stdout)
            recovery = _parse_recovery_csv(tmp)  # dentro il with: il CSV è in tmp

        findings: list[Finding] = []
        for d in domains:
            findings.append(Finding(
                kind="email_registered", value=d,
                confidence=0.85, source_reliability="B", info_credibility=2,
                evidence=[Evidence(url=f"https://{d}", title=_t("holehe.evidence_title_registered", context.lang, domain=d))],
                notes=_t("holehe.registered_notes", context.lang, domain=d),
                why_linked=[_t("holehe.registered_why_linked", context.lang, email=email, domain=d)],
            ))
        # Hint di recupero (email/telefono mascherati esposti da alcuni siti).
        for h in recovery:
            if "email" in h["kind"]:
                notes_text = _t("holehe.recovery_hint_email_notes", context.lang, domain=h["domain"], email=email)
            else:
                notes_text = _t("holehe.recovery_hint_phone_notes", context.lang, domain=h["domain"], email=email)
            findings.append(Finding(
                kind=h["kind"], value=f"{h['value']} (via {h['domain']})",
                confidence=0.7, source_reliability="B", info_credibility=2,
                evidence=[Evidence(url=f"https://{h['domain']}", title=h["domain"])],
                notes=notes_text,
                why_linked=[_t("holehe.recovery_why_linked", context.lang, domain=h["domain"], email=email)],
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"registered_on": domains, "count": len(domains),
                 "recovery_hints": len(recovery), "engine": "holehe"},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["cmd"] or cfg["python"])
