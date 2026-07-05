"""Connector: Maigret — motore username COMPLETO (~3166 siti) sulla piattaforma.

Per gli username una reimplementazione nativa fedele di migliaia di detection
per-sito non è onesta: Maigret è il programma completo affidabile. Questo
connettore lo integra nella piattaforma via subprocess + report JSON, così
diventa il motore primario username di Argo (``sherlock_lite`` resta il
fallback veloce ad alta precisione su pochi siti).

Config via env (nel .env sulla VM):
    MAIGRET_PYTHON   path del python del venv Maigret (es. /opt/argo-maigret/.venv/bin/python)
    MAIGRET_CMD      in alternativa, path dell'eseguibile 'maigret'
    MAIGRET_TIMEOUT_S   timeout complessivo del processo (default 240s)
    MAIGRET_TOP_SITES   opzionale: limita ai top-N siti (più veloce su VM piccole)

Se né MAIGRET_PYTHON né MAIGRET_CMD sono settati -> status="missing_key"
(la piattaforma continua col fallback sherlock_lite).

Input: ``handle`` / ``username``. Passivo.
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
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="maigret",
    label="Maigret (username, completo)",
    action_class=ACTION_PASSIVE,
    input_types=("handle", "username"),
    output_categories=("social_accounts",),
    required_key="",  # tool locale via env, non BYOK
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=4, per_day=200, burst=1),
    legal_note="Esegue Maigret in locale su URL pubbliche. Nessun login. Solo profili 'Claimed'.",
    health_check_url="",
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def _config() -> dict:
    return {
        "python": os.getenv("MAIGRET_PYTHON", ""),
        "cmd": os.getenv("MAIGRET_CMD", ""),
        "timeout_s": int(os.getenv("MAIGRET_TIMEOUT_S", "240") or "240"),
        "top_sites": os.getenv("MAIGRET_TOP_SITES", ""),
        # HOME scrivibile per la cache DB di Maigret (~/.maigret). Necessario
        # perché il service systemd gira con ProtectHome=true. Se non settato,
        # si usa la tempdir privata (Maigret riscarica il DB a ogni run).
        "home": os.getenv("MAIGRET_HOME", ""),
    }


def _build_argv(cfg: dict, username: str, outdir: str) -> list[str]:
    if cfg["python"]:
        base = [cfg["python"], "-m", "maigret"]
    else:
        base = [cfg["cmd"]]
    argv = base + [
        username,
        "--timeout", "12",
        "--no-recursion",
        "--json", "simple",
        "--folderoutput", outdir,
    ]
    if cfg["top_sites"]:
        argv += ["--top-sites", str(cfg["top_sites"])]
    return argv


def _parse_report(path: str) -> list[dict]:
    """Estrae i profili 'Claimed' dal report JSON 'simple' di Maigret."""
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return []
    claimed: list[dict] = []
    if isinstance(data, dict):
        for site, v in data.items():
            if not isinstance(v, dict):
                continue
            st = v.get("status")
            is_claimed = (isinstance(st, dict) and st.get("status") == "Claimed") or st == "Claimed"
            if is_claimed:
                claimed.append({
                    "site": site,
                    "url": v.get("url_user") or v.get("url") or "",
                    "tags": (st.get("tags") if isinstance(st, dict) else None) or [],
                    "ids": (st.get("ids") if isinstance(st, dict) else None) or {},
                })
    return claimed


class MaigretConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["python"] and not cfg["cmd"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=("Maigret non configurato. Setta MAIGRET_PYTHON (o MAIGRET_CMD) "
                       "nel .env. Fallback: sherlock_lite."),
            )
        username = (context.target or "").strip()
        if not _USERNAME_RE.match(username):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Username non valido.")

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"          # evita il crash cp1252 su Windows/console
        env["PYTHONIOENCODING"] = "utf-8"

        with tempfile.TemporaryDirectory(prefix="argo-maigret-") as outdir:
            # HOME scrivibile per la cache DB (~/.maigret); fallback: la tempdir.
            env["HOME"] = cfg["home"] or outdir
            argv = _build_argv(cfg, username, outdir)
            try:
                subprocess.run(
                    argv, env=env, capture_output=True,
                    timeout=cfg["timeout_s"], check=False,
                )
            except subprocess.TimeoutExpired:
                # Timeout: proviamo comunque a leggere un report parziale, se c'è.
                pass
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=f"Esecuzione Maigret fallita: {exc}")

            reports = glob.glob(os.path.join(outdir, "report_*_simple.json"))
            if not reports:
                return ConnectorResult(
                    connector=self.spec.name, status="ok", findings=[],
                    raw={"note": "Maigret non ha prodotto report (0 risultati o timeout)."},
                )
            claimed = _parse_report(reports[0])

        findings: list[Finding] = []
        for c in claimed:
            if not c["url"]:
                continue
            tag_note = f" Tag: {', '.join(c['tags'][:5])}." if c["tags"] else ""
            findings.append(Finding(
                kind="social_account", value=c["url"],
                confidence=0.9, source_reliability="A", info_credibility=1,
                evidence=[Evidence(url=c["url"], title=f"{c['site']} — {username}")],
                notes=(f"Profilo confermato da Maigret su {c['site']} "
                       f"(detection per-sito).{tag_note}"),
                why_linked=[f"Maigret ha marcato '{username}' come Claimed su {c['site']}"],
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"claimed": len(findings), "engine": "maigret"},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["python"] or cfg["cmd"])
