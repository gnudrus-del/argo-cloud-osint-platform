"""Connector: telegram-phone-number-checker (Bellingcat).

Dato un numero di telefono, verifica se corrisponde a un account Telegram
attivo. Restituisce username/nome/foto quando pubblici.

Richiede le credenziali API Telegram dell'INVESTIGATORE (api_id + api_hash
da https://my.telegram.org/apps) + numero di telefono associato al login.

Config via env (nel .env sulla VM):
    TELEGRAM_CMD             path eseguibile telegram-phone-number-checker
    TELEGRAM_API_ID          api_id Telegram
    TELEGRAM_API_HASH        api_hash Telegram
    TELEGRAM_PHONE           numero del proprio account (per il login pyrogram)
    TELEGRAM_TIMEOUT_S       default 90s

Senza CMD o senza le credenziali -> missing_key. Input: ``phone``. Passivo.
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
    name="telegram_checker",
    label="Telegram (numero → account)",
    action_class=ACTION_PASSIVE,
    input_types=("phone",),
    output_categories=("phone_footprint", "telegram"),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=4, per_day=150, burst=1),
    legal_note="telegram_checker.legal_note",
    health_check_url="",
)

_E164_RE = re.compile(r"^\+?\d{6,15}$")


def _config() -> dict:
    return {
        "cmd": os.getenv("TELEGRAM_CMD", ""),
        "api_id": os.getenv("TELEGRAM_API_ID", ""),
        "api_hash": os.getenv("TELEGRAM_API_HASH", ""),
        "phone": os.getenv("TELEGRAM_PHONE", ""),
        "timeout_s": int(os.getenv("TELEGRAM_TIMEOUT_S", "90") or "90"),
    }


class TelegramCheckerConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["cmd"]:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("telegram_checker.not_configured", context.lang))
        if not (cfg["api_id"] and cfg["api_hash"] and cfg["phone"]):
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=_t("telegram_checker.missing_credentials", context.lang))

        num = (context.target or "").strip().replace(" ", "")
        if not _E164_RE.match(num):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("telegram_checker.invalid_number", context.lang))

        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"; env["PYTHONIOENCODING"] = "utf-8"
        # La CLI legge api_id/api_hash/phone da .env nel cwd corrente.
        with tempfile.TemporaryDirectory(prefix="argo-tg-") as tmp:
            env["HOME"] = tmp
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write(f"API_ID={cfg['api_id']}\n")
                fh.write(f"API_HASH={cfg['api_hash']}\n")
                fh.write(f"PHONE_NUMBER={cfg['phone']}\n")
            out_json = os.path.join(tmp, "tg.json")
            argv = [cfg["cmd"], "--phone-numbers", num, "--output", out_json]
            try:
                subprocess.run(argv, env=env, cwd=tmp, capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=cfg["timeout_s"], check=False)
            except subprocess.TimeoutExpired:
                return ConnectorResult(connector=self.spec.name, status="error", error=_t("telegram_checker.timeout", context.lang))
            except (OSError, ValueError) as exc:
                return ConnectorResult(connector=self.spec.name, status="error",
                                       error=_t("telegram_checker.exec_failed", context.lang, error=exc))

            data = {}
            for path in glob.glob(os.path.join(tmp, "*.json")):
                try:
                    data = json.load(open(path, encoding="utf-8"))
                    break
                except Exception:
                    continue

        # La struttura di output può essere {num: {...}} o {"results": [...]}
        entry = None
        if isinstance(data, dict):
            if num in data:
                entry = data[num]
            elif "results" in data and isinstance(data["results"], list) and data["results"]:
                entry = data["results"][0]
            elif "id" in data or "username" in data:
                entry = data
        if not entry:
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": "Nessun account Telegram trovato o non risolvibile."})

        ev = [Evidence(url=(f"https://t.me/{entry['username']}" if entry.get("username")
                            else f"tg://user?id={entry.get('id','')}"),
                       title="Telegram")]
        findings: list[Finding] = []
        mapping = {
            "id": ("telegram_user_id", 0.95),
            "username": ("username", 0.9),
            "first_name": ("display_name", 0.85),
            "last_name": ("display_name_last", 0.75),
            "last_seen": ("telegram_last_seen", 0.7),
            "phone": ("phone", 0.85),
        }
        for key, (kind, conf) in mapping.items():
            v = entry.get(key)
            if v:
                findings.append(Finding(
                    kind=kind, value=str(v), confidence=conf,
                    source_reliability="A", info_credibility=1, evidence=ev,
                    notes=f"Telegram: campo '{key}' per il numero {num}.",
                    why_linked=[f"Telegram ha risolto il numero {num}"],
                ))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "telegram-checker", "fields": list(entry.keys())})

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["cmd"] and cfg["api_id"] and cfg["api_hash"] and cfg["phone"])
