"""HighRiskResearchMode — modalita' OPSEC rafforzata auto-attivata.

Fase 3 dello spec Argo. Centralizza in un solo posto:

  1) Detection automatica dei contesti ad alto rischio (dark/deep web, onion,
     leak/breach/marketplace, red team, asset tecnici sensibili, keyword di
     rischio nell'input).
  2) Policy di restrizione: cosa NON e' consentito quando la modalita' e'
     attiva (no download automatici, no interazioni attive, no credenziali
     personali, niente esecuzione di JS/plugin/redirect, contenuti read-only).
  3) Sanitizzazione difensiva di output testo/URL/filename pensata per:
       - evitare prompt-injection nei job AI;
       - bonificare HTML/URL prima di mostrarli in UI/report;
       - normalizzare nomi-file in eventuale quarantena.

Il modulo e' deliberatamente puro: nessun side effect su rete o filesystem,
nessun import opzionale. Tutto e' testabile a tavolino. Le decisioni di policy
sono enumerate come dati (non come "if" sparsi), cosi' la UI puo' mostrare
all'utente l'esatto elenco delle restrizioni attive.
"""
from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Trigger di auto-attivazione (spec: 5 categorie)
# ---------------------------------------------------------------------------

HIGH_RISK_KEYWORDS: tuple[str, ...] = (
    "leak", "leaked", "breach", "data breach", "credential dump",
    "stealer log", "stealer logs", "combolist", "combo list",
    "paste site", "pastebin dump", "marketplace", "darknet market",
    "ransom", "ransomware", "carding", "cardable", "fullz", "dox",
)

SENSITIVE_TECH_PATTERNS: tuple[str, ...] = (
    r"\bvpn\b", r"\bsso\b", r"\bsamlsso\b",
    r"\badmin\b", r"\blogin\b", r"\bauth\b",
    r"\bapi\b", r"\bgit\b", r"\bjenkins\b",
    r"\bbastion\b", r"\bjump\b", r"\bvault\b",
    r"\bidp\b", r"\boidc\b",
)
_SENSITIVE_RE = re.compile("|".join(SENSITIVE_TECH_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Policy — restrizioni applicate (dati, non if). La UI legge questa lista.
# ---------------------------------------------------------------------------

DEFAULT_RESTRICTIONS: tuple[tuple[str, str], ...] = (
    ("read_only",          "Ricerca in modalita' passiva: nessuna interazione con servizi o soggetti."),
    ("no_auto_download",   "Nessun download automatico di file, archivi, eseguibili o documenti."),
    ("no_active_login",    "Nessun login, registrazione, messaggio o acquisto su fonti ad alto rischio."),
    ("no_user_identity",   "Nessun cookie, fingerprint, email o numero personali inviati alle fonti."),
    ("no_leaked_creds",    "Le credenziali trapelate non vengono usate per testare accessi."),
    ("no_active_scan",     "Nessuna enumerazione attiva, brute force, scan invasivo o exploit."),
    ("isolated_jobs",      "Job dark/deep web isolati dalla pipeline applicativa normale."),
    ("sanitized_outputs",  "Output (HTML, URL, allegati, nomi file) sanitizzati prima della visualizzazione."),
    ("prompt_isolation",   "Risultati ad alto rischio delimitati e sanitizzati prima di entrare in prompt AI."),
    ("minimal_evidence",   "Solo metadati minimi salvati: fonte, timestamp, hash, confidence, retention."),
    ("audit_logged",       "Ogni attivazione viene registrata nell'audit log con motivo."),
)

OPSEC_BANNER_IT = (
    "Modalita' OPSEC attiva: ricerca passiva, ambiente isolato, "
    "nessuna interazione con soggetti o servizi illeciti."
)


@dataclass(frozen=True)
class HighRiskContext:
    """Risultato della detection. Immutabile, JSON-serializable."""
    active: bool
    reasons: tuple[str, ...] = ()
    restrictions: tuple[tuple[str, str], ...] = ()
    banner: str = ""

    def to_dict(self) -> dict:
        return {
            "active": self.active,
            "reasons": list(self.reasons),
            "restrictions": [{"key": k, "label": v} for k, v in self.restrictions],
            "banner": self.banner,
        }


# ---------------------------------------------------------------------------
# Detection — 5 trigger dello spec
# ---------------------------------------------------------------------------

def detect_high_risk(
    *,
    target: str = "",
    target_type: str = "",
    command: str = "",
    modules: list[str] | tuple[str, ...] | None = None,
    allow_darkweb: bool = False,
    seed_urls: list[str] | tuple[str, ...] | None = None,
) -> HighRiskContext:
    """Decide se attivare la modalita' OPSEC rafforzata.

    Trigger (uno qualunque attiva la modalita'):

      1. l'utente ha selezionato red team (modules contiene 'red_team');
      2. l'utente ha autorizzato dark/deep web (allow_darkweb=True) o ha
         selezionato il modulo 'darkweb';
      3. il target o uno dei seed URL e' un indirizzo .onion;
      4. il target/command contiene keyword tipiche di leak/breach/marketplace;
      5. il target ha forma di asset tecnico sensibile (vpn., admin., api., ...).

    La funzione e' pura: dati in ingresso -> contesto in uscita, niente piu'.
    """
    reasons: list[str] = []
    mods = {m.lower() for m in (modules or [])}
    target_l = (target or "").lower()
    command_l = (command or "").lower()
    seeds = list(seed_urls or [])

    if "red_team" in mods:
        reasons.append("modulo red team selezionato")

    if allow_darkweb or "darkweb" in mods:
        reasons.append("modulo dark/deep web autorizzato")

    if ".onion" in target_l:
        reasons.append("target su rete onion")
    onion_seeds = [u for u in seeds if ".onion" in (u or "").lower()]
    if onion_seeds:
        reasons.append(f"{len(onion_seeds)} seed URL su rete onion")

    haystack = f"{target_l}\n{command_l}"
    matched_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in haystack]
    if matched_keywords:
        sample = ", ".join(matched_keywords[:3])
        reasons.append(f"keyword di rischio nel target/command ({sample})")

    if target_type in {"domain", "url", "ip"} and _SENSITIVE_RE.search(target_l):
        reasons.append("target identificato come asset tecnico sensibile")

    active = bool(reasons)
    return HighRiskContext(
        active=active,
        reasons=tuple(reasons),
        restrictions=DEFAULT_RESTRICTIONS if active else (),
        banner=OPSEC_BANNER_IT if active else "",
    )


# ---------------------------------------------------------------------------
# Sanitizzazione — testo, URL, filename, prompt AI
# ---------------------------------------------------------------------------

# Caratteri da rimuovere (anti-spoofing/anti-injection). Usiamo SOLO escape
# espliciti per non finire mai con byte di controllo o caratteri non stampabili
# letterali dentro al sorgente Python.
#
#   \x00-\x08, \x0b, \x0c, \x0e-\x1f, \x7f : control C0/DEL (esclude TAB/LF/CR)
#   ​-‏                          : zero-width + LRM/RLM
#   ‪-‮                          : bidi-override LRE/RLE/PDF/LRO/RLO
#   ⁠-⁤, ⁦-⁩           : invisible separators / isolates
#   ﻿                                 : BOM / ZWNBSP
_INVISIBLE_RE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    "​-‏"
    "‪-‮"
    "⁠-⁤⁦-⁩"
    "﻿]"
)

_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore (all )?previous (instructions|rules)"),
    re.compile(r"(?i)disregard (the )?above"),
    re.compile(r"(?i)you are now [a-z ]{0,40}"),
    re.compile(r"(?i)system prompt"),
    re.compile(r"(?i)reveal (your|the) (prompt|instructions|system message)"),
    re.compile(r"(?i)\b(jailbreak|DAN|developer mode)\b"),
)


def sanitize_text(text: str, *, max_len: int = 8000) -> str:
    """Bonifica testo grezzo proveniente da fonti non fidate."""
    if not text:
        return ""
    s = unicodedata.normalize("NFKC", str(text))
    s = _INVISIBLE_RE.sub("", s)
    if len(s) > max_len:
        s = s[:max_len] + "\n[...troncato per policy HighRiskMode...]"
    return s


_ALLOWED_URL_SCHEMES = {"http", "https"}


def sanitize_url(url: str) -> str | None:
    """Restituisce l'URL bonificato oppure None se va scartato."""
    if not url:
        return None
    s = str(url).strip()
    if _INVISIBLE_RE.search(s):
        return None
    try:
        parsed = urllib.parse.urlparse(s)
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        return None
    if not parsed.netloc:
        return None

    host = parsed.hostname or ""
    if not host:
        return None
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"

    kept: list[tuple[str, str]] = []
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        low = key.lower()
        if low.startswith("utm_"):
            continue
        if low in {"gclid", "fbclid", "yclid", "mc_eid", "mc_cid"}:
            continue
        kept.append((key, value))
    new_query = urllib.parse.urlencode(kept, doseq=True)

    safe = parsed._replace(netloc=netloc, query=new_query, fragment="")
    return urllib.parse.urlunparse(safe)


_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, *, max_len: int = 120) -> str:
    """Normalizza un nome file in quarantena."""
    if not name:
        return "file.bin"
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_FILENAME_RE.sub("_", base).strip("._-")
    if not base:
        return "file.bin"
    if len(base) > max_len:
        if "." in base[-12:]:
            stem, dot, ext = base.rpartition(".")
            base = stem[: max_len - len(ext) - 1] + dot + ext
        else:
            base = base[:max_len]
    return base


def sanitize_for_prompt(text: str, *, source: str = "untrusted") -> str:
    """Prepara un blob di testo a essere inserito in un prompt AI."""
    body = sanitize_text(text, max_len=8000)
    for pat in _PROMPT_INJECTION_PATTERNS:
        body = pat.sub("[redatto: possibile prompt-injection]", body)
    tag = (source or "untrusted").lower()
    return (
        "<<UNTRUSTED_CONTENT source=\"" + tag + "\">>\n"
        + body + "\n"
        + "<<END_UNTRUSTED_CONTENT>>"
    )


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def audit_event_payload(ctx: HighRiskContext) -> dict:
    """Payload compatto da loggare con append_audit_event.

    Niente dati personali, niente target completi: solo motivi e restrizioni.
    """
    return {
        "active": ctx.active,
        "reasons": list(ctx.reasons),
        "restriction_keys": [k for k, _ in ctx.restrictions],
    }


__all__ = [
    "HighRiskContext",
    "OPSEC_BANNER_IT",
    "DEFAULT_RESTRICTIONS",
    "HIGH_RISK_KEYWORDS",
    "detect_high_risk",
    "sanitize_text",
    "sanitize_url",
    "sanitize_filename",
    "sanitize_for_prompt",
    "audit_event_payload",
]
