from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


class SafetyError(ValueError):
    """Raised when a requested investigation is outside the bot's guardrails."""


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    note: str


SENSITIVE_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # US SSN-like pattern
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),  # payment-card-like long digits
    re.compile(r"\bpassport\b", re.IGNORECASE),
    re.compile(r"\b(home address|private address|residential address)\b", re.IGNORECASE),
]
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.]{1,63}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ]{6,24}$")
PERSONAL_TARGET_TYPES = {"person", "phone"}
PERSONAL_EXTERNAL_TARGET_TYPES = {"person", "email", "handle", "phone"}
NETWORK_TOOLS = {"nmap"}
EXTERNAL_TOOL_TARGETS = {
    "sherlock": {"handle"},
    "maigret": {"handle"},
    "social_analyzer": {"handle"},
    "holehe": {"email"},
    "h8mail": {"email"},
    "socialscan": {"email", "handle"},
    "phoneinfoga": {"phone"},
    "ghunt": {"email"},
    "toutatis": {"handle"},
    "osintgram": {"handle"},
    "nmap": {"domain", "ip"},
    "theharvester": {"domain"},
    "spiderfoot": {"domain", "company", "ip", "email", "handle"},
    "recon_ng": {"domain", "company"},
    "amass": {"domain"},
    "subfinder": {"domain"},
    "waybackurls": {"domain"},
    "gau": {"domain"},
    "gitleaks": {"media"},
    "singlefile": {"domain", "company", "media"},
    "shodan": {"domain", "ip"},
    "censys": {"domain", "ip"},
    "exiftool": {"media"},
    "ffprobe": {"media"},
    # Fase 3
    "mosint": {"email"},
    "infoga": {"domain"},
    "phunter": {"phone"},
    "subjack": {"domain"},
    "trufflehog": {"media"},
    "cloud_enum": {"company", "domain"},
}


def assess_request(target: str, target_type: str, confirm_authorization: bool) -> SafetyDecision:
    clean_target = target.strip()
    if not clean_target:
        raise SafetyError("Il target non puo essere vuoto.")

    for pattern in SENSITIVE_PATTERNS:
        if target_type == "phone" and "13,19" in pattern.pattern:
            continue
        if pattern.search(clean_target):
            raise SafetyError(
                "Il target sembra contenere un identificatore sensibile. "
                "Riformula la ricerca su un dominio, un'organizzazione o un asset autorizzato."
            )

    if target_type in PERSONAL_TARGET_TYPES and not confirm_authorization:
        raise SafetyError(
            "Le ricerche su persone o numeri di telefono richiedono --confirm-authorization. "
            "Usalo solo per casi autorizzati, professionali o di pubblico interesse."
        )

    note = (
        "Ricerca limitata a fonti pubbliche, con citazioni e senza aggirare autenticazioni, "
        "paywall, controlli tecnici o impostazioni di privacy."
    )
    if target_type == "person":
        note += " Target personale: minimizzazione dati attiva; i contatti restano redatti salvo opzione esplicita."
    if target_type in {"email", "handle", "phone"}:
        note += " Identificatore personale: attribuzione, omonimie e contesto richiedono verifica manuale."

    return SafetyDecision(allowed=True, note=note)


def assert_external_tool_allowed(
    tool_name: str,
    target_type: str,
    confirm_authorization: bool,
    allow_network_scan: bool,
) -> None:
    allowed_targets = EXTERNAL_TOOL_TARGETS.get(tool_name)
    if allowed_targets is None:
        raise SafetyError(f"Tool esterno non supportato: {tool_name}")
    if target_type not in allowed_targets:
        allowed = ", ".join(sorted(allowed_targets))
        raise SafetyError(f"{tool_name} puo essere usato solo con target di tipo: {allowed}.")
    if target_type in PERSONAL_EXTERNAL_TARGET_TYPES and not confirm_authorization:
        raise SafetyError(
            f"{tool_name} su identificatori personali richiede --confirm-authorization "
            "e un caso d'uso autorizzato."
        )
    if tool_name in NETWORK_TOOLS and (not confirm_authorization or not allow_network_scan):
        raise SafetyError(
            "nmap richiede --confirm-authorization e --allow-network-scan su asset propri o autorizzati."
        )


def validate_tool_target(target: str, target_type: str) -> str:
    """Validate a target before passing it to an external tool subprocess.

    Rejects targets that could be interpreted as CLI options (e.g. leading "-")
    or that escape the expected charset for their type. Returns the cleaned
    token to be used as a positional argument.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        raise SafetyError("Target esterno vuoto.")
    if cleaned.startswith("-"):
        raise SafetyError(
            "Target esterno rifiutato: inizia con '-' e potrebbe essere interpretato come opzione."
        )
    if any(ch in cleaned for ch in ("\x00", "\r", "\n")):
        raise SafetyError("Target esterno contiene caratteri di controllo non ammessi.")
    if target_type == "domain":
        host = cleaned.casefold().removeprefix("http://").removeprefix("https://").split("/", 1)[0]
        host = host.removeprefix("www.")
        if not _DOMAIN_RE.fullmatch(host):
            raise SafetyError("Dominio non valido per esecuzione tool esterno.")
        return host
    if target_type == "ip":
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise SafetyError(f"IP non valido per esecuzione tool esterno: {exc}") from exc
        return cleaned
    if target_type == "handle":
        candidate = cleaned.lstrip("@")
        if not _HANDLE_RE.fullmatch(candidate):
            raise SafetyError("Handle non valido per esecuzione tool esterno.")
        return candidate
    if target_type == "email":
        if not _EMAIL_RE.fullmatch(cleaned):
            raise SafetyError("Email non valida per esecuzione tool esterno.")
        return cleaned
    if target_type == "phone":
        if not _PHONE_RE.fullmatch(cleaned):
            raise SafetyError("Numero di telefono non valido per esecuzione tool esterno.")
        return cleaned
    if target_type in {"media"}:
        # Media targets are local file paths; reject leading dashes only.
        # Path traversal is handled at upload boundary.
        return cleaned
    if target_type in {"company", "org", "crypto", "person"}:
        # Free-form targets must not look like options.
        if re.search(r"[\x00-\x1f]", cleaned):
            raise SafetyError("Target contiene caratteri di controllo non ammessi.")
        return cleaned
    return cleaned


# Pillar 0.2: action classification. Every external action declares which
# class it is — the RoE allows or denies based on this.
ACTION_CLASSES = {"passive", "active-gated", "pii-gated", "darkweb-gated"}


# Mapping external tool name → action class. Used by external_tools.run_tool
# to ask the RoE engine the right question. Conservative defaults: when in
# doubt, classify as pii-gated (the higher gate).
TOOL_ACTION_CLASSES = {
    # Passive lookups, no PII targeting per se.
    "shodan": "passive",
    "censys": "passive",
    "theharvester": "passive",
    "amass": "passive",
    "subfinder": "passive",
    "waybackurls": "passive",
    "gau": "passive",
    "spiderfoot": "passive",
    "recon_ng": "passive",
    "singlefile": "passive",
    "exiftool": "passive",
    "ffprobe": "passive",
    "infoga": "passive",
    # PII-gated: target IS a personal identifier or directly enumerates them.
    "sherlock": "pii-gated",
    "maigret": "pii-gated",
    "social_analyzer": "pii-gated",
    "holehe": "pii-gated",
    "h8mail": "pii-gated",
    "socialscan": "pii-gated",
    "phoneinfoga": "pii-gated",
    "ghunt": "pii-gated",
    "toutatis": "pii-gated",
    "osintgram": "pii-gated",
    "mosint": "pii-gated",
    "phunter": "pii-gated",
    # Passive: expanded red-team / EASM passive tools
    "httpx": "passive",
    "dnsx": "passive",
    "dnstwist": "passive",
    "whatweb": "passive",
    "wafw00f": "passive",
    "gospider": "passive",
    "hakrawler": "passive",
    "katana": "passive",
    "linkfinder": "passive",
    "secretfinder": "passive",
    "metagoofil": "passive",
    "eyewitness": "passive",
    "testssl": "passive",
    "fierce": "passive",
    "dnsenum": "passive",
    # Active-gated: touches the target with packets or invasive enumeration.
    "nmap": "active-gated",
    "naabu": "active-gated",
    "nuclei": "active-gated",
    "masscan": "active-gated",
    "nikto": "active-gated",
    "wpscan": "active-gated",
    "feroxbuster": "active-gated",
    "ffuf": "active-gated",
    "dalfox": "active-gated",
    "dirsearch": "active-gated",
    "arjun": "active-gated",
    "gitdumper": "active-gated",
    "enum4linux": "active-gated",
    "smbmap": "active-gated",
    "snmpwalk": "active-gated",
    "subjack": "active-gated",
    "cloud_enum": "active-gated",
    "trufflehog": "active-gated",
    "gitleaks": "active-gated",
}


def action_class_for_tool(tool_name: str) -> str:
    return TOOL_ACTION_CLASSES.get(tool_name, "pii-gated")


def _is_in_scope(target_type: str, target: str, scope: dict) -> bool:
    """Default-deny scope check. Empty scope of a category means "nothing in
    that category is allowed" — not "everything goes".

    The wildcard ``scope["any"] = True`` is the explicit opt-in for the
    permissive auto-signed RoE on legacy/default cases.
    """
    if scope.get("any"):
        return True
    target = (target or "").strip().casefold()
    if not target:
        return False
    if target_type == "domain":
        for entry in scope.get("domains", []) or []:
            entry = entry.casefold()
            if target == entry or target.endswith("." + entry):
                return True
        return False
    if target_type == "ip":
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        for entry in scope.get("ips", []) or []:
            try:
                if ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        for cidr in scope.get("cidrs", []) or []:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    if target_type == "handle":
        for entry in scope.get("handles", []) or []:
            if target == entry.casefold().lstrip("@"):
                return True
        return False
    if target_type == "email":
        for entry in scope.get("emails", []) or []:
            if target == entry.casefold():
                return True
        # Also allow if the email's domain is in scope.domains.
        if "@" in target:
            dom = target.rsplit("@", 1)[-1]
            for entry in scope.get("domains", []) or []:
                entry = entry.casefold()
                if dom == entry or dom.endswith("." + entry):
                    return True
        return False
    if target_type == "phone":
        digits = re.sub(r"\D+", "", target)
        for entry in scope.get("phones", []) or []:
            if re.sub(r"\D+", "", entry) == digits:
                return True
        return False
    if target_type in {"company", "org"}:
        for entry in scope.get("companies", []) or []:
            if target == entry.casefold() or target in entry.casefold():
                return True
        return False
    return False


def _within_window(roe: dict, now_iso: str) -> bool:
    vf = roe.get("valid_from") or ""
    vt = roe.get("valid_to") or ""
    if vf and now_iso < vf:
        return False
    if vt and now_iso > vt:
        return False
    return True


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    mandate_reference: str = ""


def authorize_action(
    *,
    action_class: str,
    target_type: str,
    target: str,
    case_id: str | None,
    actor: str,
    storage,
    now_iso: str | None = None,
) -> AuthorizationResult:
    """Decide whether *actor* may run an action of *action_class* on *target*.

    The decision is made by the RoE attached to *case_id*. Empty case_id is
    legacy CLI flow: no RoE is consulted. Real cases (any case with id and an
    active RoE) enforce scope + time window + allowed_classes. Auto-permissive
    "Caso default" carries an auto-signed RoE covering all classes, no scope,
    no window — so legacy web usage keeps working.

    Failure modes raise SafetyError so the caller's command never gets built.
    """
    if action_class not in ACTION_CLASSES:
        raise SafetyError(f"Classe di azione sconosciuta: {action_class}")
    if not case_id:
        # Legacy/CLI path with no case context; preserved for back-compat.
        return AuthorizationResult(True, "no-case (legacy path)")

    roe = storage.get_active_roe(case_id) if storage else None
    if roe is None:
        _audit_roe_denied(storage, actor, case_id, action_class, target, "no_active_roe")
        raise SafetyError("Nessuna Regola d'Ingaggio attiva per questo caso: firmane una prima di lanciare azioni.")
    if action_class not in roe["allowed_classes"]:
        _audit_roe_denied(storage, actor, case_id, action_class, target, "class_not_allowed", roe)
        raise SafetyError(f"La RoE non consente azioni di classe '{action_class}'.")
    from datetime import datetime, timezone
    now_iso = now_iso or datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not _within_window(roe, now_iso):
        _audit_roe_denied(storage, actor, case_id, action_class, target, "outside_time_window", roe)
        raise SafetyError("Azione fuori dalla finestra temporale della RoE.")
    if roe.get("requires_second_signature") and action_class in {"active-gated", "darkweb-gated"}:
        if not roe.get("second_signed_at"):
            _audit_roe_denied(storage, actor, case_id, action_class, target, "missing_second_signature", roe)
            raise SafetyError("Questa classe di azione richiede una seconda firma (4-eyes) sulla RoE.")
    if not _is_in_scope(target_type, target, roe.get("scope") or {}):
        _audit_roe_denied(storage, actor, case_id, action_class, target, "out_of_scope", roe)
        raise SafetyError("Target fuori dallo scope autorizzato dalla RoE.")
    _audit_roe_authorized(storage, actor, case_id, action_class, target, roe)
    return AuthorizationResult(True, "ok", roe.get("mandate_reference", ""))


def _audit_roe_denied(storage, actor: str, case_id: str, action_class: str,
                      target: str, reason: str, roe: dict | None = None) -> None:
    if not storage:
        return
    try:
        storage.append_audit_event(
            actor or "system",
            "roe_denied",
            {
                "case_id": case_id,
                "action_class": action_class,
                "target": target,
                "reason": reason,
                "mandate_reference": (roe or {}).get("mandate_reference", ""),
            },
        )
    except Exception:
        pass


def _audit_roe_authorized(storage, actor: str, case_id: str, action_class: str,
                          target: str, roe: dict) -> None:
    if not storage:
        return
    try:
        storage.append_audit_event(
            actor or "system",
            "roe_authorized",
            {
                "case_id": case_id,
                "action_class": action_class,
                "target": target,
                "mandate_reference": roe.get("mandate_reference", ""),
            },
        )
    except Exception:
        pass


def assert_darkweb_allowed(allow_darkweb: bool) -> None:
    if not allow_darkweb:
        raise SafetyError(
            "Le funzioni dark/deep web richiedono --allow-darkweb. "
            "Sono limitate a monitoraggio difensivo, fonti autorizzate e riferimenti seed verificabili."
        )


def redact_email(email: str) -> str:
    local, sep, domain = email.partition("@")
    if not sep:
        return email
    if len(local) <= 2:
        redacted_local = "*" * len(local)
    else:
        redacted_local = f"{local[0]}***{local[-1]}"
    return f"{redacted_local}@{domain}"


def redact_phone(value: str) -> str:
    digits = re.sub(r"\D+", "", value)
    if len(digits) <= 4:
        return "*" * len(digits)
    return f"{'*' * max(0, len(digits) - 4)}{digits[-4:]}"
