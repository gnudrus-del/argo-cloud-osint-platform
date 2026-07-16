"""Connector: legit_scorer — aggregatore nativo che stima la legittimità di
un'email o un numero di telefono.

Combina i segnali di più connettori già presenti nel registro (holehe_native,
holehe, gravatar, threatfox, ignorant, phone_meta) e produce:
  * uno score 0..100 (interpretato: 0-30 sospetto, 30-60 incerto, 60-100 legittimo),
  * un rationale in italiano con i segnali positivi/negativi,
  * un verdetto ("legittima"/"incerta"/"sospetta").

Ispirato all'idea "SION-like": aggregare più fonti per profilare
identità digitali senza SaaS esterni. Zero API key. Passivo.

Input: ``email`` o ``phone``.
"""
from __future__ import annotations

from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorRegistry,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="legit_scorer",
    label="Legit scorer (email/telefono)",
    action_class=ACTION_PASSIVE,
    input_types=("email", "phone"),
    output_categories=("identity_score",),
    required_key="",
    cache_ttl=1800,
    rate_limit=RateLimit(per_minute=10, per_day=500, burst=2),
    legal_note="legit_scorer.legal_note",
    health_check_url="",
)


def _try_run(registry: ConnectorRegistry, name: str, ctx: ConnectorContext):
    try:
        conn = registry.get(name)
    except KeyError:
        return None
    # Bypassiamo rate-limit/cache di BaseConnector.run (siamo già dentro un
    # aggregatore passivo con il proprio rate-limit), ma il gate RoE/scope
    # resta obbligatorio per ogni delegato — non solo per legit_scorer stesso
    # — così un futuro delegato gated non erediterebbe silenziosamente
    # l'autorizzazione passiva di legit_scorer.
    from ..policy import check_policy
    allowed, _reason = check_policy(ctx, conn.spec)
    if not allowed:
        return None
    try:
        return conn._fetch(ctx)
    except Exception:
        return None


class LegitScorerConnector(BaseConnector):
    spec = _SPEC

    # Iniettato dal registro dopo la costruzione (setattr in __init__.py).
    _registry: ConnectorRegistry | None = None

    def bind_registry(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("legit_scorer.target_empty", context.lang))
        if self._registry is None:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("legit_scorer.registry_uninit", context.lang))

        # Distingui email vs phone
        is_email = "@" in target
        signals: list[dict] = []
        score = 50   # baseline neutra

        if is_email:
            # holehe_native: valida dominio (MX) + Gravatar + disposable + canonical.
            r = _try_run(self._registry, "holehe_native", context)
            if r and r.status == "ok":
                kinds = {f.kind for f in r.findings}
                if "email_domain_valid" in kinds:
                    score += 10; signals.append({"weight": +10, "why": "Dominio email valido (risolve)."})
                if "email_disposable" in kinds:
                    score -= 30; signals.append({"weight": -30, "why": "Dominio email 'usa e getta'."})
                if any(f.kind == "email_service" and "Gravatar" in f.value for f in r.findings):
                    score += 15; signals.append({"weight": +15, "why": "Profilo Gravatar pubblico."})
            # gravatar diretto (ridondante con holehe_native.Gravatar; salta se già visto)
            # holehe pieno: siti registrati -> forte segnale positivo
            r = _try_run(self._registry, "holehe", context)
            if r and r.status == "ok":
                sites = r.raw.get("registered_on") or []
                n = len(sites)
                if n >= 5:
                    score += 25; signals.append({"weight": +25, "why": f"Email registrata su {n} servizi noti (holehe)."})
                elif n >= 2:
                    score += 15; signals.append({"weight": +15, "why": f"Email registrata su {n} servizi (holehe)."})
                elif n == 0 and r.raw.get("count") == 0:
                    score -= 5; signals.append({"weight": -5, "why": "Nessuna registrazione rilevata (holehe)."})
                if r.raw.get("recovery_hints", 0):
                    score += 10; signals.append({"weight": +10,
                        "why": f"{r.raw['recovery_hints']} hint di recupero (dati collegati)."})
            elif r and r.status == "missing_key":
                signals.append({"weight": 0, "why": "holehe (completo) non configurato: usato solo fallback nativo."})

            # threatfox reputation (email/dominio)
            r = _try_run(self._registry, "threatfox", context)
            if r and r.status == "ok" and r.findings:
                bad = [f for f in r.findings if f.kind == "threat_ioc"]
                if bad:
                    score -= 40; signals.append({"weight": -40, "why": "Email/dominio segnalato in ThreatFox."})

        else:  # phone
            r = _try_run(self._registry, "phone_meta", context)
            if r and r.status == "ok":
                valid = any(f.kind == "phone_valid" and f.value == "false" for f in r.findings)
                if valid:
                    score -= 40; signals.append({"weight": -40, "why": "Numero sintatticamente non valido."})
                else:
                    score += 10; signals.append({"weight": +10, "why": "Numero valido (libphonenumber)."})
                ptype = next((f.value for f in r.findings if f.kind == "phone_type"), "")
                if ptype in ("voip",):
                    score -= 10; signals.append({"weight": -10, "why": "Tipo numero: VoIP (spesso monouso)."})
                if ptype == "mobile":
                    score += 5; signals.append({"weight": +5, "why": "Tipo numero: mobile."})
            # ignorant (registrazioni su piattaforme)
            r = _try_run(self._registry, "ignorant", context)
            if r and r.status == "ok":
                sites = r.raw.get("registered_on") or []
                n = len(sites)
                if n >= 3:
                    score += 25; signals.append({"weight": +25, "why": f"Numero registrato su {n} servizi (ignorant)."})
                elif n >= 1:
                    score += 15; signals.append({"weight": +15, "why": f"Numero registrato su {n} servizio/i (ignorant)."})
            elif r and r.status == "missing_key":
                signals.append({"weight": 0, "why": "ignorant non configurato: segnale mancante."})
            # telegram_checker (nome, username, last seen)
            r = _try_run(self._registry, "telegram_checker", context)
            if r and r.status == "ok" and r.findings:
                score += 15; signals.append({"weight": +15, "why": "Account Telegram esistente sul numero."})

        # Clamp e verdetto
        score = max(0, min(100, score))
        if score >= 65:
            verdict = "legittima"
        elif score >= 40:
            verdict = "incerta"
        else:
            verdict = "sospetta"

        ev = [Evidence(url="", title="aggregazione nativa")]
        summary = f"Score {score}/100 → {verdict}"
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=[Finding(
                kind="legit_score", value=summary,
                confidence=min(0.95, 0.5 + abs(score - 50) / 100),
                source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=" · ".join(s["why"] for s in signals) or "Nessun segnale forte disponibile.",
                why_linked=[s["why"] for s in signals if s["weight"] > 0],
                gaps=[s["why"] for s in signals if s["weight"] == 0],
            )],
            raw={"score": score, "verdict": verdict, "signals": signals,
                 "engine": "legit_scorer", "kind": "email" if is_email else "phone"},
        )

    def health_check(self) -> bool:
        return True
