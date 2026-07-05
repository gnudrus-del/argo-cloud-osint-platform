"""Scoring trasparente (Fase 4).

Ogni risultato del bot deve poter dichiarare PERCHE' e' stato collegato a
una entita' e CON QUALE confidenza. Lo spec elenca i componenti:

  - exact_match            (la value combacia esattamente con la target?)
  - fuzzy_match            (overlap testuale, sottostringa, normalizzazione?)
  - source_reliability     (chi l'ha detto? Admiralty A..F)
  - recency                (quanto e' recente la cattura?)
  - contradictions         (esistono altre evidenze che la negano?)

Questo modulo offre dataclass immutabili e funzioni pure: ogni componente
ha un peso fisso (somma=1.0). I valori sono normalizzati [0, 1]. Il
``ScoreBreakdown.confidence`` e' la media pesata.

L'output e' pensato per essere mostrato all'utente: il `rationale` e' una
lista di stringhe leggibili che spiegano il punteggio in chiaro.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .grading import classify_evidence_level


# Pesi: somma == 1.0. La somma esatta e' un invariante testato.
WEIGHTS: dict[str, float] = {
    "exact_match":        0.30,
    "fuzzy_match":        0.20,
    "source_reliability": 0.25,
    "recency":            0.10,
    "contradictions":     0.15,
}


@dataclass(frozen=True)
class ScoreBreakdown:
    """Breakdown trasparente di un confidence score.

    Tutti i componenti in [0, 1]. ``confidence`` e' la media pesata sui
    WEIGHTS sopra. ``rationale`` contiene una riga leggibile per componente.
    """
    exact_match: float
    fuzzy_match: float
    source_reliability: float
    recency: float
    contradictions: float
    confidence: float
    level: str
    rationale: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["rationale"] = list(self.rationale)
        return d


# ---------------------------------------------------------------------------
# Componenti — funzioni pure, ognuna restituisce (score, rationale_line)
# ---------------------------------------------------------------------------

def _norm(text: str) -> str:
    """Normalizzazione leggera per il confronto: lower + collapse spazi +
    rimozione punteggiatura."""
    s = re.sub(r"[^\w\s]+", " ", (text or "").lower())
    return " ".join(s.split())


def score_exact_match(value: str, target: str) -> tuple[float, str]:
    nv, nt = _norm(value), _norm(target)
    if not nv or not nt:
        return 0.0, "exact_match=0.00 (valore o target vuoto)"
    if nv == nt:
        return 1.0, f"exact_match=1.00 (\"{value}\" combacia con il target)"
    return 0.0, f"exact_match=0.00 (\"{value}\" diverso dal target)"


def score_fuzzy_match(value: str, target: str) -> tuple[float, str]:
    """Punteggio di sottostringa + token-overlap. Niente Levenshtein qui:
    non serve per il segnale grosso e ridurrebbe la trasparenza."""
    nv, nt = _norm(value), _norm(target)
    if not nv or not nt:
        return 0.0, "fuzzy_match=0.00 (valore o target vuoto)"
    if nv == nt:
        return 1.0, "fuzzy_match=1.00 (coincide con il target)"
    if nv in nt or nt in nv:
        return 0.8, f"fuzzy_match=0.80 (sottostringa diretta target/value)"
    tv, tt = set(nv.split()), set(nt.split())
    if not tv or not tt:
        return 0.0, "fuzzy_match=0.00 (nessun token significativo)"
    overlap = len(tv & tt) / max(len(tv), len(tt))
    overlap = round(overlap, 2)
    return overlap, f"fuzzy_match={overlap:.2f} (overlap token {len(tv & tt)}/{max(len(tv), len(tt))})"


# Mappa Admiralty -> score [0,1]. F = unrated, conservativo 0.10.
_RELIABILITY_SCORE = {"A": 1.00, "B": 0.85, "C": 0.65, "D": 0.40, "E": 0.20, "F": 0.10}


def score_source_reliability(reliability: str, credibility: int) -> tuple[float, str]:
    rel = (reliability or "F").upper()
    try:
        cred = int(credibility)
    except (TypeError, ValueError):
        cred = 6
    rel_s = _RELIABILITY_SCORE.get(rel, 0.10)
    # credibility 1..6 mappato linearmente: 1 -> 1.0, 6 -> 0.0
    cred_s = max(0.0, min(1.0, (6 - cred) / 5.0))
    s = round((rel_s * 0.6) + (cred_s * 0.4), 3)
    level = classify_evidence_level(rel, cred)
    return s, f"source_reliability={s:.2f} (grado {rel}{cred} -> {level})"


def score_recency(collected_at_iso: str, *, now: datetime | None = None) -> tuple[float, str]:
    """Decadimento esponenziale: oggi=1.0, ~6 mesi=0.5, oltre 5 anni->0.

    ``collected_at_iso`` puo' essere vuoto: in quel caso, neutrale 0.5.
    """
    if not collected_at_iso:
        return 0.5, "recency=0.50 (nessun timestamp -> neutrale)"
    try:
        ts = datetime.fromisoformat(collected_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return 0.5, f"recency=0.50 (timestamp non parsabile: {collected_at_iso!r})"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    days = max(0.0, (now - ts).total_seconds() / 86400.0)
    # half-life 180 giorni.
    s = round(math.exp(-days / 180.0), 3)
    return s, f"recency={s:.2f} (catturato {int(days)} giorni fa)"


def score_contradictions(value: str, other_values: list[str] | tuple[str, ...]) -> tuple[float, str]:
    """1.0 se nessuna contraddizione, decade con N valori in conflitto.

    "Contraddizione" = stesso 'kind' (gestito dal chiamante), valore DIVERSO
    da quello in esame nella lista passata.
    """
    nv = _norm(value)
    if not nv:
        return 0.0, "contradictions=0.00 (valore vuoto)"
    conflicts = [o for o in (other_values or []) if _norm(o) and _norm(o) != nv]
    if not conflicts:
        return 1.0, "contradictions=1.00 (nessuna evidenza in conflitto)"
    # 1 conflitto -> 0.6, 2 -> 0.4, 3 -> 0.27, ...
    s = round(1.0 / (1.0 + len(conflicts)), 3)
    return s, f"contradictions={s:.2f} ({len(conflicts)} evidenze in conflitto)"


# ---------------------------------------------------------------------------
# Aggregazione
# ---------------------------------------------------------------------------

def compute_score(
    *,
    value: str,
    target: str,
    reliability: str,
    credibility: int,
    collected_at: str = "",
    other_values_same_kind: list[str] | tuple[str, ...] = (),
    now: datetime | None = None,
) -> ScoreBreakdown:
    """Calcola il breakdown completo. Funzione pura, deterministica."""
    em, em_r = score_exact_match(value, target)
    fm, fm_r = score_fuzzy_match(value, target)
    sr, sr_r = score_source_reliability(reliability, credibility)
    rc, rc_r = score_recency(collected_at, now=now)
    ct, ct_r = score_contradictions(value, other_values_same_kind)

    confidence = (
        em * WEIGHTS["exact_match"] +
        fm * WEIGHTS["fuzzy_match"] +
        sr * WEIGHTS["source_reliability"] +
        rc * WEIGHTS["recency"] +
        ct * WEIGHTS["contradictions"]
    )
    confidence = round(confidence, 3)
    level = classify_evidence_level(reliability, credibility)

    return ScoreBreakdown(
        exact_match=round(em, 3),
        fuzzy_match=round(fm, 3),
        source_reliability=round(sr, 3),
        recency=round(rc, 3),
        contradictions=round(ct, 3),
        confidence=confidence,
        level=level,
        rationale=(em_r, fm_r, sr_r, rc_r, ct_r),
    )


__all__ = [
    "WEIGHTS",
    "ScoreBreakdown",
    "compute_score",
    "score_exact_match",
    "score_fuzzy_match",
    "score_source_reliability",
    "score_recency",
    "score_contradictions",
]
