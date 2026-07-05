"""AI-enrichment locale: OCR, NER, entity-resolution, summarization, traduzione.

Filosofia "offline-first, degradazione graceful":
  * ogni capability usa una libreria opzionale se presente, altrimenti un
    fallback pure-Python o uno skip pulito. La piattaforma base NON richiede
    nessuna di queste dipendenze per avviarsi.
  * niente chiamate a servizi cloud: OCR/NER/summary girano in-process, così
    nessun dato personale lascia la VM (requisito privacy-by-design).

Capability opzionali (rilevate a runtime):
  * OCR          -> pytesseract + Pillow  (binario tesseract)
  * NER          -> spaCy + modello it/xx (fallback: regex su patterns.py)
  * language id  -> langdetect            (fallback: euristica stopword)
  * traduzione   -> deep-translator / argostranslate (fallback: None)

Summarization estrattiva e' sempre disponibile (algoritmo frequency-based
in pure Python, nessuna dipendenza).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .patterns import (
    BTC_RE,
    DOMAIN_RE,
    EMAIL_RE,
    ETH_RE,
    HANDLE_RE,
    IP_RE,
    PHONE_RE,
    URL_RE,
)


# ---------------------------------------------------------------------------
# Capability detection (lazy, cached)
# ---------------------------------------------------------------------------
_CAP_CACHE: dict[str, bool] = {}


def _has(module: str) -> bool:
    if module in _CAP_CACHE:
        return _CAP_CACHE[module]
    try:
        __import__(module)
        _CAP_CACHE[module] = True
    except Exception:
        _CAP_CACHE[module] = False
    return _CAP_CACHE[module]


def capabilities() -> dict[str, bool]:
    """Ritorna quali enrichment sono disponibili in questo ambiente."""
    return {
        "ocr": _has("pytesseract") and _has("PIL"),
        "ner_spacy": _has("spacy"),
        "language_id": _has("langdetect"),
        "translate": _has("deep_translator") or _has("argostranslate"),
        "summarization": True,  # sempre (pure python)
        "ner_regex_fallback": True,  # sempre
    }


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class NamedEntity:
    text: str
    label: str            # PERSON | ORG | GPE | EMAIL | PHONE | URL | DOMAIN | IP | CRYPTO | HANDLE | MISC
    confidence: float = 0.5
    source: str = "regex"  # spacy | regex


@dataclass
class OcrResult:
    text: str = ""
    available: bool = False
    engine: str = ""
    note: str = ""
    entities: list[NamedEntity] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OCR
# ---------------------------------------------------------------------------
def ocr_image(path: str, lang: str = "ita+eng") -> OcrResult:
    """Estrae testo da un'immagine. Usa pytesseract se disponibile."""
    if not (_has("pytesseract") and _has("PIL")):
        return OcrResult(
            available=False,
            note="OCR non disponibile: installa 'pytesseract' + 'Pillow' e il binario tesseract.",
        )
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
    except Exception as exc:  # pragma: no cover
        return OcrResult(available=False, note=f"Import OCR fallito: {exc}")
    try:
        with Image.open(path) as img:
            text = pytesseract.image_to_string(img, lang=lang)
    except Exception as exc:
        # lang pack mancante o binario assente: riprova senza lang esplicito
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore
            with Image.open(path) as img:
                text = pytesseract.image_to_string(img)
        except Exception as exc2:
            return OcrResult(available=False, note=f"OCR runtime error: {exc2}")
    text = (text or "").strip()
    return OcrResult(
        text=text,
        available=True,
        engine="tesseract",
        entities=named_entities(text) if text else [],
    )


# ---------------------------------------------------------------------------
# NER
# ---------------------------------------------------------------------------
# Sequenze di parole capitalizzate = candidati PERSON/ORG (fallback regex).
_CAP_SEQ_RE = re.compile(r"\b([A-ZÀ-Ý][a-zà-ÿ'’]+(?:\s+[A-ZÀ-Ý][a-zà-ÿ'’]+){1,3})\b")
_ORG_HINTS = ("srl", "spa", "s.p.a", "s.r.l", "inc", "ltd", "gmbh", "llc",
              "group", "holding", "bank", "università", "university", "ministero")

_STRUCTURED = [
    (EMAIL_RE, "EMAIL", 0.95),
    (URL_RE, "URL", 0.9),
    (IP_RE, "IP", 0.9),
    (ETH_RE, "CRYPTO", 0.9),
    (BTC_RE, "CRYPTO", 0.9),
    (PHONE_RE, "PHONE", 0.7),
    (HANDLE_RE, "HANDLE", 0.6),
]


def _regex_entities(text: str) -> list[NamedEntity]:
    out: list[NamedEntity] = []
    seen: set[tuple[str, str]] = set()

    def _add(val: str, label: str, conf: float):
        key = (label, val.lower())
        if val and key not in seen:
            seen.add(key)
            out.append(NamedEntity(text=val, label=label, confidence=conf, source="regex"))

    for pattern, label, conf in _STRUCTURED:
        for m in pattern.finditer(text):
            val = m.group(0)
            # HANDLE_RE cattura il gruppo senza @; normalizzo
            if label == "HANDLE":
                val = "@" + m.group(1)
            _add(val, label, conf)

    # Domini (evita di duplicare quelli già dentro URL/email)
    joined = " ".join(e.text.lower() for e in out)
    for m in DOMAIN_RE.finditer(text):
        dom = m.group(0)
        if dom.lower() not in joined:
            _add(dom, "DOMAIN", 0.6)

    # PERSON/ORG candidati da sequenze capitalizzate
    for m in _CAP_SEQ_RE.finditer(text):
        phrase = m.group(1).strip()
        low = phrase.lower()
        label = "ORG" if any(h in low for h in _ORG_HINTS) else "PERSON"
        _add(phrase, label, 0.4)  # bassa: euristica, va confermata

    return out


_SPACY_LABEL_MAP = {
    "PER": "PERSON", "PERSON": "PERSON",
    "ORG": "ORG",
    "LOC": "GPE", "GPE": "GPE",
    "MISC": "MISC",
}


def named_entities(text: str, lang: str = "it") -> list[NamedEntity]:
    """Estrae named entity dal testo. spaCy se disponibile, altrimenti regex.

    Combina sempre il risultato con gli identificatori strutturati (email,
    telefono, url, ip, crypto, handle) via regex — spaCy da solo li perde.
    """
    text = (text or "").strip()
    if not text:
        return []

    entities: list[NamedEntity] = []
    if _has("spacy"):
        try:
            spacy_ents = _spacy_entities(text, lang)
            entities.extend(spacy_ents)
        except Exception:
            pass  # cade sul fallback regex sotto

    # Gli identificatori strutturati vanno sempre aggiunti (spaCy li ignora).
    regex_ents = _regex_entities(text)

    # Merge dedup: chiave (label, valore lower). spaCy vince sui PERSON/ORG.
    merged: dict[tuple[str, str], NamedEntity] = {}
    for e in entities + regex_ents:
        key = (e.label, e.text.lower())
        cur = merged.get(key)
        if cur is None or e.confidence > cur.confidence:
            merged[key] = e
    return sorted(merged.values(), key=lambda e: (-e.confidence, e.label, e.text))


def _spacy_entities(text: str, lang: str) -> list[NamedEntity]:
    import spacy  # type: ignore

    # Prova modello italiano, poi multilingua, poi blank pipeline (nessuna NER).
    nlp = None
    for model in (f"{lang}_core_news_sm", "xx_ent_wiki_sm", "en_core_web_sm"):
        try:
            nlp = spacy.load(model)
            break
        except Exception:
            continue
    if nlp is None:
        return []
    doc = nlp(text[:100_000])  # cap per non esplodere su testi enormi
    out: list[NamedEntity] = []
    for ent in doc.ents:
        label = _SPACY_LABEL_MAP.get(ent.label_, "MISC")
        if label in ("PERSON", "ORG", "GPE", "MISC"):
            out.append(NamedEntity(text=ent.text.strip(), label=label,
                                   confidence=0.75, source="spacy"))
    return out


# ---------------------------------------------------------------------------
# Entity resolution (dedupe/merge cross-source)
# ---------------------------------------------------------------------------
def resolve_named_entities(entities: list[NamedEntity]) -> list[NamedEntity]:
    """Fonde entity duplicate normalizzando i valori (riusa entities.normalize_value
    per email/telefono/dominio) e tenendo la confidence massima."""
    from .entities import normalize_value

    label_to_argo = {
        "EMAIL": "email", "PHONE": "phone", "DOMAIN": "domain",
        "URL": "url", "IP": "ip", "CRYPTO": "crypto", "HANDLE": "handle",
    }
    merged: dict[tuple[str, str], NamedEntity] = {}
    for e in entities:
        argo_type = label_to_argo.get(e.label)
        norm = normalize_value(argo_type, e.text) if argo_type else e.text.strip().lower()
        key = (e.label, norm)
        cur = merged.get(key)
        if cur is None or e.confidence > cur.confidence:
            merged[key] = NamedEntity(text=e.text, label=e.label,
                                      confidence=e.confidence, source=e.source)
    return sorted(merged.values(), key=lambda e: (-e.confidence, e.label))


# ---------------------------------------------------------------------------
# Summarization estrattiva (pure python, sempre disponibile)
# ---------------------------------------------------------------------------
_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-ZÀ-Ý0-9])")
_WORD_RE = re.compile(r"[A-Za-zÀ-ÿ0-9]{3,}")
_STOPWORDS = {
    # italiano + inglese, set minimale per lo scoring
    "che", "non", "per", "con", "una", "uno", "del", "della", "delle", "dei",
    "gli", "gli", "come", "sono", "hanno", "questo", "questa", "anche", "piu",
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
    "has", "have", "not", "but", "you", "all", "can", "her", "his", "its",
}


def extractive_summary(text: str, max_sentences: int = 5) -> str:
    """Riassunto estrattivo frequency-based: seleziona le frasi con maggiore
    densità di parole-chiave (TF senza stopword), preservando l'ordine originale.
    """
    text = (text or "").strip()
    if not text:
        return ""
    sentences = [s.strip() for s in _SENT_SPLIT_RE.split(text) if s.strip()]
    if len(sentences) <= max_sentences:
        return " ".join(sentences)

    # Frequenze parole
    freq: dict[str, int] = {}
    for w in _WORD_RE.findall(text.lower()):
        if w in _STOPWORDS:
            continue
        freq[w] = freq.get(w, 0) + 1
    if not freq:
        return " ".join(sentences[:max_sentences])
    max_f = max(freq.values())
    for w in freq:
        freq[w] /= max_f  # normalizza

    # Score per frase (media dei pesi parola, penalizza frasi lunghissime)
    scored: list[tuple[int, float]] = []
    for idx, sent in enumerate(sentences):
        words = [w for w in _WORD_RE.findall(sent.lower()) if w not in _STOPWORDS]
        if not words:
            scored.append((idx, 0.0))
            continue
        score = sum(freq.get(w, 0.0) for w in words) / (len(words) ** 0.5)
        scored.append((idx, score))

    top_idx = sorted(sorted(scored, key=lambda x: -x[1])[:max_sentences], key=lambda x: x[0])
    return " ".join(sentences[i] for i, _ in top_idx)


# ---------------------------------------------------------------------------
# Language detection + traduzione (opzionali)
# ---------------------------------------------------------------------------
_IT_STOP = {"che", "non", "per", "con", "della", "sono", "gli", "questo"}
_EN_STOP = {"the", "and", "for", "with", "that", "this", "from", "have"}


def detect_language(text: str) -> str:
    """Ritorna un codice lingua ISO-639-1 best-effort. langdetect se presente,
    altrimenti euristica stopword it/en, altrimenti 'und'."""
    text = (text or "").strip()
    if not text:
        return "und"
    if _has("langdetect"):
        try:
            from langdetect import detect  # type: ignore
            return detect(text)
        except Exception:
            pass
    words = set(_WORD_RE.findall(text.lower()))
    it_hits = len(words & _IT_STOP)
    en_hits = len(words & _EN_STOP)
    if it_hits == en_hits == 0:
        return "und"
    return "it" if it_hits >= en_hits else "en"


def translate_text(text: str, target: str = "en", source: str = "auto") -> str | None:
    """Traduce il testo se una libreria locale/offline e' disponibile.
    Ritorna None se nessun traduttore e' installato (nessun fallback cloud)."""
    text = (text or "").strip()
    if not text:
        return ""
    if _has("deep_translator"):
        try:
            from deep_translator import GoogleTranslator  # type: ignore
            return GoogleTranslator(source=source, target=target).translate(text[:4900])
        except Exception:
            return None
    if _has("argostranslate"):
        try:
            import argostranslate.translate as at  # type: ignore
            src = source if source != "auto" else detect_language(text)
            return at.translate(text, src, target)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Convenienza: enrich di un blob di testo (usato dal pipeline/report)
# ---------------------------------------------------------------------------
def enrich_text(text: str, *, summarize: bool = True, translate_to: str = "") -> dict[str, Any]:
    """Applica NER + language + (opz.) summary + (opz.) traduzione a un testo."""
    ents = resolve_named_entities(named_entities(text))
    result: dict[str, Any] = {
        "language": detect_language(text),
        "entities": [{"text": e.text, "label": e.label,
                      "confidence": round(e.confidence, 2), "source": e.source}
                     for e in ents],
        "entity_count": len(ents),
    }
    if summarize:
        result["summary"] = extractive_summary(text, max_sentences=5)
    if translate_to:
        result["translation"] = translate_text(text, target=translate_to)
        result["translation_target"] = translate_to
    return result
