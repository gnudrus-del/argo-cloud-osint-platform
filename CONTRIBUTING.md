# Contribuire ad Argo OSINT

Benvenuto/a. Argo è una piattaforma **OSINT italiana** privacy-by-design,
GDPR-oriented, court-ready. Ogni contributo ci aiuta a farla diventare un
punto di riferimento.

## Come partecipare

### Segnalare un bug
- Verifica che non esista già una issue simile.
- Apri una issue con: sistema operativo, versione (`git rev-parse HEAD`),
  passi di riproduzione, output atteso vs. osservato, log rilevanti.
- **Segreti**: mai nei log/screenshot che alleghi. Reduci le API key.

### Proporre una feature
- Discuti prima in una **Discussion** o issue "proposal": vuoi capire se
  ha spazio nella roadmap prima di scrivere il codice.
- Argo ha una linea forte: **privacy-by-design + native-first**. Le PR che
  aggiungono dipendenze pesanti o servizi SaaS obbligatori vanno motivate.

### Aggiungere un connettore OSINT
- Vedi `osint_bot/connectors/` per il pattern (subclass `BaseConnector`).
- Regole d'oro:
  1. **Passivo di default** (`ACTION_PASSIVE`); attivo solo se ha senso e
     va marcato `ACTION_ACTIVE_GATED`.
  2. **Graceful degrade**: se il tool/chiave manca → `status="missing_key"`
     con messaggio chiaro. Mai eccezioni.
  3. **Rate limit e cache TTL** dichiarati nello spec.
  4. **Test offline deterministici** (in `tests/`).
  5. **Legal note** in italiano nello spec: cosa manda in rete e a chi.

### Sicurezza
Vedi [SECURITY.md](SECURITY.md). Se scopri una vulnerabilità, **non aprire
una issue pubblica**: usa GitHub Security Advisories.

## Setup dev

```bash
git clone https://github.com/<user>/argo-osint.git
cd argo-osint
python -m venv .venv && . .venv/bin/activate   # oppure .venv\Scripts\activate
pip install -e '.[ai,postgres,queue]'          # extras opzionali
cp .env.example .env                           # configura almeno OSINT_WEB_TOKEN
python -m pytest tests/ -q                     # deve passare tutto
python -m osint_bot.web --port 7655            # avvia il backend
```

Frontend Next.js opzionale in `web-next/` (vedi `web-next/README.md`).

## Stile di codice

- **Python 3.10+**, type hints dove aiutano la leggibilità.
- Commenti solo dove il WHY è non ovvio; niente commenti "questa è la funzione X".
- Naming italiano nei messaggi utente/documenti, inglese nel codice.
- **Test**: ogni connettore ha un `tests/test_connector_<name>.py` offline.

## Processo PR

1. Fai fork + branch da `main` (`feat/<nome>`, `fix/<nome>`).
2. Un commit = un cambio logico; commit message imperativo in inglese.
3. `pre-push`: `python -m pytest tests/ -q` deve passare.
4. Nella PR: descrivi cosa cambia, perché, come l'hai testato.
5. Un maintainer fa review; sii aperto a discussione.

## Codice di condotta

Vedi [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). In sintesi: sii rispettoso,
non pubblicare dati personali di terzi negli esempi, niente attacchi ad
personam.

Grazie per il tuo tempo. 💛
