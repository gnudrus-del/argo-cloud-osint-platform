# Argo Cloud OSINT Platform

> Una piattaforma OSINT difensiva self-hosted per analisti che hanno bisogno di indagini con fonti verificabili, catena audit e attenzione alla privacy.

Argo gira interamente sulla tua infrastruttura. Aggrega fonti pubbliche (58 connettori nativi, key-free e BYOK), tiene una catena audit SHA-256 di ogni finding e produce report in Markdown, JSON, PDF, STIX 2.1 e MISP. UI e output dei connettori sono bilingui (italiano / inglese). Niente telemetria, niente dipendenza cloud, niente vendor lock-in.

## Perché Argo

Le SaaS OSINT esistenti funzionano bene finché non puoi inviare i dati del caso a un cloud terzo — indagini regolamentate, due diligence aziendale, protezione delle fonti giornalistiche, casi legali con obblighi di riservatezza. Argo gira sulla **tua** macchina o VM. I tuoi lead e i tuoi finding non escono mai dal tuo perimetro **di default** — l'unica eccezione sono le capability IA (LLM) opzionali e opt-in, che inviano dati del caso a un provider BYOK a tua scelta solo se le abiliti esplicitamente; vedi [`docs/THREAT_MODEL.md`](THREAT_MODEL.md).

## Caratteristiche principali

- **CLI + web UI** — CLI Python per lo scripting; web UI leggera (nessun framework runtime bloat) per la gestione dei casi.
- **UI e output bilingui (italiano / inglese)** — rilevata automaticamente al primo accesso, persistente per utente, sempre commutabile dal controllo nella barra in alto. Le stringhe `notes`, `remediation` e `legal_note` dei connettori passano da un catalogo condiviso e vengono tradotte per richiesta (`ConnectorContext.lang`).
- **Investigazioni case-based** — ogni query vive dentro un caso con scope, Rules of Engagement e endpoint DSAR (GDPR).
- **Target handling privacy-by-design** — target personali richiedono base giuridica esplicita; i contatti sono redatti di default.
- **Modello BYOK** — 15 provider opzionali (Shodan, VirusTotal, HIBP, SecurityTrails, ecc.) usano *le tue* chiavi, mai intermediati. Altri 3 (EmailRep, IPinfo, OpenCorporates) funzionano anche senza chiave, ma la sfruttano se configurata.
- **58 connettori nativi** — 43 key-free + 15 BYOK.
- **HTTP outbound hardened SSRF** — ogni connettore, più il fetcher usato da CLI e job queue (campo `seed_urls`), passa da `_safe_http`: blocco cloud metadata, loopback, RFC1918, schemi non-HTTP e redirect cross-boundary (inclusa la risoluzione di `robots.txt`). Enforced in CI.
- **DSAR reale (GDPR Art. 15 / Art. 17)** — l'endpoint di cancellazione esegue una transazione atomica con prova hash-chained `dsar_tombstoned`.
- **Finding con fonte** — ogni finding porta URL di evidenza, timestamp e confidence.
- **Catena audit (SHA-256)** — ogni evento è appeso a un log hash-chained. Modificare un evento passato invalida tutti gli hash successivi.
- **Sigillo dei report (Ed25519, sempre attivo)** — ogni job completato viene sigillato automaticamente: evidenze e file di report finiscono in un manifest, firmato con la chiave Ed25519 dell'istanza, registrato nella catena audit. Timestamp RFC3161 opzionale verso una TSA a tua scelta (esce solo un digest SHA-256 di 32 byte, mai il contenuto del caso) — verificabile offline con `argo-verify-report` o strumenti standard (`openssl ts -verify`). Vedi [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) per cosa dimostra davvero e cosa no.
- **Export Markdown / JSON / PDF / STIX 2.1 / MISP**.
- **Architettura a connettori/plugin** — aggiungi una fonte con ~50 righe.
- **Deploy Docker + self-hosted** — include Dockerfile, docker-compose, unit systemd e ricetta Caddy reverse-proxy.

## Cosa Argo *non* fa

Argo è uno strumento **difensivo**. Rifiuta di essere un'arma.

- **No doxxing.** Target personali richiedono base giuridica esplicita e output redatti di default.
- **No stalking.** Nessun monitoraggio continuo di individui.
- **No bypass login / credential stuffing / account takeover.**
- **No scraping aggressivo.** Rispetta rate limit e `robots.txt`.
- **No scansioni non autorizzate.** La recon attiva richiede caso in-scope ed emette eventi di audit.
- **No acquisto/rivendita di dati privati.** Le integrazioni HIBP/simili sono per verifica di account **propri**, non per lookup di massa.

## Quickstart

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

Prima CLI (nessuna chiave richiesta):

```bash
argo-osint example.com --type domain --provider none \
    --output-dir reports/smoke --format both
```

Avvio web UI:

```bash
export OSINT_WEB_TOKEN="scegli-un-token-lungo"
python -m osint_bot.web --host 127.0.0.1 --port 8000
# apri http://127.0.0.1:8000
```

Docker:

```bash
export OSINT_WEB_TOKEN="scegli-un-token-lungo"
docker compose up --build
```

## Documentazione

- [Quickstart completo](QUICKSTART.md)
- [Installazione](INSTALLATION.md)
- [Deploy (VM, Docker, Cloudflare Tunnel, stack avanzato)](DEPLOY.md)
- [Configurazione](CONFIGURATION.md)
- [Connettori](CONNECTORS.md)
- [Esempi](EXAMPLES.md)
- [Uso responsabile](RESPONSIBLE_USE.md)
- [Threat model](THREAT_MODEL.md)
- [Roadmap](ROADMAP.md)
- [FAQ](FAQ.md)

## Licenza

Apache License 2.0 — vedi [`LICENSE`](../LICENSE).

## Come contribuire

Vedi [`CONTRIBUTING.md`](../CONTRIBUTING.md). Domande su [Discussions](https://github.com/gnudrus-del/argo-cloud-osint-platform/discussions).

## Stella al progetto

Se Argo ti è utile, mettere una stella al repository aiuta altri analisti a trovarlo. È la cosa più utile che puoi fare senza scrivere codice.
