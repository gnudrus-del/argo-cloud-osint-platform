# OSINT Bot

Un bot CLI e piattaforma web per ricerche OSINT difensive e verificabili. Raccoglie solo informazioni pubbliche, conserva le fonti, applica limiti di velocita, rispetta `robots.txt` e genera report Markdown, JSON e PDF dalla UI web.

## Uso etico

Usalo solo per ricerche legittime: asset propri o autorizzati, aziende, domini, threat intelligence difensiva, due diligence professionale o ricerca di pubblico interesse. Per target personali il bot richiede conferma esplicita e redige i contatti per impostazione predefinita.

Non e progettato per doxxing, stalking, aggiramento di login, scraping aggressivo, acquisto di dati, deanonymization o raccolta di dati sensibili.

## Setup

```powershell
cd <path\to\argo-osint>
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Configura almeno un provider di ricerca, oppure passa URL seed manuali. La modalita predefinita e `all`: usa tutte le API configurate e genera dork verificabili per Google, Bing, DuckDuckGo e Yandex.

```powershell
$env:BING_SEARCH_API_KEY="..."
$env:BRAVE_SEARCH_API_KEY="..."
# oppure
$env:SERPER_API_KEY="..."
$env:SHODAN_API_KEY="..."
$env:CENSYS_API_ID="..."
$env:CENSYS_API_SECRET="..."
$env:HIBP_API_KEY="..."
$env:HUNTER_API_KEY="..."
$env:INTELX_API_KEY="..."
$env:EPIEOS_API_KEY="..."
```

Per salvare le chiavi nell'utente Windows senza inserirle nei file del progetto:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-api-keys.ps1
```

Riavvia poi la piattaforma: i processi gia avviati non leggono le nuove variabili d'ambiente.

## Esempi

Ricerca su un dominio:

```powershell
osint-bot example.com --type domain --depth 2 --max-results 12
```

Ricerca su un'azienda:

```powershell
osint-bot "Example Inc" --type company --depth 2
```

Ricerca autorizzata su una persona, con contatti redatti:

```powershell
osint-bot "Nome Cognome" --type person --confirm-authorization
```

Senza API, usando URL pubblici di partenza:

```powershell
osint-bot example.com --type domain --provider none --seed-url https://example.com
```

Comando naturale con scelta automatica degli agenti:

```powershell
osint-bot --command "Analizza example.com come dominio, valuta OPSEC, geo pubblica e report investigativo"
```

Avvio piattaforma web:

```powershell
$env:OSINT_WEB_TOKEN="scegli-un-token-lungo"
$env:OSINT_SIGNUPS_ENABLED="1"
python -m osint_bot.web --host 127.0.0.1 --port 8000
```

Guida deployment: `DEPLOYMENT.md`.

Avvio con Docker:

```powershell
$env:OSINT_WEB_TOKEN="scegli-un-token-lungo"
docker compose up --build
```

Apri `http://127.0.0.1:8000`.

### Dashboard e ricerca globale

La home è una dashboard in stile motore di ricerca OSINT. Una barra di ricerca
unica rileva automaticamente il tipo di entità inserita (nome, username, email,
telefono, dominio, azienda, IP, wallet) e pre-compila il flusso di ricerca
guidato, portando con sé il caso selezionato. Il rilevamento client-side serve
solo a pre-compilare i campi: la classificazione autorevole resta server-side
(`classify_target`).

> Gating dati personali: per email, telefoni e nomi di persona la ricerca
> richiede un caso attivo con base giuridica documentata e conferma di
> autorizzazione. La barra non avvia automaticamente job su dati personali senza
> un caso.

La dashboard aggrega, per l'utente corrente, casi recenti, report recenti, stato
dei job, copertura delle fonti (provider e tool configurati via BYOK) e avvisi di
privacy/compliance (es. casi senza base giuridica chiara). Tutti i dati arrivano
dall'endpoint `GET /api/dashboard`, che riusa gli helper esistenti e non espone
mai dati di altri utenti.

### Profilo entità

Da un report completato (sezione **Report** → *Apri profilo entità*) si apre il
profilo aggregato dell'entità, costruito client-side dai dati del report del caso
(nessun archivio cross-caso: persistenza **per-caso**, privacy-by-design). Il
profilo è organizzato in tab — Overview, Identificatori, Social, Domini/Aziende,
Contatti, Media/Geo, Crypto, Evidenze, Timeline, Audit — e mostra:

- **Overview**: confidenza media, conteggi, avvertenze su dati incerti e
  **omonimi** (identità simili non vengono mai unite automaticamente) e l'elenco
  delle **fonti consultate** (provider di ricerca + host delle evidenze).
- **Evidenze**: ogni finding con severità, valore, confidenza e **link cliccabili
  alla fonte** (aperti in scheda isolata con `rel="noopener noreferrer"`).
- **Audit**: tracciabilità del report (generazione, query verificabili, moduli
  eseguiti). La catena di audit firmata SHA-256 resta lato server.

I contatti sono mostrati con il valore già redatto lato server (`safe_display`).

## Architettura core

Il core e organizzato per moduli isolati: ogni tool OSINT viene eseguito tramite un plugin con input tipizzato e output normalizzato. La pipeline web usa una coda job in background, produce avanzamento progressivo, mantiene un audit log append-only e arricchisce i report con entita e relazioni. Il viewer web include timeline del job, export PDF e grafo entita con pivot assistito.

Documenti tecnici:

- `docs/ARCHITECTURE.md`: mappa attuale, debito tecnico, rischi e roadmap.
- `docs/CONTRIBUTING_MODULES.md`: contratto per aggiungere nuovi moduli OSINT.

## Repository e strumenti

I repository OSINT curati sono nel catalogo `config/tool_catalog.json` e possono essere clonati con:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-repos.ps1 -CloneOnly
```

Gli agenti scelgono automaticamente gli strumenti in base al tipo di ricerca. Per esempio, su un dominio selezionano `theHarvester`, `amass`, `subfinder`, `waybackurls`, `gau`, `Shodan`, `Censys`, `SpiderFoot` e `Recon-ng` quando configurati; su username autorizzati selezionano `Sherlock`, `Maigret`, `Socialscan`, `Social Analyzer`, `Toutatis` e `Osintgram`; su email autorizzate selezionano `Holehe`, `Socialscan`, `h8mail` e `GHunt`.

Per username/social la UI imposta il percorso rapido `Username / social`: i tool cercano profili pubblici candidati. La piattaforma non recupera email o telefoni privati di registrazione dei social; puo raccogliere solo contatti pubblicamente visibili nelle fonti.

Il report include sempre query/dork usati, fonti principali, checklist di verifica manuale e fascicolo finale separato in fatti osservati, inferenze e ipotesi operative. I dork e i link servizio non vengono trasformati in fatti: sono fonti da aprire e verificare.

Per controllare quali comandi sono disponibili nel sistema:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-tools.ps1 -CheckOnly
```

Esecuzione multi-agent con moduli difensivi:

```powershell
osint-bot example.com --type domain --agent planner --agent web --agent geo
```

Wrapper per tool OSINT installati localmente:

```powershell
osint-bot myhandle --type handle --confirm-authorization --agent external --external-tool sherlock
osint-bot myhandle --type handle --confirm-authorization --agent external --external-tool maigret
osint-bot user@example.com --type email --confirm-authorization --agent external --external-tool holehe
osint-bot example.com --type domain --confirm-authorization --allow-network-scan --agent external --external-tool nmap
```

Configura i path se i comandi non sono nel `PATH`:

```powershell
$env:SHERLOCK_CMD="C:\tools\sherlock\sherlock.exe"
$env:MAIGRET_CMD="C:\tools\maigret\maigret.exe"
$env:HOLEHE_CMD="C:\tools\holehe\holehe.exe"
$env:NMAP_CMD="C:\Program Files (x86)\Nmap\nmap.exe"
```

I report vengono salvati in `reports/`.

## Output

Il Markdown e pensato per essere letto da un analista. Il JSON contiene le stesse evidenze in forma strutturata per successive pipeline. La piattaforma web genera anche PDF scaricabili per i report completati.

Se vuoi trasformarlo in un bot Telegram, Discord o web app, il punto di ingresso da riusare e `osint_bot.cli.run_investigation`.

## Cosa non fa

- Non esegue scraping aggressivo o bypass di limiti/robots/login.
- Non cerca indirizzi privati, date di nascita o intestatari di numeri telefonici.
- Non attribuisce wallet crypto, profili social o email a persone senza fonti indipendenti.
- Non usa `nmap` su asset non autorizzati.
- Non automatizza elicitazione ingannevole, impersonificazione o pressione psicologica.
- Non accede a mercati, credenziali o contenuti illegali nel dark web.
