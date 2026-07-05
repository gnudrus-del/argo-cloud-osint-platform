# Architettura e roadmap di Gufo OSINT

Gufo OSINT e una piattaforma self-hosted per analisi OSINT difensive, verificabili e documentabili. Il principio guida e mantenere il core stabile: la UI deve guidare l'analista, i moduli devono essere isolati, ogni evidenza deve rimanere collegata a una fonte e le azioni attive devono essere autorizzate e tracciate lato server.

## Mappa dell'architettura attuale

### UI web

- `osint_bot/web_static/index.html`, `app.js`, `app.css`: interfaccia italiana con ricerca guidata, palette tema, profili OPSEC, provider SERP, aree di ricerca, intensita, report Markdown/JSON/PDF, timeline job, grafo entita, pivot assistito e upload media.
- La UI invia richieste HTTP al server stdlib in `osint_bot/web.py`.
- Le stringhe utente restano in italiano; il codice resta in inglese.

### Server applicativo

- `osint_bot/web.py`: server HTTP, autenticazione, sessioni HttpOnly, CSRF, security header, API protette, creazione job, stato job e rendering statico.
- `web_jobs/`: storage file-based per job, utenti e report generati.
- `osint_bot/job_queue.py`: coda background in-process con worker dedicato. Ogni job viene accodato, passa da `queued` a `running` e aggiorna la lista `progress`.
- `osint_bot/audit.py`: audit log append-only con hash chaining. Registra creazione, avvio, completamento ed errore job con target redatti quando necessario.

### Pipeline OSINT

- `osint_bot/cli.py`: punto di ingresso CLI e riuso della pipeline per il web.
- `osint_bot/orchestrator.py`: interpreta comandi naturali e costruisce profili di ricerca.
- `osint_bot/search.py`: provider SERP Brave, Bing, Serper e modalita multi-provider quando le API sono configurate.
- `osint_bot/dorks.py` e `osint_bot/discovery.py`: query, dork e seed URL verificabili.
- `osint_bot/fetch.py`, `extract.py`, `analyze.py`: recupero pagine pubbliche, estrazione e analisi.
- `osint_bot/agents.py`: agenti di analisi e ponte verso moduli esterni.
- `osint_bot/report.py`: report Markdown/JSON con separazione tra fatti osservati, inferenze e ipotesi operative.
- `osint_bot/pdf_report.py`: export PDF leggibile da Markdown, usato dalla piattaforma web per i job completati.

### Plugin e tool esterni

- `osint_bot/external_tools.py`: catalogo dei tool locali e wrapper subprocess con timeout.
- `osint_bot/plugins.py`: registro plugin, contesto uniforme e risultati normalizzati.
- Ogni plugin riceve input tipizzato tramite `PluginContext` e restituisce `PluginResult` con `status`, `findings`, `output`, `error`, `warnings` e `duration_ms`.
- L'esecuzione plugin e parallela e degrada in modo controllato: un modulo mancante, bloccato dai guardrail o in errore non ferma l'intera pipeline.

### Modello dati

- `osint_bot/models.py`: dataclass principali per risultati, pagine, evidenze, finding, agenti, indagini, entita e relazioni.
- `osint_bot/entities.py`: normalizza entita come dominio, URL, email, telefono, IP, wallet, username, media e organizzazioni; costruisce relazioni tra target, pagine, finding e citazioni.
- Email e telefoni hanno `display_value` redatto per ridurre esposizione accidentale nei report.

### Media e metadati

- `osint_bot/media.py`: analisi locale di immagini/video caricati, hash e dimensioni.
- I moduli ExifTool/reverse image restano una fase successiva: il core ora ha il punto in cui integrarli come plugin.

### Sicurezza e guardrail

- `osint_bot/safety.py`: separa OSINT passivo da azioni gated, blocca usi non consentiti e applica autorizzazioni lato server.
- `assert_external_tool_allowed` viene richiamato anche dal layer plugin, quindi il gating non dipende solo dalla UI.
- Secrets: oggi via variabili d'ambiente o script Windows, mai hardcoded nei file del progetto.

## Debito tecnico e rischi attuali

- Storage file-based: semplice e self-hostable, ma non ideale per concorrenza alta, multi-tenant reale, ricerca storica e retention GDPR granulare.
- Coda in-process: affidabile per una singola istanza, ma non sopravvive a crash/process restart come farebbe Redis/RQ/Celery o un job store persistente.
- Parsing tool ancora minimale: molti tool esterni vengono tradotti in finding tramite euristiche; servono parser dedicati per output JSON/CSV dove disponibili.
- Secrets non cifrati centralmente: manca un vault applicativo o integrazione con secret manager.
- Provider API incompleti: Shodan, Censys, HIBP, Hunter, VirusTotal, AbuseIPDB, ipinfo e Bright Data devono stare dietro adapter comuni con rate limit e auditing.
- Multi-tenancy predisposta ma non completa: servono isolamento dati per tenant, ruoli, quote, retention e cancellazione per caso.
- Il grafo UI e l'export PDF sono presenti, ma richiedono ancora funzioni avanzate: filtri, layout persistente, export grafico e viste caso.
- Osservabilita limitata: logging strutturato, metriche per modulo ed error tracking vanno aggiunti prima di un deploy serio.
- Docker/compose e CI base sono presenti; restano da aggiungere hardening container, scansioni security e test integrazione browser in pipeline.

## Roadmap prioritaria

### Fase 1 - Core affidabile

Stato: implementata in questo snapshot.

- Contratto plugin uniforme (`PluginContext`, `PluginResult`, registry).
- Esecuzione parallela dei moduli con timeout ed errore strutturato.
- Coda job background con avanzamento.
- Modello entita/relazioni e arricchimento automatico dei report.
- Audit log append-only con hash chain.
- Export PDF dei report completati.
- Viewer grafo entita con pivot assistito dalla UI.
- Test unitari per plugin, entita, audit log e coda.
- Documentazione architetturale e guida moduli.

### Fase 2 - Persistenza, provider e governance

- Sostituire lo storage file-based con repository astratti e backend SQLite/PostgreSQL.
- Aggiungere cache e deduplica query: chiave normalizzata su provider, target, modulo, profilo OPSEC e parametri.
- Introdurre adapter provider comuni per SERP e API key.
- Cifrare e centralizzare le chiavi con vault locale o integrazione secret manager.
- Aggiungere gestione casi, retention, cancellazione, versioning risultati e audit UI.
- Rendere l'audit log esportabile e verificabile.

### Fase 3 - Moduli OSINT estesi

- Username/SOCMINT: Sherlock, Maigret, WhatsMyName dataset, Social-Analyzer e holehe con parser dedicati.
- Dominio/Azienda: BBOT, SpiderFoot, theHarvester, Amass, Subfinder, OpenCorporates/Aleph, Shodan/Censys.
- Email/Telefono/IP: holehe, h8mail, HIBP, Hunter, PhoneInfoga, AbuseIPDB, VirusTotal e ipinfo.
- Crypto: explorer pubblici, tracing base e screening liste OFAC/SDN.
- Media: ExifTool, reverse image workflow e hashing esteso.
- Deep/dark web: OnionSearch, Ahmia, OnionScan e onion-lookup solo con gating server-side e autorizzazione esplicita.

### Fase 4 - Prodotto e piattaforma

- Raffinamento vista grafo: filtri, layout salvato, ricerca entita, export immagine.
- Export PDF avanzato con indice, allegati e copertina caso.
- Ruoli, permessi, quote, piani Pro e isolamento tenant.
- Estendere Docker/docker-compose e CI con test integrazione browser e security checks.
- Logging strutturato, metriche per modulo, error tracking e dashboard di salute.
- Layer agentico MCP-native opzionale per concatenare moduli e compilare report.

## Come verificare la Fase 1

```powershell
cd <path\to\argo-osint>
python -m compileall osint_bot
python -m unittest discover -s tests
node --check osint_bot\web_static\app.js
python -m osint_bot.cli example.com --type domain --provider none --max-pages 1 --output-dir reports\phase1-smoke --format both
```

Il report Markdown deve includere la sezione `Entita e relazioni`; il JSON deve includere `entities` e `relationships`; i job web completati devono esporre anche `/report.pdf`.
