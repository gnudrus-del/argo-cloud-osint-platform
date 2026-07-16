# Matrice di sostituzione — cosa il nuovo stack rimpiazza e cosa va rimosso

Principio: **ogni componente nuovo sostituisce uno vecchio, che va decommissionato.**
Niente doppioni in esecuzione — su una VM piccola, tenere entrambi gli stack
attivi in parallelo rischia l'OOM.

Legenda: 🟢 = sostituito completamente, rimuovibile · 🟡 = sostituito solo in
parte, resta per i casi profondi · ⚪ = nuovo, non sostituisce nulla.

## Servizi (container / processi)

| Nuovo (Argo nativo) | Sostituisce | Azione |
|---|---|---|
| Neo4j Argo (`stack-compose` profile `graph`) + `neo4j_sync` | 🟢 Grafo di **FlowSINT** | Se usavi FlowSINT come graph store, Argo scrive ora il proprio grafo nativamente. |
| Coda **Celery/Redis** Argo (profile `queue`) | 🟢 **Redis + Celery di FlowSINT** e coda in-process | Un solo broker/worker: quello di Argo. |
| **Postgres** Argo (profile `db`) + `storage_postgres` | 🟢 **Postgres di FlowSINT** e SQLite (archiviato) | Un solo DB relazionale. SQLite archiviato come backup. |
| Connettori nativi (`dns_query`, `tls_cert`, `gravatar`, `common_crawl`, `web_fingerprint`, `shodan_internetdb`, `overpass`, `threatfox`, `asn_lookup`) | 🟢 **Enricher di FlowSINT** (FastAPI + Nginx + Celery FlowSINT) | Gli enricher richiamati in precedenza via il bridge `flowsint` sono ora nativi in-process. |
| `misp` connector | ⚪ nuovo (bridge a MISP esterno se presente) | — |
| OpenSearch Argo (profile `search`) | ⚪ nuovo (ricerca full-text: FlowSINT non l'aveva) | — |

**Conseguenza:** se avevi uno stack **FlowSINT standalone (6 container: nginx,
fastapi, postgres, redis, neo4j, celery, ~1 GB)** attivo, diventa ridondante →
`decommission.sh` lo spegne e ne archivia i volumi. Il connettore-bridge
`flowsint` resta nel codice ma, con FlowSINT spento, ritorna
`missing_key`/`error` in modo graceful (o rimuovilo dal registry se vuoi
pulizia totale — vedi sotto).

## Tool CLI

| Nuovo (Argo nativo) | Sostituisce | Azione |
|---|---|---|
| `content_discovery` (fuzzing path, ATTIVO) | 🟢 **ffuf, dirsearch, feroxbuster, arjun** | Wordlist curata high-signal + soft-404 filter. Rimuovi i 4 binari + `*_CMD`. |
| `port_scan` (TCP-connect, ATTIVO) | 🟢 **naabu**, 🟡 **nmap/masscan** | Inventario porte + banner. Per SYN/stealth/UDP raw resta nmap on-demand (non nel path auto). |
| `subdomain_enum` (crt.sh+brute+CC) | 🟢 **subfinder, amass, fierce, dnsenum** | CT logs + bruteforce DNS + storici. |
| `dnstwist_native` | 🟢 **dnstwist** | Permutazioni + risoluzione (typosquat/phishing). |
| `secret_scan` (regex catalog) | 🟢 **secretfinder**, 🟡 **gitleaks/trufflehog** | Segreti nel contenuto web/JS. Scansione history repo Git resta a gitleaks. |
| `url_harvest` (Wayback CDX) | 🟢 **waybackurls, gau, hakrawler, linkfinder**, 🟡 **gospider/katana** | URL storiche + endpoint interessanti. Crawling JS attivo resta a gospider/katana. |
| `holehe_native` (Gravatar+MX+disposable) | 🟡 **holehe, mosint, infoga** | Caso rapido nativo; copertura ~120 siti resta a holehe CLI on-demand. |
| `phone_meta` (libphonenumber) | 🟢 **phoneinfoga, phunter** | Rimuovi binari + `PHONEINFOGA_CMD`. |
| `dns_query` (dig+socket) | 🟢 **dnsx** (lookup base) | Record A/AAAA/MX/NS/TXT/CNAME nativi. |
| `tls_cert` (ssl nativo) | 🟢 **testssl** (lettura cert) | Audit TLS cipher-level approfondito resta testssl on-demand. |
| `web_fingerprint` | 🟢 **whatweb, wafw00f** (base) | Server/tech/cookie/CSP nativi. |
| media.py EXIF/GPS pure-python | 🟢 **exiftool** (immagini) | Metadati JPEG/GPS nativi. `ffprobe` resta per video. |
| `asn_lookup`, `overpass`, `threatfox`, `shodan_internetdb`, `enrichment_ai`, `stix_export` | ⚪ nuovi | — |

### Restano (capacità non replicabili nativamente in modo onesto)
- **Maigret** (~3000 siti) per username deep-scan; `sherlock_lite` copre il rapido.
- **nmap/masscan** per SYN/stealth/UDP e detection avanzata (raw socket + root).
- **nuclei, wpscan, dalfox, nikto** (template/vuln engine attivi): fuori scope nativo sano.
- **ffprobe, yt_dlp** (video/streaming binari).
- **spiderfoot, recon_ng** (framework di orchestrazione — Argo È l'orchestratore ora,
  quindi valuta se dismetterli del tutto).
- **enum4linux, smbmap, snmpwalk** (protocolli SMB/SNMP).
- **ghunt, instaloader, toutatis, osintgram, snscrape** (scraping social autenticato).
- **eyewitness, singlefile** (screenshot/archiviazione via browser headless).

## Ordine operativo consigliato
1. (Se usi Postgres) migra i dati: `python -m osint_bot.migrate_sqlite_to_postgres`.
2. Porta su lo stack Argo: `install-stack.sh db queue graph search`.
3. Aggiorna `.env` con le var di `dotenv.stack.template`, riavvia `argo-osint`.
4. Verifica che le nuove capability rispondano (grafo/coda/ricerca).
5. **Solo allora** decommissiona i doppioni: `decommission.sh flowsint sqlite phoneinfoga`.
