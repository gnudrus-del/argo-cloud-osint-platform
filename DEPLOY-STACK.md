# Deploy dello stack avanzato Argo (Fasi 4-13)

Guida per portare in produzione, sulla VM, tutto ciò che è stato aggiunto:
export STIX/MISP, connettori nativi, AI locale, storage Postgres, frontend
Next.js, Neo4j, OpenSearch, coda Celery — **sostituendo** i componenti resi
ridondanti (vedi `deploy_artifacts/REPLACEMENTS.md`).

> Principio guida: **ogni cosa nuova rimpiazza una vecchia, che va decommissionata.**
> Niente doppioni in esecuzione. Su una VM da 5.9 GB (che gira già FlowSINT ~1 GB)
> lo stack Argo prende il posto di quello FlowSINT.

## 0. Prerequisiti
- Codice aggiornato in `/opt/argo-osint` (usa `deploy.ps1`/`deploy.sh` come sempre).
- Servizio base `argo-osint` attivo dietro Caddy (invariato).

## 1. Cosa NON richiede nulla (già attivo dopo il deploy del codice)
Queste capability sono in-process e non hanno dipendenze esterne:
- Export **STIX 2.1 / MISP** → `/api/jobs/{id}/stix.json` · `/misp.json`
- Connettori nativi Fasi 10-13 (DNS, TLS, ASN, Gravatar, Common Crawl, web
  fingerprint, Shodan InternetDB, Overpass, ThreatFox, **content_discovery,
  port_scan, subdomain_enum, dnstwist, secret_scan, url_harvest, holehe**)
- **NER + summarization** (regex/pure-python). OCR/traduzione richiedono l'extra `ai`.

Verifica: `GET /api/capabilities` mostra `ai_enrichment`, `external_stores`, `queue`.

## 2. AI opzionale (OCR/spaCy/traduzione)
```bash
sudo -u ubuntu /opt/argo-osint/.venv/bin/pip install -e '/opt/argo-osint[ai]'
sudo apt-get install -y tesseract-ocr tesseract-ocr-ita   # binario OCR
sudo -u ubuntu /opt/argo-osint/.venv/bin/python -m spacy download it_core_news_sm
sudo systemctl restart argo-osint
```

## 3. Stack di supporto (Postgres / Neo4j / OpenSearch / Redis)
Attiva **solo i profili che vuoi** (ognuno sostituisce un pezzo di FlowSINT):
```bash
export ARGO_PG_PASSWORD='...'; export ARGO_NEO4J_PASSWORD='...'
cd /opt/argo-osint/deploy_artifacts
sudo -E bash install-stack.sh db queue graph search
```
Poi appendi a `/opt/argo-osint/.env` le righe di `dotenv.stack.template` che ti
servono (scommentandole) e riavvia:
```bash
sudo systemctl restart argo-osint argo-celery
```

### Migrazione dati SQLite → Postgres (se usi il profilo `db`)
```bash
sudo -u ubuntu /opt/argo-osint/.venv/bin/python -m osint_bot.migrate_sqlite_to_postgres \
    --dsn "postgresql://argo:${ARGO_PG_PASSWORD}@127.0.0.1:5433/argo"
```
Verifica che stampi `catena audit verificata`, poi imposta `DATABASE_URL` nell'.env.

## 4. Frontend Next.js (opzionale)
```bash
cd /opt/argo-osint/deploy_artifacts
sudo bash install-stack.sh web     # installa Node, build, servizio :3000
```
Esporlo via Caddy (esempio, su path `/console` o sottodominio):
```
handle_path /console* {
    reverse_proxy 127.0.0.1:3000
}
```
Il frontend legacy (`web_static/`) resta servito dal backend: la migrazione è
graduale, pagina per pagina.

## 5. Decommissionare i doppioni (DOPO aver verificato lo stack nativo)
```bash
cd /opt/argo-osint/deploy_artifacts
sudo bash decommission.sh flowsint sqlite tools
```
- `flowsint` → spegne i 6 container FlowSINT (volumi preservati; `-v` per cancellarli).
- `sqlite` → archivia `gufo.sqlite3` (solo se `DATABASE_URL` Postgres è attiva).
- `tools` → commenta nell'.env i `*_CMD` ora nativi (backup automatico).

Vedi `deploy_artifacts/REPLACEMENTS.md` per la matrice completa "nuovo → sostituisce".

## 6. Sizing / attenzione OOM
Heap tarati per VM piccola (OpenSearch 512m, Neo4j 512m+256m, Redis 192m,
Postgres ~384m). **Spegnendo FlowSINT** liberi ~1 GB + il suo Postgres/Redis/Neo4j,
che è esattamente ciò che lo stack Argo va a rimpiazzare. Se resti stretto,
attiva i profili in modo incrementale (prima `queue`+`graph`, poi `search`).

## 7. Sicurezza
- Tutti i servizi dello stack sono bindati su **127.0.0.1** (mai pubblici).
- OpenSearch gira con security plugin OFF: lecito **solo** perché non è esposto.
- Le password (`ARGO_PG_PASSWORD`, `ARGO_NEO4J_PASSWORD`, `MISP_KEY`, ecc.) stanno
  in `/opt/argo-osint/.env` (chmod 600) o in `stack.env`, mai nel repo.
