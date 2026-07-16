# Deploy

Questa guida copre il deploy di Argo in produzione: Docker, VM self-hosted
(systemd + Caddy), Cloudflare Tunnel come alternativa senza VPS pubblico,
configurazione dei tool OSINT esterni e lo stack avanzato opzionale
(Postgres/Neo4j/OpenSearch/Celery). Per il primo avvio locale (CLI + web UI in
5 minuti) vedi [`docs/QUICKSTART.md`](QUICKSTART.md); per i dettagli
dell'immagine Docker vedi [`docs/DOCKER.md`](DOCKER.md).

Indice:

- [Panoramica](#panoramica)
- [Deploy rapido con Docker](#deploy-rapido-con-docker)
- [Deploy su VM (systemd + Caddy)](#deploy-su-vm-systemd--caddy)
- [Deploy senza VPS pubblico: Cloudflare Tunnel](#deploy-senza-vps-pubblico-cloudflare-tunnel)
- [Tool esterni: configurazione locale](#tool-esterni-configurazione-locale)
- [Stack avanzato opzionale (Postgres/Neo4j/OpenSearch/Celery)](#stack-avanzato-opzionale-postgresneo4jopensearchcelery)
- [Sicurezza operativa e classificazione](#sicurezza-operativa-e-classificazione)
- [Piano gratuito e upgrade](#piano-gratuito-e-upgrade)

## Panoramica

Argo ha due parti:

- `osint_bot.web`: backend + UI, esegue agenti, job e tool installati sulla
  macchina.
- Un reverse proxy pubblico (Caddy su VM, o un tunnel) che rende il backend
  raggiungibile da internet.

Cloudflare Pages e Workers vanno bene per frontend statici e funzioni edge, ma
non sono adatti a eseguire binari locali come `nmap`, `sherlock`, `maigret`,
`holehe`, `phoneinfoga`, `exiftool` o `ffprobe`. Per questi serve una macchina
runner: PC locale, server, VM o container.

## Deploy rapido con Docker

Per build locale, `docker compose`, immagine prebuilt GHCR, volumi e
healthcheck vedi la guida completa [`docs/DOCKER.md`](DOCKER.md). In sintesi:

```bash
export OSINT_WEB_TOKEN="scegli-un-token-lungo"
export POSTGRES_PASSWORD="scegli-un-altro-valore-lungo"
docker compose up --build
```

Il container espone `http://0.0.0.0:8000` (mappato su `127.0.0.1:8000` in
locale). Per HTTPS pubblico usa comunque un reverse proxy (Caddy, Traefik,
nginx), Cloudflare Tunnel, una VPN o Cloudflare Access — imposta
`OSINT_SECURE_COOKIE=1` e `OSINT_HSTS=1` quando servi su HTTPS.

## Deploy su VM (systemd + Caddy)

Configurazione raccomandata a costo zero, usata come riferimento in questa
sezione: **Oracle Cloud Ampere A1 (Always Free) + Caddy (HTTPS automatico) +
Resend (email transazionale)**. Qualsiasi altra VM Ubuntu con IP pubblico e
qualsiasi provider email SMTP/API funzionano allo stesso modo — sostituisci
provider e hostname dove serve.

| Componente | Esempio | Note |
|------------|----------|------|
| Server | Oracle Cloud Ampere A1 (4 OCPU, 24 GB RAM) | Always Free, no scadenza; qualsiasi VM Ubuntu 24.04 va bene |
| Dominio | DuckDNS (free) o un dominio proprio | DuckDNS dà `*.duckdns.org` gratis |
| Reverse proxy + HTTPS | Caddy (Let's Encrypt automatico) | TLS gratis, rinnovo auto |
| Email transazionale | Resend.com (o altro provider SMTP/API) | Free tier tipico: 3.000 email/mese, 100/giorno |

> Tempo di setup indicativo: ~45 minuti (di cui ~15 di attesa per la
> propagazione DNS).

### Provisioning (esempio Oracle Cloud Always Free)

1. Account: https://signup.cloud.oracle.com — serve carta di credito per la
   verifica (non viene mai addebitato il tier Always Free).
2. Console → **Compute → Instances → Create Instance**.
3. Image: **Ubuntu 24.04** (ARM 64 Ampere).
4. Shape: **VM.Standard.A1.Flex** → 2 OCPU, 12 GB RAM (basta; puoi espandere
   fino a 4/24 free).
5. Networking: **Assign public IPv4** — sì.
6. SSH key: incolla la tua chiave pubblica (`~/.ssh/id_ed25519.pub`).
7. Crea l'istanza. Annota l'IP pubblico.
8. **Apri porte** in Security List: Console → Networking → VCN → Default
   Security List → Add Ingress Rule → TCP 80 e TCP 443 da `0.0.0.0/0`.
9. **Apri firewall del sistema** (su Ubuntu Oracle preinstalla iptables):

   ```bash
   ssh ubuntu@<IP>
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   ```

### DNS

Con DuckDNS (5 min):

1. Vai su https://www.duckdns.org — login con GitHub/Google.
2. Scegli un subdomain, es. `argo-tuonome`.
3. Incolla l'IP pubblico della VM nel campo "current ip" → Update.
4. Il tuo URL sarà `https://argo-tuonome.duckdns.org`.

Se hai già un dominio (es. `tuonome.it`), aggiungi invece un record A che
punta all'IP della VM. Caddy fa il resto.

### Installazione sul server

```bash
ssh ubuntu@<IP>

# Sistema base
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git curl debian-keyring debian-archive-keyring apt-transport-https

# Caddy
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy

# Clona Argo (o copia via scp)
cd /opt
sudo mkdir argo-osint && sudo chown ubuntu:ubuntu argo-osint
cd argo-osint
# Copia tutto il contenuto del repo qui

# Setup venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .   # o `pip install -r requirements.txt` se preferisci quel percorso
```

> In alternativa ai passi manuali sopra, `scripts/bootstrap-vm-fresh.sh`
> automatizza il provisioning base (Python, utente di servizio, unit systemd,
> reverse proxy Caddy) su una VM Ubuntu pulita — vedi
> [`docs/INSTALLATION.md`](INSTALLATION.md) sezione C.

### Configurazione environment

Crea `/opt/argo-osint/.env` (chmod 600):

```bash
# Auth secrets
OSINT_WEB_TOKEN=  # vuoto = nessun token statico, solo auth utente
EMAIL_VERIFICATION_SECRET=<openssl rand -hex 32>

# Email (Resend, o altro provider)
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_xxxxxxxxxxxxxx
EMAIL_FROM_ADDR=noreply@argo-tuonome.duckdns.org
EMAIL_FROM_NAME=Argo

# Base URL (usato nei link di verifica)
EMAIL_VERIFICATION_BASE_URL=https://argo-tuonome.duckdns.org

# Sicurezza cookie
OSINT_SECURE_COOKIE=1
OSINT_SESSION_TTL_SECONDS=28800
```

Genera il secret:

```bash
echo "EMAIL_VERIFICATION_SECRET=$(openssl rand -hex 32)" >> .env
```

Setup Resend:

1. https://resend.com — signup free.
2. Verifica il dominio (puoi anche usare `onboarding@resend.dev` come from
   address senza verifica per i primi test).
3. API Keys → Create API Key → copia in `.env`.

### Servizio systemd

Crea `/etc/systemd/system/argo-osint.service`:

```ini
[Unit]
Description=Argo bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/argo-osint
EnvironmentFile=/opt/argo-osint/.env
ExecStart=/opt/argo-osint/.venv/bin/python -m osint_bot.web --port 7655 --host 127.0.0.1
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now argo-osint
sudo systemctl status argo-osint
```

### Reverse proxy Caddy

Sostituisci `/etc/caddy/Caddyfile`:

```caddy
argo-tuonome.duckdns.org {
    encode gzip
    reverse_proxy 127.0.0.1:7655 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), camera=(), microphone=()"
        -Server
    }
    log {
        output file /var/log/caddy/argo-access.log
        format json
    }
}
```

```bash
sudo systemctl reload caddy
```

Caddy chiede automaticamente il certificato Let's Encrypt al primo accesso.

### Test

Da browser: `https://argo-tuonome.duckdns.org`

1. Iscrizione → inserisci username + email + password (≥ 12 caratteri).
2. Ricevi email dal provider configurato con link di verifica.
3. Click sul link → account attivato.
4. Login.

### Aggiornamenti successivi

Una volta che la VM è in piedi, per pubblicare le modifiche locali ci sono due
modalità equivalenti:

- **Bash (default consigliato — usabile anche dall'assistente):** `./deploy.sh`,
  `./verify-live.sh`, `./rollback.sh` — wrapper sottili che invocano i
  corrispondenti `.ps1` con i parametri giusti e l'host pubblico.
- **PowerShell (manuale):** lancia direttamente [`deploy.ps1`](../deploy.ps1),
  [`verify-live.ps1`](../verify-live.ps1), [`rollback.ps1`](../rollback.ps1).

Lo script copia **solo** `osint_bot/` in `/opt/argo-osint/osint_bot/`, quindi
**non tocca** `.env`, `web_jobs/` né il `.venv` remoto. Esegue in ordine: test
SSH → backup remoto (`osint_bot.bak-YYYYMMDD-HHMMSS`) → copia (rsync con
`--delete`, fallback scp) → `sudo systemctl restart argo-osint` → status →
health check su `/api/dashboard` (200/401/403 = backend attivo).

**Prerequisiti:** client OpenSSH (`ssh`/`scp`, inclusi in Windows 10/11) e
accesso con la stessa chiave SSH usata per la VM. `rsync` è opzionale (se
assente usa scp).

```bash
# anteprima senza modificare la VM (consigliato la prima volta)
./deploy.sh --dry-run

# deploy reale
./deploy.sh
```

Override host: `HOST=argo-altro.duckdns.org ./deploy.sh`. Parametri
PowerShell utili (`-IdentityFile <chiave>`, `-Port <n>`, `-User`,
`-RemotePath`, `-Service`, `-HealthUrl`) restano disponibili passando
direttamente a `deploy.ps1`. Nessun IP/segreto è hardcoded in alcuno script.

**Verifica automatica post-deploy** (read-only, solo HTTP, niente SSH):

```bash
./verify-live.sh
```

Controlla in sequenza: HTTP `/api/dashboard` (401/403/200 = nuovo backend, 404
= vecchio), marker `renderAuditTab` / `/api/dashboard` / `evidenceHostLabel`
in `/app.js`, marker Fase 1 in `/app.css`, `id="panel-dashboard"` in `/`.
Stampa `VERSIONE NUOVA ONLINE` oppure `VERSIONE INCOMPLETA / VECCHIA` con
dettaglio.

**Cache del browser:** i file statici sono serviti con `Cache-Control:
no-cache, must-revalidate` + `ETag`. Il browser rivalida ogni volta: 304
quando invariato, 200 con la nuova versione appena cambia. **Ctrl+F5 non è più
necessario** dopo un deploy.

**Rollback automatico** con `./rollback.sh` (sceglie da solo il backup più
recente, ma puoi listare/selezionare):

```bash
./rollback.sh -List                                # elenca backup
./rollback.sh -DryRun                              # anteprima
./rollback.sh                                      # esecuzione (chiede 'yes')
./rollback.sh -BackupName 20260629-153002 -Force   # backup specifico
```

Lo script salva sempre la versione corrente in
`osint_bot.rollback-rescue-<ts>` prima di sostituirla, quindi **il rollback
stesso è annullabile**: in caso di errore stampa il comando di recupero.

**Rollback manuale** (se non puoi usare lo script) — `deploy.ps1` stampa il
comando esatto con il timestamp reale:

```bash
ssh ubuntu@<IP> "rm -rf /opt/argo-osint/osint_bot && mv /opt/argo-osint/osint_bot.bak-YYYYMMDD-HHMMSS /opt/argo-osint/osint_bot && sudo systemctl restart argo-osint"
```

### Tool CLI esterni sulla VM (`install-tools-vm.sh`)

Per attivare i tool OSINT esterni (sherlock, maigret, holehe, subfinder, ...),
copia ed esegui sulla VM lo script `scripts/install-tools-vm.sh`:

```bash
scp scripts/install-tools-vm.sh ubuntu@<HOST>:/tmp/
ssh ubuntu@<HOST> 'sudo bash /tmp/install-tools-vm.sh'
```

Cosa fa (idempotente):

- **Tier 1 (apt)** — whatweb, wafw00f, exiftool, dnstwist, dnsenum, whois, jq,
  curl, wget.
- **Tier 2 (pip)** — venv dedicato `/opt/argo-tools/.venv` con
  sherlock-project, maigret, holehe, theHarvester, socialscan, h8mail
  (symlinkati in `/opt/argo-tools/bin`).
- **Tier 3 (bin)** — binari precompilati dalle GitHub Releases: subfinder,
  httpx, amass, trufflehog (in `/opt/argo-tools/bin`).
- **Drop-in systemd** — `/etc/systemd/system/argo-osint.service.d/tools-path.conf`
  estende il `PATH` del servizio includendo `/opt/argo-tools/bin`, riavvia
  `argo-osint`. Il file della unit originale non viene toccato.

Tool **NON installati per policy OPSEC** (richiedono autorizzazione esplicita
prima dell'uso): `nmap`, `masscan`, `nuclei`, `wpscan`, `naabu`, `katana`.
Installazione manuale con `sudo apt install <tool>` quando lo scope di un caso
lo autorizza esplicitamente.

Verifica:

```bash
sudo bash /tmp/install-tools-vm.sh --check     # lista locale
```

oppure dal pannello UI **Chiavi API** → sezione *Stato copertura*: dopo il
restart del servizio (~30s di cache health-check) i tool installati mostrano
il pallino verde.

#### Installer v2 (set completo)

Per coprire tutti i ~60 tool del catalogo (oltre OSINT passivo, anche scanner
attivi gated da scope/red-team policy, e tool che richiedono credenziali
utente), esegui dopo il v1:

```bash
scp scripts/install-tools-vm-v2.sh ubuntu@<HOST>:/tmp/
ssh ubuntu@<HOST> 'sudo bash /tmp/install-tools-vm-v2.sh'
```

Aggiunge (tutto in `/opt/argo-tools/`, drop-in systemd aggiornato):

- **Tier 4 (apt)** — nmap, masscan, nikto, enum4linux, snmp/snmpwalk,
  ffmpeg/ffprobe, fierce, gobuster, ffuf, smbmap, testssl.sh.
- **Tier 5 (Go install)** — installa Go 1.22 in `/usr/local/go` e poi: dnsx,
  naabu, katana, nuclei, dalfox, gospider, gau, hakrawler, waybackurls,
  subjack, mosint (tutti in `/opt/argo-tools/go/bin`).
- **Tier 6 (pip esteso)** — arjun, dirsearch, cloud-enum, recon-ng,
  spiderfoot, social-analyzer, linkfinder, metagoofil, toutatis, ghunt,
  censys, shodan, EyeWitness.
- **Tier 7 (git clone + wrapper)** — osintgram, secretfinder, phunter,
  git-dumper.
- **Tier 8 (binary)** — gitleaks.
- **Fix bug v1** — alias case-sensitive `theHarvester` (Linux è
  case-sensitive, il symlink era stato fatto solo in minuscolo).

**Tool che richiedono CREDENZIALI per funzionare** (la CLI è installata, ma la
config è tua):

| Tool | Cosa serve |
|------|------------|
| ghunt | `ghunt login` → cookie Google |
| osintgram | login Instagram in `/opt/argo-tools/repos/osintgram/config/` |
| censys | API key (`CENSYS_API_ID` + `CENSYS_API_SECRET`) |
| shodan | `shodan init <API_KEY>` |
| wpscan (se installato a mano) | `WPSCAN_API_TOKEN` |

**Skip motivati:**

- `wpscan` (Ruby + bundler complesso) — `sudo apt install ruby-dev && gem install wpscan`.
- `infoga` (Python 2 deprecato, repo upstream non mantenuto).

Verifica integrazione con Argo via `external_tools.all_tools_health()`:

```bash
ssh ubuntu@<HOST> 'PATH=/opt/argo-tools/bin:$PATH \
  /opt/argo-osint/.venv/bin/python -c \
  "from osint_bot.external_tools import all_tools_health; \
   print(len([t for t in all_tools_health() if t[\"available\"]]), \"available\")"'
```

> Script più recenti (`install-tools-vm-v3.sh` e successivi, in `scripts/`)
> estendono ulteriormente la copertura tool sulla VM: consulta l'intestazione
> di ciascuno script per il changelog puntuale prima di eseguirlo.

### Hardening minimo

```bash
# Fail2ban
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban

# UFW (firewall a livello kernel, ridondante con iptables ma più ergonomico)
sudo ufw default deny incoming
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable

# Automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### Monitoraggio

- Audit log: `/opt/argo-osint/web_jobs/audit.jsonl` (SHA-256 hash-chain).
- Caddy access: `/var/log/caddy/argo-access.log`.
- Systemd: `journalctl -u argo-osint -f`.
- Email log (se il provider email è down): `/opt/argo-osint/web_jobs/email_log.jsonl`.

### Backup

```bash
# Cron daily backup
cat > /home/ubuntu/backup-argo.sh <<'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d)
tar czf /home/ubuntu/backups/argo-$DATE.tar.gz -C /opt argo-osint/web_jobs
find /home/ubuntu/backups -name "argo-*.tar.gz" -mtime +14 -delete
EOF
chmod +x /home/ubuntu/backup-argo.sh
mkdir -p /home/ubuntu/backups
(crontab -l 2>/dev/null; echo "30 3 * * * /home/ubuntu/backup-argo.sh") | crontab -
```

## Deploy senza VPS pubblico: Cloudflare Tunnel

Se non vuoi gestire un VPS, esegui il bot in locale (o su una macchina
interna) e tunnellalo via Cloudflare.

### Tunnel rapido

Per usare subito la piattaforma da telefono senza aprire porte sul router,
avvia lo script incluso nel repo:

```powershell
cd <path\to\argo-osint>
powershell -ExecutionPolicy Bypass -File .\scripts\start-online-cloudflare.ps1
```

Lo script:

- avvia il backend solo su `127.0.0.1`;
- disattiva nuove iscrizioni con `OSINT_SIGNUPS_ENABLED=0`;
- abilita cookie sicuri e HSTS per l'uso via HTTPS;
- avvia `cloudflared tunnel --url`;
- scrive il link pubblico nel log `web_jobs\cloudflared-8769.err.log`.

Il tunnel rapido usa un dominio `trycloudflare.com`: comodo per prove
immediate, ma l'URL cambia a ogni riavvio del tunnel e non ha garanzia di
uptime.

In alternativa, senza lo script, puoi lanciare `cloudflared` manualmente:

```bash
# Install cloudflared
brew install cloudflared  # mac
# oppure, su Windows:
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe -o cloudflared.exe

# Autenticazione
cloudflared tunnel login

# Quick tunnel (URL casuale *.trycloudflare.com)
cloudflared tunnel --url http://127.0.0.1:7655
```

Limiti: il bot deve restare acceso sulla macchina locale; l'URL è casuale a
ogni avvio (per uno fisso serve un tunnel Cloudflare persistente, vedi sotto).

### Tunnel stabile

Nel dashboard Cloudflare Zero Trust:

1. Crea un tunnel.
2. Installa `cloudflared` sulla macchina runner.
3. Aggiungi un Public Hostname, ad esempio `osint.tuodominio.it`.
4. Imposta il Service URL su `http://localhost:8000` (o la porta configurata,
   es. `7655`).
5. Proteggi l'hostname con Cloudflare Access, SSO, email allowlist o mTLS.

Esempio di config ingress per un tunnel gestito via config file:

```yaml
tunnel: <TUNNEL_ID>
credentials-file: C:\Users\<utente>\.cloudflared\<TUNNEL_ID>.json

ingress:
  - hostname: osint.tuodominio.it
    service: http://localhost:8000
  - service: http_status:404
```

## Tool esterni: configurazione locale

Per un'installazione locale (dev/analyst laptop, tipicamente Windows) i tool
esterni si configurano tramite variabili d'ambiente se non sono nel `PATH`
(per l'equivalente su VM Linux vedi
[Tool CLI esterni sulla VM](#tool-cli-esterni-sulla-vm-install-tools-vmsh)
sopra):

```powershell
$env:SHERLOCK_CMD="C:\tools\sherlock\sherlock.exe"
$env:MAIGRET_CMD="C:\tools\maigret\maigret.exe"
$env:HOLEHE_CMD="C:\tools\holehe\holehe.exe"
$env:NMAP_CMD="C:\Program Files (x86)\Nmap\nmap.exe"
$env:EXIFTOOL_CMD="C:\tools\exiftool.exe"
$env:FFPROBE_CMD="C:\ffmpeg\bin\ffprobe.exe"
$env:PHONEINFOGA_CMD="C:\tools\phoneinfoga.exe"
$env:SOCIAL_ANALYZER_CMD="C:\tools\social-analyzer.exe"
$env:H8MAIL_CMD="C:\tools\h8mail.exe"
$env:GHUNT_CMD="C:\tools\ghunt.exe"
$env:TOUTATIS_CMD="C:\tools\toutatis.exe"
$env:SINGLEFILE_CMD="C:\tools\single-file.cmd"
$env:SHODAN_CMD="C:\tools\shodan.exe"
$env:CENSYS_CMD="C:\tools\censys.exe"
```

Per controllare lo stato dei tool locali:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-tools.ps1 -CheckOnly
```

Per le ricerche web ampie non viene usato un solo motore come predefinito. La
modalità `all` usa tutte le API configurate tra Bing, Brave e Serper, genera
dork verificabili per Google/Bing/DuckDuckGo/Yandex e aggiunge link servizio
per Shodan, Censys, HIBP, Hunter, IntelX, Epieos e Wayback quando pertinenti.

Per configurare le chiavi API in modo guidato:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-api-keys.ps1
```

Se vuoi configurare solo Bing:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-bing-key.ps1
```

Poi riavvia il backend o il tunnel online. Gli username usano
Sherlock/Maigret/Social Analyzer/Toutatis/Osintgram per profili pubblici
candidati quando autorizzati; email e telefoni di registrazione dei social non
sono dati pubblici e non vengono recuperati.

I repository GitHub curati sono descritti in `config/tool_catalog.json`. Per
clonarli nella piattaforma:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-repos.ps1 -CloneOnly
```

Gli agenti scelgono gli strumenti automaticamente; l'utente non deve
selezionare repository o comandi. Se un comando manca, il report segnala lo
strumento non disponibile invece di fallire.

SpiderFoot, Recon-ng, IntelOwl e Aleph sono piattaforme/framework esterni: il
catalogo li rende selezionabili dal planner, ma per l'esecuzione piena
servono setup e credenziali secondo la documentazione ufficiale. In assenza di
setup, il report li registra come `manual_setup` invece di inventare
risultati.

I dork e i link verso servizi esterni sono piste di verifica. Non vengono
trattati come fatti osservati finché non apri le fonti e confermi manualmente
le evidenze importanti.

## Stack avanzato opzionale (Postgres/Neo4j/OpenSearch/Celery)

Le capability opzionali dello stack completo — export STIX/MISP, connettori
nativi, AI locale, storage Postgres, frontend Next.js, Neo4j, OpenSearch, coda
Celery — si attivano sulla VM dopo il deploy base, e possono **sostituire**
con i loro equivalenti nativi eventuali componenti esterni ridondanti già in
uso (vedi `deploy_artifacts/REPLACEMENTS.md`).

> Principio guida: **ogni cosa nuova rimpiazza una vecchia, che va
> decommissionata.** Niente doppioni in esecuzione. Se sulla stessa VM gira
> già uno stack standalone equivalente (es. un grafo/ricerca/coda esterni), i
> profili nativi Argo (sotto) coprono lo stesso perimetro — puoi
> decommissionarlo dopo aver verificato che gli equivalenti nativi
> funzionano. Su una VM piccola, tenerli entrambi attivi in parallelo può
> esaurire la RAM: vedi [Sizing](#sizing--attenzione-oom) più sotto.

### Prerequisiti

- Codice aggiornato in `/opt/argo-osint` (usa `deploy.ps1`/`deploy.sh` come
  sempre).
- Servizio base `argo-osint` attivo dietro Caddy (invariato).

### Cosa NON richiede nulla (già attivo dopo il deploy del codice)

Queste capability sono in-process e non hanno dipendenze esterne:

- Export **STIX 2.1 / MISP** → `/api/jobs/{id}/stix.json` · `/misp.json`.
- Connettori nativi (DNS, TLS, ASN, Gravatar, Common Crawl, web fingerprint,
  Shodan InternetDB, Overpass, ThreatFox, **content_discovery, port_scan,
  subdomain_enum, dnstwist, secret_scan, url_harvest, holehe**).
- **NER + summarization** (regex/pure-python). OCR/traduzione richiedono
  l'extra `ai`.

Verifica: `GET /api/capabilities` mostra `ai_enrichment`, `external_stores`,
`queue`.

### AI opzionale (OCR/spaCy/traduzione)

```bash
sudo -u ubuntu /opt/argo-osint/.venv/bin/pip install -e '/opt/argo-osint[ai]'
sudo apt-get install -y tesseract-ocr tesseract-ocr-ita   # binario OCR
sudo -u ubuntu /opt/argo-osint/.venv/bin/python -m spacy download it_core_news_sm
sudo systemctl restart argo-osint
```

### Stack di supporto (Postgres / Neo4j / OpenSearch / Redis)

Attiva **solo i profili che ti servono** (ognuno sostituisce un pezzo di uno
stack esterno equivalente, se presente):

```bash
export ARGO_PG_PASSWORD='...'; export ARGO_NEO4J_PASSWORD='...'
cd /opt/argo-osint/deploy_artifacts
sudo -E bash install-stack.sh db queue graph search
```

Poi appendi a `/opt/argo-osint/.env` le righe di `dotenv.stack.template` che
ti servono (scommentandole) e riavvia:

```bash
sudo systemctl restart argo-osint argo-celery
```

#### Migrazione dati SQLite → Postgres (se usi il profilo `db`)

```bash
sudo -u ubuntu /opt/argo-osint/.venv/bin/python -m osint_bot.migrate_sqlite_to_postgres \
    --dsn "postgresql://argo:${ARGO_PG_PASSWORD}@127.0.0.1:5433/argo"
```

Verifica che stampi `catena audit verificata`, poi imposta `DATABASE_URL`
nell'`.env`.

### Frontend Next.js (opzionale)

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

### Decommissionare i doppioni (DOPO aver verificato lo stack nativo)

```bash
cd /opt/argo-osint/deploy_artifacts
sudo bash decommission.sh flowsint sqlite tools
```

- `flowsint` → spegne i container di uno stack esterno equivalente (volumi
  preservati; `-v` per cancellarli).
- `sqlite` → archivia `gufo.sqlite3` (solo se `DATABASE_URL` Postgres è
  attiva).
- `tools` → commenta nell'`.env` i `*_CMD` ora nativi (backup automatico).

Vedi `deploy_artifacts/REPLACEMENTS.md` per la matrice completa "nuovo →
sostituisce".

### Sizing / attenzione OOM

Heap tarati per VM piccola (OpenSearch 512m, Neo4j 512m+256m, Redis 192m,
Postgres ~384m). Se stai migrando da uno stack esterno equivalente,
decommissionarlo (sezione precedente) libera la RAM/CPU che i suoi container
occupavano — è esattamente ciò che i profili nativi Argo vanno a rimpiazzare.
Se resti stretto, attiva i profili in modo incrementale (prima `queue`+`graph`,
poi `search`).

### Sicurezza dello stack

- Tutti i servizi dello stack sono bindati su **127.0.0.1** (mai pubblici).
- OpenSearch gira con security plugin OFF: lecito **solo** perché non è
  esposto.
- Le password (`ARGO_PG_PASSWORD`, `ARGO_NEO4J_PASSWORD`, `MISP_KEY`, ecc.)
  stanno in `/opt/argo-osint/.env` (chmod 600) o in `stack.env`, mai nel
  repo.

## Sicurezza operativa e classificazione

Checklist operativa, valida sia per il deploy su VM sia per il tunnel
Cloudflare:

- Esegui il backend dietro Caddy, Cloudflare Access o VPN — mai esposto in
  chiaro.
- Usa un token lungo in `OSINT_WEB_TOKEN` (o lascialo vuoto per affidarti solo
  all'auth utente).
- Non esporre il backend direttamente senza autenticazione.
- Esegui i tool in un utente dedicato, senza privilegi admin.
- Conserva i report in storage cifrato se contengono identificatori personali.
- Usa `--allow-network-scan` e `--allow-darkweb` solo per casi autorizzati.
- Dopo il primo setup pubblico valuta `OSINT_SIGNUPS_ENABLED=0`.
- Su HTTPS imposta `OSINT_SECURE_COOKIE=1` e `OSINT_HSTS=1`.
- Lascia `OSINT_MAX_UPLOAD_BYTES` basso se non devi analizzare video grandi.
- Usa il WAF/rate limiting di Cloudflare e Access con MFA quando disponibili.
- Non salvare API key o password nei report.

Classificazione di sicurezza del deploy VM di riferimento (sezione
[Deploy su VM](#deploy-su-vm-systemd--caddy)):

| Aspetto | Stato | Note |
|---------|-------|------|
| Trasporto | HTTPS forzato (Caddy + HSTS) | Bot ascolta su `127.0.0.1:7655`, mai esposto in chiaro |
| Auth | Username + password (≥12) + email verification | Token HMAC-SHA256 firmato, 24h TTL |
| Session | HttpOnly + Secure + SameSite=Strict | TTL 8h default, configurabile |
| CSRF | Token per-sessione, header `X-CSRF-Token` | Mantenuto da implementazione esistente |
| Audit | Tutti gli eventi auth nell'hash chain SHA-256 | `user_signup`, `verification_email_sent`, `email_verified`, `login_success`, `signup_rollback_email_error` |
| Email transport | TLS via Resend / SMTPS / STARTTLS | Mai cleartext |
| Email content | Nessun dato sensibile nel corpo | Solo username + link |
| Segreti | Tutti da env var, mai hardcoded | `.env` chmod 600 |
| Rollback signup | User row eliminato se email fallisce | Niente account "fantasma" |
| Account login | Bloccato finché `verified=False` | Errore 403 esplicito |
| Logging accessi IP | Sì, in audit chain | `remote_ip` registrato a ogni login_success |
| GDPR | Email è dato personale → necessaria base giuridica documentata nel caso | RoPA già supportato |

## Piano gratuito e upgrade

Il backend salva gli utenti con piano `free`. Il campo `plan` è già nel file
utenti e nella UI; puoi aggiungere in seguito:

- quote per numero di job/report;
- piano `pro`;
- integrazione pagamenti;
- tenant separati per team;
- log di audit per accessi e download report.
