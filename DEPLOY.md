# Deploy di Argo

## Configurazione raccomandata: Oracle Cloud Always Free + Caddy + Resend

**Costo totale: 0 €/mese.**

| Componente | Provider | Note |
|------------|----------|------|
| Server | Oracle Cloud Ampere A1 (4 OCPU, 24 GB RAM) | Always Free, no scadenza |
| Dominio | DuckDNS (free) o tuo dominio | DuckDNS dà `*.duckdns.org` gratis |
| Reverse proxy + HTTPS | Caddy (Let's Encrypt automatico) | TLS gratis, rinnovo auto |
| Email transactional | Resend.com | Free tier 3.000 email/mese, 100/giorno |

> Setup tempo totale: ~45 minuti (di cui ~15 di attesa per la propagazione DNS).

---

## 1. Provisioning Oracle Cloud (10 min)

1. Account: https://signup.cloud.oracle.com — serve carta di credito per la verifica (non viene mai addebitato il tier Always Free).
2. Console → **Compute → Instances → Create Instance**
3. Image: **Ubuntu 24.04** (ARM 64 Ampere)
4. Shape: **VM.Standard.A1.Flex** → 2 OCPU, 12 GB RAM (basta; puoi espandere fino a 4/24 free)
5. Networking: **Assign public IPv4** — sì
6. SSH key: incolla la tua chiave pubblica (`~/.ssh/id_ed25519.pub`)
7. Crea l'istanza. Annota l'IP pubblico.

8. **Apri porte** in Security List:
   - Console → Networking → VCN → Default Security List → Add Ingress Rule
   - TCP 80 da `0.0.0.0/0`
   - TCP 443 da `0.0.0.0/0`

9. **Apri firewall del sistema** (su Ubuntu Oracle preinstalla iptables):
   ```bash
   ssh ubuntu@<IP>
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   ```

## 2. Setup DNS con DuckDNS (5 min)

1. Vai su https://www.duckdns.org — login con GitHub/Google
2. Scegli un subdomain, es. `argo-tuonome`
3. Incolla l'IP pubblico Oracle nel campo "current ip" → Update
4. Il tuo URL sarà `https://argo-tuonome.duckdns.org`

> Se hai già un dominio (es. tuonome.it), aggiungi un record A che punta all'IP Oracle. Caddy farà tutto il resto.

## 3. Installazione su server (15 min)

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
# Copia tutto il contenuto di osint-bot/ qui

# Setup venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
# Le dipendenze sono nelle requirements/ esistenti — vedi README del bot
pip install -r requirements.txt  # se esiste; altrimenti pip install standard libs richieste
```

## 4. Configurazione environment (5 min)

Crea `/opt/argo-osint/.env` (chmod 600):

```bash
# Auth secrets
OSINT_WEB_TOKEN=  # vuoto = nessun token statico, solo auth utente
EMAIL_VERIFICATION_SECRET=<openssl rand -hex 32>

# Email (Resend)
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_xxxxxxxxxxxxxx
EMAIL_FROM_ADDR=noreply@argo-tuonome.duckdns.org
EMAIL_FROM_NAME=Argo

# Base URL (usato nei link verification)
EMAIL_VERIFICATION_BASE_URL=https://argo-tuonome.duckdns.org

# Sicurezza cookie
OSINT_SECURE_COOKIE=1
OSINT_SESSION_TTL_SECONDS=28800
```

**Genera il secret:**
```bash
echo "EMAIL_VERIFICATION_SECRET=$(openssl rand -hex 32)" >> .env
```

**Setup Resend:**
1. https://resend.com — signup free
2. Verifica domain (puoi anche usare `onboarding@resend.dev` come from address senza verifica per i primi test)
3. API Keys → Create API Key → copia in `.env`

## 5. Systemd service (5 min)

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

## 6. Caddy reverse proxy (5 min)

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

Caddy chiederà automaticamente il cert Let's Encrypt al primo accesso.

## 7. Test

Da browser: `https://argo-tuonome.duckdns.org`

1. Iscrizione → inserisci username + email + password (≥ 12 char)
2. Ricevi email da Resend con link di verifica
3. Click sul link → account attivato
4. Login

## 7bis. Aggiornamenti successivi

Una volta che la VM è in piedi, per pubblicare le modifiche locali ci sono due
modalita' equivalenti:

* **Bash (default consigliato — usabile anche dall'assistente):**
  `./deploy.sh`, `./verify-live.sh`, `./rollback.sh` — wrapper sottili che
  invocano i corrispondenti `.ps1` con i parametri giusti e l'host pubblico.
* **PowerShell (manuale):** lancia direttamente [`deploy.ps1`](deploy.ps1),
  [`verify-live.ps1`](verify-live.ps1), [`rollback.ps1`](rollback.ps1).

Lo script copia **solo** `osint_bot/` in `/opt/argo-osint/osint_bot/`, quindi
**non tocca** `.env`, `web_jobs/` né il `.venv` remoto.

Copia **solo** `osint_bot/` in `/opt/argo-osint/osint_bot/`, quindi **non tocca**
`.env`, `web_jobs/` né il `.venv` remoto. Esegue in ordine: test SSH → backup
remoto (`osint_bot.bak-YYYYMMDD-HHMMSS`) → copia (rsync con `--delete`, fallback
scp) → `sudo systemctl restart argo-osint` → status → health check su
`/api/dashboard` (200/401/403 = backend attivo).

**Prerequisiti:** client OpenSSH (`ssh`/`scp`, inclusi in Windows 10/11) e accesso
con la stessa chiave SSH usata per la VM. `rsync` è opzionale (se assente usa scp).

```bash
# anteprima senza modificare la VM (consigliato la prima volta)
./deploy.sh --dry-run

# deploy reale
./deploy.sh
```

Override host: `HOST=argo-altro.duckdns.org ./deploy.sh`. Parametri PowerShell
utili (`-IdentityFile <chiave>`, `-Port <n>`, `-User`, `-RemotePath`, `-Service`,
`-HealthUrl`) restano disponibili passando direttamente a `deploy.ps1`. Nessun
IP/segreto è hardcoded in alcuno script.

**Verifica automatica post-deploy** (read-only, solo HTTP, niente SSH):

```bash
./verify-live.sh
```

Controlla in sequenza: HTTP `/api/dashboard` (401/403/200 = nuovo backend, 404 =
vecchio), marker `renderAuditTab` / `/api/dashboard` / `evidenceHostLabel` in
`/app.js`, marker Fase 1 in `/app.css`, `id="panel-dashboard"` in `/`. Stampa
`VERSIONE NUOVA ONLINE` oppure `VERSIONE INCOMPLETA / VECCHIA` con dettaglio.

**Cache del browser:** dalla versione corrente del backend i file statici sono
serviti con `Cache-Control: no-cache, must-revalidate` + `ETag`. Il browser
rivalida ogni volta: 304 quando invariato, 200 con la nuova versione appena
cambia. **Ctrl+F5 non è più necessario** dopo un deploy.

**Rollback automatico** con `./rollback.sh` (sceglie da solo il backup piu'
recente, ma puoi listare/selezionare):

```bash
./rollback.sh -List                                # elenca backup
./rollback.sh -DryRun                              # anteprima
./rollback.sh                                      # esecuzione (chiede 'yes')
./rollback.sh -BackupName 20260629-153002 -Force   # backup specifico
```

Lo script salva sempre la versione corrente in `osint_bot.rollback-rescue-<ts>`
prima di sostituirla, quindi **il rollback stesso e' annullabile**: in caso di
errore stampa il comando di recupero.

**Rollback manuale** (se non puoi usare lo script) — `deploy.ps1` stampa il
comando esatto con il timestamp reale:

```bash
ssh ubuntu@<IP> "rm -rf /opt/argo-osint/osint_bot && mv /opt/argo-osint/osint_bot.bak-YYYYMMDD-HHMMSS /opt/argo-osint/osint_bot && sudo systemctl restart argo-osint"
```

## 7ter. Tool CLI esterni (`install-tools-vm.sh`)

Per attivare i tool OSINT esterni (sherlock, maigret, holehe, subfinder, ...),
copia ed esegui sulla VM lo script `scripts/install-tools-vm.sh`:

```bash
scp scripts/install-tools-vm.sh ubuntu@<HOST>:/tmp/
ssh ubuntu@<HOST> 'sudo bash /tmp/install-tools-vm.sh'
```

Cosa fa (idempotente):

* **Tier 1 (apt)** — whatweb, wafw00f, exiftool, dnstwist, dnsenum, whois, jq, curl, wget.
* **Tier 2 (pip)** — venv dedicato `/opt/argo-tools/.venv` con sherlock-project,
  maigret, holehe, theHarvester, socialscan, h8mail (symlinkati in
  `/opt/argo-tools/bin`).
* **Tier 3 (bin)** — binari precompilati dalle GitHub Releases: subfinder,
  httpx, amass, trufflehog (in `/opt/argo-tools/bin`).
* **Drop-in systemd** — `/etc/systemd/system/argo-osint.service.d/tools-path.conf`
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
oppure dal pannello UI **Chiavi API** > sezione *Stato copertura*: dopo il
restart del servizio (~30s di cache health-check) i tool installati mostrano
il pallino verde.

### Installer v2 (set completo)

Per coprire tutti i ~60 tool del catalogo (oltre OSINT passivo, anche scanner
attivi gated da scope/red-team policy, e tool che richiedono credenziali
utente), esegui dopo il v1:

```bash
scp scripts/install-tools-vm-v2.sh ubuntu@<HOST>:/tmp/
ssh ubuntu@<HOST> 'sudo bash /tmp/install-tools-vm-v2.sh'
```

Aggiunge (tutto in `/opt/argo-tools/`, drop-in systemd aggiornato):

* **Tier 4 (apt)** — nmap, masscan, nikto, enum4linux, snmp/snmpwalk,
  ffmpeg/ffprobe, fierce, gobuster, ffuf, smbmap, testssl.sh.
* **Tier 5 (Go install)** — installa Go 1.22 in `/usr/local/go` e poi:
  dnsx, naabu, katana, nuclei, dalfox, gospider, gau, hakrawler,
  waybackurls, subjack, mosint (tutti in `/opt/argo-tools/go/bin`).
* **Tier 6 (pip esteso)** — arjun, dirsearch, cloud-enum, recon-ng,
  spiderfoot, social-analyzer, linkfinder, metagoofil, toutatis, ghunt,
  censys, shodan, EyeWitness.
* **Tier 7 (git clone + wrapper)** — osintgram, secretfinder, phunter,
  git-dumper.
* **Tier 8 (binary)** — gitleaks.
* **Fix bug v1** — alias case-sensitive `theHarvester` (Linux è
  case-sensitive, il symlink era stato fatto solo in minuscolo).

**Tool che richiedono CREDENZIALI per funzionare** (la CLI è installata, ma
la config è tua):

| Tool | Cosa serve |
|------|------------|
| ghunt | `ghunt login` → cookie Google |
| osintgram | login Instagram in `/opt/argo-tools/repos/osintgram/config/` |
| censys | API key (`CENSYS_API_ID` + `CENSYS_API_SECRET`) |
| shodan | `shodan init <API_KEY>` |
| wpscan (se installato a mano) | `WPSCAN_API_TOKEN` |

**Skip motivati**:
* `wpscan` (Ruby + bundler complesso) — `sudo apt install ruby-dev && gem install wpscan`
* `infoga` (Python 2 deprecato, repo upstream non mantenuto).

Verifica integrazione con Argo via `external_tools.all_tools_health()`:
```bash
ssh ubuntu@<HOST> 'PATH=/opt/argo-tools/bin:$PATH \
  /opt/argo-osint/.venv/bin/python -c \
  "from osint_bot.external_tools import all_tools_health; \
   print(len([t for t in all_tools_health() if t[\"available\"]]), \"available\")"'
```

## 8. Hardening minimo addizionale

```bash
# Fail2ban
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban

# UFW (firewall a livello kernel, redundante con iptables ma più ergonomico)
sudo ufw default deny incoming
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable

# Automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

## 9. Monitoraggio (opzionale)

- Audit log: `/opt/argo-osint/web_jobs/audit.jsonl` (SHA-256 hash-chain)
- Caddy access: `/var/log/caddy/argo-access.log`
- Systemd: `journalctl -u argo-osint -f`
- Email log (se Resend è down): `/opt/argo-osint/web_jobs/email_log.jsonl`

## 10. Backup

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

## Variante: Cloudflare Tunnel (senza VPS)

Se non vuoi gestire un VPS, esegui il bot in locale e tunnellalo via Cloudflare:

```bash
# Install cloudflared
brew install cloudflared  # mac
# o
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe -o cloudflared.exe

# Authentic
cloudflared tunnel login

# Quick tunnel (URL random *.trycloudflare.com)
cloudflared tunnel --url http://127.0.0.1:7655
```

Limiti: il bot deve restare acceso sulla macchina locale, URL casuale ogni avvio (per uno fisso serve account CF Tunnel persistente).

---

## Classificazione di sicurezza — Unità 1

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
