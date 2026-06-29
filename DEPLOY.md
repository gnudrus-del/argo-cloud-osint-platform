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
