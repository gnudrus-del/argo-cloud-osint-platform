#!/usr/bin/env bash
# Argo OSINT — bootstrap di una VM Oracle Cloud Ubuntu 24.04 nuda.
#
# Tutto in un colpo: sistema base, Caddy con TLS Let's Encrypt, Python venv,
# clone codice Argo (verra' sostituito dal rsync di deploy.sh), unit systemd,
# .env minimale, iptables aperti per 80/443.
#
# Idempotente: si puo' rilanciare. Sicuro su VM A1.Flex (ARM) o E2 (x86).
#
# Uso (da SSH come ubuntu sulla VM nuova, in sudo):
#   curl -fsSL ... -o /tmp/bs.sh && sudo bash /tmp/bs.sh
# oppure (da locale via scp + ssh — fatto da deploy.sh wrapper):
#   scp bootstrap-vm-fresh.sh ubuntu@NEW_IP:/tmp/
#   ssh ubuntu@NEW_IP 'sudo bash /tmp/bootstrap-vm-fresh.sh'
#
# Niente segreti hardcoded: i secret per .env li passi dopo con il deploy.

set -uo pipefail

say()  { echo "[bootstrap] $*"; }
ok()   { echo -e "  \033[32m✓\033[0m $*"; }
note() { echo -e "  \033[33m·\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: lancia con sudo" >&2; exit 1; }

# ============================================================================
# 1) Sistema base
# ============================================================================
say "Sistema base"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip git curl wget jq whois \
  ca-certificates apt-transport-https debian-keyring debian-archive-keyring \
  unzip xz-utils \
  iptables-persistent ufw \
  >/dev/null
ok "pacchetti base installati"

# ============================================================================
# 2) Firewall: 80, 443 in ingresso (SSH gia' OK)
# ============================================================================
say "Firewall"
# iptables (compatible con preset Oracle Cloud)
iptables -C INPUT -m state --state NEW -p tcp --dport 80  -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80  -j ACCEPT
iptables -C INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
netfilter-persistent save >/dev/null 2>&1 || true
ok "iptables 80/443 aperti + salvati"

# ============================================================================
# 3) Caddy (reverse proxy + TLS automatico)
# ============================================================================
say "Caddy"
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
    gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
    tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -qq
  apt-get install -y caddy >/dev/null
  ok "caddy installato"
else
  ok "caddy gia' presente"
fi

# Caddyfile (placeholder — verra' personalizzato col dominio reale)
DOMAIN="${ARGO_DOMAIN:-argo.example.com}"
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode gzip
    reverse_proxy 127.0.0.1:7655 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
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
EOF
systemctl reload caddy 2>/dev/null || systemctl restart caddy
ok "Caddy configurato per $DOMAIN"

# ============================================================================
# 4) Argo: dir, venv, codice, unit systemd
# ============================================================================
say "Argo: dir + venv + skeleton codice"
mkdir -p /opt/argo-osint
chown ubuntu:ubuntu /opt/argo-osint
sudo -u ubuntu bash -c '
cd /opt/argo-osint
if [ ! -d osint_bot ]; then
  # Skeleton minimale: il vero osint_bot/ arriva via rsync di deploy.sh
  mkdir -p osint_bot web_jobs
fi
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
fi
'
ok "/opt/argo-osint pronto"

# .env minimale (l utente lo completa con i secret veri)
if [ ! -f /opt/argo-osint/.env ]; then
  cat > /opt/argo-osint/.env <<'EOF'
# === Argo .env — riempi con i valori reali ===
OSINT_WEB_TOKEN=
EMAIL_VERIFICATION_SECRET=
EMAIL_PROVIDER=console
EMAIL_FROM_ADDR=noreply@argo.example.com
EMAIL_FROM_NAME=Argo
EMAIL_VERIFICATION_BASE_URL=https://argo.example.com
OSINT_SECURE_COOKIE=1
OSINT_SESSION_TTL_SECONDS=28800
OSINT_SIGNUPS_ENABLED=1
EOF
  chmod 600 /opt/argo-osint/.env
  chown ubuntu:ubuntu /opt/argo-osint/.env
  # Genera un EMAIL_VERIFICATION_SECRET random
  SECRET=$(openssl rand -hex 32)
  sed -i "s/^EMAIL_VERIFICATION_SECRET=.*/EMAIL_VERIFICATION_SECRET=$SECRET/" /opt/argo-osint/.env
  ok ".env scheletro creato (con EMAIL_VERIFICATION_SECRET random)"
else
  ok ".env gia' presente — non sovrascritto"
fi

# ============================================================================
# 5) Unit systemd
# ============================================================================
say "Unit systemd argo-osint.service"
cat > /etc/systemd/system/argo-osint.service <<'EOF'
[Unit]
Description=Argo OSINT bot
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
EOF
systemctl daemon-reload
systemctl enable argo-osint >/dev/null
# NB: NON faccio `systemctl start` qui — manca ancora il codice osint_bot/.
# Lo start avviene dopo il rsync del deploy.sh.
ok "unit installata e abilitata (start dopo deploy)"

# ============================================================================
# 6) Stato finale
# ============================================================================
say ""
say "Bootstrap completo. Prossimi step (lato locale):"
note "1. Aggiornare DuckDNS per puntare a IP=$(curl -s ifconfig.me)"
note "2. Lanciare: HOST=<dominio> bash deploy.sh   # rsync osint_bot/"
note "3. Lanciare: bash install-tools-vm-v5.sh     # i 60+ tool"
note "4. Verificare: bash verify-live.sh"
say ""
say "MEM: $(free -m | awk '/^Mem:/ {print $0}')"
say "$(uname -m) | $(lsb_release -ds 2>/dev/null || echo Ubuntu)"
