#!/usr/bin/env bash
# Argo — installer per Ubuntu 24.04 (ARM o x86)
# Lancia: sudo bash install.sh
set -euo pipefail

ARGO_USER="ubuntu"
ARGO_HOME="/opt/argo-osint"
ARGO_PORT="7655"

echo "[1/8] Update apt + dependenze base..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl debian-keyring \
    debian-archive-keyring apt-transport-https ufw fail2ban unattended-upgrades

echo "[2/8] Caddy via repository ufficiale..."
if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
fi

echo "[3/8] User + cartelle..."
mkdir -p "$ARGO_HOME" /var/log/caddy
chown -R "$ARGO_USER:$ARGO_USER" "$ARGO_HOME"

echo "[4/8] Firewall (UFW)..."
ufw --force default deny incoming
ufw --force default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

echo "[5/8] Apri iptables anche per Oracle Cloud (filtra di default)..."
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
else
    apt-get install -y -qq iptables-persistent
fi

echo "[6/8] Fail2ban + unattended-upgrades..."
systemctl enable --now fail2ban
echo 'APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades

echo "[7/8] Python venv (lasciato vuoto, lo crea il deploy)"
echo "[8/8] Done. Ora trasferisci il codice in $ARGO_HOME e segui la guida."
