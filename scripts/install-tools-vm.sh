#!/usr/bin/env bash
# Argo OSINT — installer dei tool CLI sulla VM (Ubuntu/Debian).
#
# Filosofia: installa solo tool di OSINT PASSIVO + recognizance light.
# NON installa scanner di rete attivi (nmap, masscan, wpscan, naabu attivi,
# nuclei) — la policy OPSEC dello spec richiede autorizzazione esplicita
# prima di lanciarli, quindi devono restare opt-in manuale.
#
# Layout:
#   - Tier 1 (apt)  : pacchetti Debian disponibili nei repo Ubuntu standard
#   - Tier 2 (pip)  : tool Python OSINT, in venv dedicato /opt/argo-tools/.venv
#                     symlinkati in /opt/argo-tools/bin (dove Argo li cerca)
#   - Tier 3 (bin)  : binari precompilati da github releases
#
# Idempotente: si puo' rilanciare quante volte serve.
#
# Uso:
#   sudo bash install-tools-vm.sh            # installa tutto
#   sudo bash install-tools-vm.sh --check    # mostra solo cosa e' presente
#   sudo bash install-tools-vm.sh --pip-only # salta apt (utile se gia' fatto)

set -uo pipefail

CHECK_ONLY=0
PIP_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --pip-only) PIP_ONLY=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
  esac
done

# ---------------------------------------------------------------- helpers
say() { echo "[install-tools] $*"; }
ok() { echo -e "  \033[32m✓\033[0m $*"; }
ko() { echo -e "  \033[31m✗\033[0m $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"

# ---------------------------------------------------------------- CHECK MODE
if [ "$CHECK_ONLY" = 1 ]; then
  say "Inventario tool installati:"
  for t in whois nmap whatweb wafw00f exiftool dnstwist dnsenum dnsx \
           subfinder amass httpx katana ffuf gobuster \
           sherlock maigret holehe theharvester spiderfoot recon-ng \
           photon socialscan h8mail phoneinfoga ghunt osintgram toutatis \
           trufflehog gitleaks; do
    if have "$t"; then ok "$t -> $(command -v $t)"; else ko "$t"; fi
  done
  exit 0
fi

# Privilegi: serve sudo per apt e per /opt
if [ "$EUID" -ne 0 ]; then
  echo "ERR: questo script deve girare come root (usa sudo)." >&2
  exit 1
fi

mkdir -p "$ARGO_TOOLS_DIR" "$ARGO_BIN"

# ---------------------------------------------------------------- TIER 1 — apt
if [ "$PIP_ONLY" = 0 ]; then
  say "Tier 1 (apt) — pacchetti dai repo Ubuntu/Debian"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # Set di tool PASSIVI/utility:
  #   whois          - lookup registrar
  #   whatweb        - fingerprint web (request HTTP single, OK passivo)
  #   wafw00f        - detect WAF (passivo a basso volume)
  #   exiftool       - metadata di media
  #   dnsutils       - dig, nslookup
  #   dnstwist       - typo-squatting analysis (locale, no scan attivo)
  #   dnsenum        - DNS enumeration (queries, no brute)
  #   jq, curl, wget - tooling base
  #   python3-venv   - per i venv pip sotto
  apt-get install -y --no-install-recommends \
      whois whatweb wafw00f exiftool dnsutils dnstwist dnsenum \
      jq curl wget ca-certificates \
      python3-venv python3-pip \
      git unzip xz-utils \
      >/dev/null && ok "apt: pacchetti installati"
fi

# ---------------------------------------------------------------- TIER 2 — pip (venv dedicato)
say "Tier 2 (pip) — venv dedicato in $ARGO_VENV"
if [ ! -d "$ARGO_VENV" ]; then
  python3 -m venv "$ARGO_VENV"
  ok "venv creato: $ARGO_VENV"
fi
# shellcheck disable=SC1091
source "$ARGO_VENV/bin/activate"
pip install --quiet --upgrade pip

# Tool Python pubblici, robusti e maintained:
PIP_TOOLS=(
  "sherlock-project"   # username -> sherlock
  "maigret"            # username (~3000 siti)
  "holehe"             # email -> social presence
  "theHarvester"       # email/domain harvesting (passivo via search)
  "socialscan"         # username availability
  "h8mail"             # email -> public breach refs
)
for pkg in "${PIP_TOOLS[@]}"; do
  if pip show "$pkg" >/dev/null 2>&1; then
    ok "pip: $pkg gia' installato"
  else
    if pip install --quiet "$pkg"; then
      ok "pip: $pkg installato"
    else
      ko "pip: $pkg NON installato (skip)"
    fi
  fi
done
deactivate || true

# Symlink dei comandi del venv in $ARGO_BIN (che mettiamo nel PATH della
# unit systemd argo-osint via /etc/environment override piu' avanti).
say "Symlink dei comandi in $ARGO_BIN"
for name in sherlock maigret holehe theHarvester socialscan h8mail; do
  src="$ARGO_VENV/bin/$name"
  if [ -x "$src" ]; then
    ln -sf "$src" "$ARGO_BIN/$(echo $name | tr '[:upper:]' '[:lower:]')"
    ok "$name -> $ARGO_BIN/$(echo $name | tr '[:upper:]' '[:lower:]')"
  fi
done

# ---------------------------------------------------------------- TIER 3 — binary
say "Tier 3 (bin) — binari precompilati"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH_GH="linux_amd64" ;;
  aarch64|arm64) ARCH_GH="linux_arm64" ;;
  *) ARCH_GH="" ;;
esac

install_release_binary() {
  # $1 = nome locale, $2 = url tarball/zip, $3 = path interno al binario
  local name="$1" url="$2" inner="$3"
  if [ -x "$ARGO_BIN/$name" ]; then ok "bin: $name gia' presente"; return 0; fi
  local tmp
  tmp=$(mktemp -d)
  pushd "$tmp" >/dev/null || return 1
  if [[ "$url" == *.tar.gz ]] || [[ "$url" == *.tgz ]]; then
    curl -fsSL "$url" -o pkg.tgz && tar -xzf pkg.tgz
  elif [[ "$url" == *.zip ]]; then
    curl -fsSL "$url" -o pkg.zip && unzip -q pkg.zip
  fi
  if [ -f "$inner" ]; then
    install -m 0755 "$inner" "$ARGO_BIN/$name" && ok "bin: $name installato"
  else
    ko "bin: $name (archivio non contiene $inner)"
  fi
  popd >/dev/null || return 1
  rm -rf "$tmp"
}

if [ -n "$ARCH_GH" ]; then
  # subfinder — projectdiscovery (passive subdomain enum)
  install_release_binary "subfinder" \
    "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_${ARCH_GH}.zip" \
    "subfinder"
  # httpx — projectdiscovery (HTTP toolkit, viene usato in modalita' passiva da Argo)
  install_release_binary "httpx" \
    "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_${ARCH_GH}.zip" \
    "httpx"
  # amass (lightweight binary)
  install_release_binary "amass" \
    "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_${ARCH_GH##linux_}.zip" \
    "amass_Linux_${ARCH_GH##linux_}/amass"
  # trufflehog (secret scanning passivo su sorgenti pubbliche)
  install_release_binary "trufflehog" \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.13/trufflehog_3.82.13_${ARCH_GH}.tar.gz" \
    "trufflehog"
else
  say "Arch '$ARCH' non riconosciuta -> skip Tier 3"
fi

# ---------------------------------------------------------------- TOOL ATTIVI (note)
say ""
say "NON installati (richiedono autorizzazione esplicita - policy OPSEC):"
echo "    - nmap, masscan       (scan rete attivo)"
echo "    - nuclei, wpscan      (vulnerability scanner attivo)"
echo "    - katana, naabu       (crawler attivo)"
say "Per installarli manualmente quando autorizzati:"
echo "    sudo apt install nmap masscan        # scanner di rete"
echo "    # nuclei/wpscan: vedi loro doc upstream"

# ---------------------------------------------------------------- systemd drop-in
# Il servizio argo-osint gira con User=ubuntu, ma il suo PATH non include
# /opt/argo-tools/bin. Aggiungo un drop-in (non tocca la unit originale).
DROPIN_DIR="/etc/systemd/system/argo-osint.service.d"
if [ -d "/etc/systemd/system" ] && systemctl list-unit-files argo-osint.service >/dev/null 2>&1; then
  mkdir -p "$DROPIN_DIR"
  cat > "$DROPIN_DIR/tools-path.conf" <<'CONF'
# Drop-in generato da install-tools-vm.sh.
# Estende PATH del servizio in modo che shutil.which() trovi i tool OSINT
# installati in /opt/argo-tools/bin (sherlock, maigret, holehe, subfinder, ...)
[Service]
Environment="PATH=/opt/argo-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONF
  systemctl daemon-reload
  systemctl restart argo-osint
  ok "Drop-in systemd creato + servizio argo-osint riavviato."
else
  say "systemd/argo-osint non rilevato: drop-in NON creato (manuale)."
fi

say "Fatto. Argo health-check vedra' i tool al prossimo refresh (~30s di cache)."
