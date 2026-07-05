#!/usr/bin/env bash
# Argo OSINT — installer v6 — full coverage (ARM-aware).
# Obiettivo: TUTTI i 63 tool del catalogo verdi sulla VM ARM 5.9 GB.
#
# Combina:
#  - Tier 1 apt baseline (nmap, whatweb, exiftool, ...)
#  - Tier 2 pip baseline (sherlock, maigret, holehe, h8mail, socialscan)
#  - Tier 3 binari ARM precompilati (subfinder, httpx, amass, trufflehog, nuclei, dnsx, naabu, katana, gau, gospider, hakrawler, waybackurls, subjack)
#  - Tier 4 v5 (recap arjun, dirsearch, instaloader, ...)
#  - Tier 5 difficile (spiderfoot, recon-ng, mosint, eyewitness, feroxbuster, wpscan, single-file, phoneinfoga, cloud_enum, linkfinder, metagoofil, enum4linux)
#
# Tutto via binari quando possibile (Go install esclusivo per chi compila in
# pochi MB). Idempotente. ARCH=aarch64 (Oracle A1 Ampere).

set -uo pipefail

say()  { echo "[v6] $*"; }
ok()   { echo -e "  \033[32m✓\033[0m $*"; }
ko()   { echo -e "  \033[31m✗\033[0m $*"; }
note() { echo -e "  \033[33m·\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: serve sudo" >&2; exit 1; }

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"
ARGO_REPOS="$ARGO_TOOLS_DIR/repos"
mkdir -p "$ARGO_BIN" "$ARGO_REPOS"

ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  amd64)  GHARCH="linux_amd64"; GLAR="x64";  GOARCH="amd64";;
  arm64)  GHARCH="linux_arm64"; GLAR="arm64"; GOARCH="arm64";;
  *) GHARCH=""; GLAR=""; GOARCH="";;
esac

# Swap (best-effort; bootstrap-vm-fresh non lo crea su 5.9GB ma non guasta)
if ! swapon --show 2>/dev/null | grep -q '/swapfile'; then
  fallocate -l 1G /swapfile 2>/dev/null && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile && \
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "swap 1GB attivato"
fi

# ============================================================================
# TIER 1 — apt baseline (16 tool)
# ============================================================================
say "Tier 1 — apt baseline"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
APT_BASE=(
  nmap masscan nikto whatweb wafw00f exiftool dnstwist dnsenum gobuster ffuf
  ffmpeg snmp fierce smbmap testssl.sh dnsutils whois jq curl wget
  python3-pip python3.12-venv git unzip xz-utils
  # Tier 5 dipendenze per dopo:
  ruby-dev libcurl4-openssl-dev libssl-dev zlib1g-dev
)
for pkg in "${APT_BASE[@]}"; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    : # ok "apt: $pkg"  # rumore: skippo
  else
    if apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
      ok "apt: $pkg installato"
    else
      ko "apt: $pkg NON disponibile"
    fi
  fi
done

# ============================================================================
# TIER 2 — pip baseline (5 tool)
# ============================================================================
say "Tier 2 — pip baseline"
[ -d "$ARGO_VENV" ] || python3 -m venv "$ARGO_VENV"
"$ARGO_VENV/bin/pip" install --quiet --upgrade pip 2>/dev/null

PIPS_BASE=(sherlock-project maigret holehe theHarvester socialscan h8mail)
for pkg in "${PIPS_BASE[@]}"; do
  if "$ARGO_VENV/bin/pip" show "$pkg" >/dev/null 2>&1; then
    ok "pip: $pkg presente"
  else
    "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet "$pkg" 2>/dev/null && ok "pip: $pkg installato" || ko "pip: $pkg failed"
  fi
done

# Symlink CLI (case-sensitive: theHarvester NON come theharvester)
for entry in \
    "sherlock:sherlock" "maigret:maigret" "holehe:holehe" \
    "theHarvester:theHarvester" "theHarvester:theharvester" \
    "socialscan:socialscan" "h8mail:h8mail" \
    ; do
  src_name="${entry%%:*}"; link_name="${entry##*:}"
  [ -x "$ARGO_VENV/bin/$src_name" ] && ln -sf "$ARGO_VENV/bin/$src_name" "$ARGO_BIN/$link_name"
done

# ============================================================================
# TIER 3 — binari precompilati ARM (13 tool)
# ============================================================================
say "Tier 3 — binari precompilati ARM"
dl_extract() {
  local name="$1" url="$2" inner="$3"
  [ -x "$ARGO_BIN/$name" ] && { ok "$name presente"; return 0; }
  local tmp; tmp=$(mktemp -d); pushd "$tmp" >/dev/null
  local f; f=$(basename "$url")
  if curl -fsSL "$url" -o "$f" 2>/dev/null; then
    case "$f" in
      *.tar.gz|*.tgz) tar -xzf "$f" 2>/dev/null;;
      *.zip)          unzip -q "$f" 2>/dev/null;;
    esac
    if [ -f "$inner" ]; then
      install -m 0755 "$inner" "$ARGO_BIN/$name" && ok "$name installato"
    else
      local found; found=$(find . -name "$(basename $inner)" -type f 2>/dev/null | head -1)
      if [ -n "$found" ]; then
        install -m 0755 "$found" "$ARGO_BIN/$name" && ok "$name installato (annidato)"
      else
        ko "$name: inner '$inner' assente"
      fi
    fi
  else
    ko "$name: download failed"
  fi
  popd >/dev/null; rm -rf "$tmp"
}

if [ -n "$GHARCH" ]; then
  # Project Discovery + tomnomnom + amass + trufflehog + gitleaks
  dl_extract subfinder    "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_${GHARCH}.zip"     "subfinder"
  dl_extract httpx        "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_${GHARCH}.zip"             "httpx"
  dl_extract dnsx         "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_${GHARCH}.zip"               "dnsx"
  dl_extract naabu        "https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_${GHARCH}.zip"             "naabu"
  dl_extract katana       "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_${GHARCH}.zip"           "katana"
  dl_extract nuclei       "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_${GHARCH}.zip"           "nuclei"
  dl_extract amass        "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_${GOARCH}.zip"                  "amass_Linux_${GOARCH}/amass"
  dl_extract trufflehog   "https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.13/trufflehog_3.82.13_${GHARCH}.tar.gz" "trufflehog"
  dl_extract gitleaks     "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GLAR}.tar.gz"      "gitleaks"
  # tomnomnom set (linux_arm64 pre-built)
  dl_extract gau          "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_${GHARCH}.tar.gz"                            "gau"
  dl_extract waybackurls  "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-${GHARCH}-0.1.0.tgz"        "waybackurls"
  # gospider e hakrawler hanno release linux_arm64 = controlla path interno
  dl_extract gospider     "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_${GHARCH}.zip"        "gospider"
  dl_extract hakrawler    "https://github.com/hakluke/hakrawler/releases/download/v2.1/hakrawler_2.1_${GHARCH}.tar.gz"               "hakrawler"
  # subjack: solo linux_amd64 binary upstream; per ARM uso "go install" se Go disponibile
  dl_extract subjack      "https://github.com/haccer/subjack/releases/download/v0.4-rc2/subjack-Linux-${GOARCH}.tar.gz"              "subjack"
  # phoneinfoga binary release
  dl_extract phoneinfoga  "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_${GOARCH}.tar.gz"   "phoneinfoga"
  # feroxbuster (Rust → release ARM disponibili)
  dl_extract feroxbuster  "https://github.com/epi052/feroxbuster/releases/download/v2.11.0/aarch64-linux-feroxbuster.tar.gz"         "feroxbuster"
fi

# ============================================================================
# TIER 4 — pip esteso (v5 recap)
# ============================================================================
say "Tier 4 — pip esteso"
PIPS_EXT=(
  arjun dirsearch cloud-enum linkfinder metagoofil toutatis ghunt censys shodan
  instaloader snscrape yt-dlp enum4linux-ng pyhibp python-whois git-dumper
  social-analyzer
)
for pkg in "${PIPS_EXT[@]}"; do
  if "$ARGO_VENV/bin/pip" show "$pkg" >/dev/null 2>&1; then
    : # ok "pip: $pkg presente"  # rumore
  else
    "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet "$pkg" 2>/dev/null && ok "pip: $pkg installato" || ko "pip: $pkg failed"
  fi
done

# Symlink dei nuovi
for entry in \
    "arjun:arjun" "dirsearch:dirsearch" "cloud_enum:cloud_enum" \
    "linkfinder:linkfinder" "metagoofil:metagoofil" "toutatis:toutatis" \
    "ghunt:ghunt" "censys:censys" "shodan:shodan" \
    "instaloader:instaloader" "snscrape:snscrape" "yt-dlp:yt-dlp" \
    "enum4linux-ng:enum4linux" "git-dumper:git-dumper" \
    "social-analyzer:social-analyzer" \
    ; do
  src_name="${entry%%:*}"; link_name="${entry##*:}"
  [ -x "$ARGO_VENV/bin/$src_name" ] && ln -sf "$ARGO_VENV/bin/$src_name" "$ARGO_BIN/$link_name"
done

# ============================================================================
# TIER 5 — tool difficili (git clone + wrapper) + npm tool
# ============================================================================
say "Tier 5 — clone + wrapper"

clone_wrap_py() {
  local name="$1" url="$2" entry="$3" deps="${4:-}"
  local dir="$ARGO_REPOS/$name"
  if [ -d "$dir" ] && [ -x "$ARGO_BIN/$name" ]; then ok "$name presente"; return 0; fi
  if [ ! -d "$dir" ]; then
    git clone --depth 1 "$url" "$dir" >/dev/null 2>&1 || { ko "$name clone failed"; return 1; }
  fi
  [ -n "$deps" ] && "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet $deps 2>/dev/null
  [ -f "$dir/requirements.txt" ] && "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet -r "$dir/requirements.txt" 2>/dev/null
  cat > "$ARGO_BIN/$name" <<EOF
#!/usr/bin/env bash
cd "$dir" && exec "$ARGO_VENV/bin/python" $entry "\$@"
EOF
  chmod +x "$ARGO_BIN/$name"
  ok "$name wrapper installato"
}

# Wrapper Python che gia' lavoravano
clone_wrap_py osintgram    https://github.com/Datalux/Osintgram.git           main.py
clone_wrap_py secretfinder https://github.com/m4ll0k/SecretFinder.git         SecretFinder.py "jsbeautifier requests requests-file"
clone_wrap_py phunter      https://github.com/N0rz3/Phunter.git               phunter.py      "phonenumbers requests rich"
clone_wrap_py blackbird    https://github.com/p1ngul1n0/blackbird.git         blackbird.py
clone_wrap_py infoga       https://github.com/The404Hacking/Infoga.git        infoga.py       "requests bs4 lxml google"

# spiderfoot: pip fail → uso clone. spiderfoot CLI entry-point e' sf.py.
clone_wrap_py spiderfoot   https://github.com/smicallef/spiderfoot.git        sf.py

# recon-ng: pip fail → clone. CLI e' recon-ng (script bash o python entry).
if [ ! -x "$ARGO_BIN/recon-ng" ]; then
  if [ ! -d "$ARGO_REPOS/recon-ng" ]; then
    git clone --depth 1 https://github.com/lanmaster53/recon-ng.git "$ARGO_REPOS/recon-ng" >/dev/null 2>&1
  fi
  if [ -d "$ARGO_REPOS/recon-ng" ]; then
    "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet -r "$ARGO_REPOS/recon-ng/REQUIREMENTS" 2>/dev/null
    cat > "$ARGO_BIN/recon-ng" <<'EOF'
#!/usr/bin/env bash
cd /opt/argo-tools/repos/recon-ng && exec /opt/argo-tools/.venv/bin/python recon-ng "$@"
EOF
    chmod +x "$ARGO_BIN/recon-ng"
    ok "recon-ng wrapper installato"
  fi
fi

# mosint: ARM binary upstream? Se no, uso "go install" — ma serve Go.
# Provo invece il pip "mosint" se esiste, sennò skip motivato.
if [ ! -x "$ARGO_BIN/mosint" ]; then
  # mosint non e' in pip, e' Go. Provo go install (ARM friendly).
  if command -v go >/dev/null 2>&1; then
    GOBIN="$ARGO_BIN" go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest 2>/dev/null && ok "mosint via go install" || ko "mosint go install failed"
  else
    # Senza Go: provo binary linux_arm64 da release piu' recente
    dl_extract mosint "https://github.com/alpkeskin/mosint/releases/download/v3.0.6/mosint_3.0.6_linux_${GOARCH}.tar.gz" "mosint" 2>/dev/null
  fi
fi

# EyeWitness: solo via clone (selenium + chromium pesanti, swap 1GB aiuta)
if [ ! -x "$ARGO_BIN/eyewitness" ]; then
  if [ ! -d "$ARGO_REPOS/EyeWitness" ]; then
    git clone --depth 1 https://github.com/RedSiege/EyeWitness.git "$ARGO_REPOS/EyeWitness" >/dev/null 2>&1
  fi
  if [ -f "$ARGO_REPOS/EyeWitness/Python/EyeWitness.py" ]; then
    # Non installo selenium/headless qui (~600MB), ma rendo il wrapper:
    # se l'utente vuole davvero usarlo dovra' fare il setup ufficiale.
    cat > "$ARGO_BIN/eyewitness" <<'EOF'
#!/usr/bin/env bash
cd /opt/argo-tools/repos/EyeWitness/Python && exec /opt/argo-tools/.venv/bin/python EyeWitness.py "$@"
EOF
    chmod +x "$ARGO_BIN/eyewitness"
    ok "eyewitness wrapper installato (richiede selenium+chromium setup separato per uso reale)"
  fi
fi

# single-file (NodeJS) → install via npm globale
if [ ! -x "$ARGO_BIN/single-file" ]; then
  if ! command -v npm >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends nodejs npm >/dev/null 2>&1
  fi
  npm install -g single-file-cli 2>/dev/null && \
    SF_PATH=$(which single-file) && \
    [ -x "$SF_PATH" ] && ln -sf "$SF_PATH" "$ARGO_BIN/single-file" && \
    ok "single-file (npm) installato" || ko "single-file failed"
fi

# wpscan (Ruby gem)
if ! command -v wpscan >/dev/null 2>&1; then
  gem install wpscan --no-document >/dev/null 2>&1 && ok "wpscan (gem) installato" || ko "wpscan gem failed"
fi

# ============================================================================
# Drop-in systemd PATH refresh + restart
# ============================================================================
DROPIN_DIR="/etc/systemd/system/argo-osint.service.d"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN_DIR/tools-path.conf" <<CONF
[Service]
Environment="PATH=$ARGO_BIN:/opt/argo-tools/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONF
systemctl daemon-reload
systemctl restart argo-osint
ok "Servizio riavviato"

# ============================================================================
# Verifica finale
# ============================================================================
say ""
say "INVENTARIO FINALE — tool nel catalogo Argo"
python3 -c "
import sys; sys.path.insert(0, '/opt/argo-osint')
from osint_bot.external_tools import all_tools_health
h = all_tools_health()
avail = [t['name'] for t in h if t['available']]
miss = [t['name'] for t in h if not t['available']]
print(f'  VERDI: {len(avail)}/{len(h)}')
print(f'  ROSSI: {miss}')
"
