#!/usr/bin/env bash
# Argo OSINT — installer v4 (RAM-safe per VM 1GB con swap dedicato).
#
# Strategia:
#   1) Crea SWAP file 2GB se assente (la VM 1GB non ha swap → OOM facili).
#   2) Installa pip UNO ALLA VOLTA, controllando free MEM tra una install
#      e l'altra. Se sotto soglia, salta il pacchetto.
#   3) Niente pacchetti certamente OOM su 1GB: spiderfoot (~400MB resident),
#      social-analyzer (Node+headless), EyeWitness (selenium+chromium),
#      wpscan (ruby build).
#   4) Recon-ng e' borderline: lo proviamo per ultimo con --no-cache-dir.
#   5) Tier 5 = solo binari precompilati (no Go install).
#   6) Idempotente, ri-eseguibile.

set -uo pipefail

say()  { echo "[v4] $*"; }
ok()   { echo -e "  \033[32m✓\033[0m $*"; }
ko()   { echo -e "  \033[31m✗\033[0m $*"; }
note() { echo -e "  \033[33m·\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: serve sudo" >&2; exit 1; }

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"
ARGO_REPOS="$ARGO_TOOLS_DIR/repos"
mkdir -p "$ARGO_BIN" "$ARGO_REPOS"

# Minimum free MB before installing the next package. Sotto questa soglia,
# saltiamo e segnaliamo. Sulla VM 1GB con swap 2GB, ~150 MB sono ragionevoli.
MIN_FREE_MB=150
free_mb() {
  free -m | awk '/^Mem:/ { print $7 }'   # "available" = piu' realistico di "free"
}

# ============================================================================
# Step 0 — swap file 2GB (one-shot)
# ============================================================================
say "Swap file 2GB"
if swapon --show 2>/dev/null | grep -q '/swapfile'; then
  ok "swap gia' attivo: $(swapon --show --bytes | awk 'NR==2{print $3}')"
else
  if [ -f /swapfile ]; then
    note "swapfile esistente non attivo: lo riattivo"
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile && ok "swap riattivato"
  else
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile && ok "swap 2GB creato e attivato"
    # Persistenza al boot:
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    # Tuning: swappiness bassa per non swappare prematuramente.
    sysctl -w vm.swappiness=20 >/dev/null
    echo 'vm.swappiness = 20' > /etc/sysctl.d/99-argo-swap.conf
    ok "swappiness=20 + persistente"
  fi
fi
free -m | head -3

# ============================================================================
# Step 1 — pip cautious one-by-one
# ============================================================================
say "Pip cautious (controllo memoria tra installazioni)"
PIPS=(
  arjun dirsearch cloud-enum recon-ng linkfinder metagoofil toutatis
  ghunt censys shodan instaloader snscrape yt-dlp enum4linux-ng
  pyhibp python-whois git-dumper
)
for pkg in "${PIPS[@]}"; do
  if "$ARGO_VENV/bin/pip" show "$pkg" >/dev/null 2>&1; then
    ok "$pkg gia' installato"; continue
  fi
  FM=$(free_mb)
  if [ "$FM" -lt "$MIN_FREE_MB" ]; then
    ko "$pkg: SKIP (free=${FM}MB < $MIN_FREE_MB)"; continue
  fi
  if "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet "$pkg" 2>/dev/null; then
    ok "$pkg installato (free=$(free_mb)MB)"
  else
    ko "$pkg failed (free=$(free_mb)MB)"
  fi
done

# Symlink eseguibili dal venv -> ARGO_BIN
say "Symlink CLI"
declare -A SYMLINKS=(
  [arjun]=arjun [dirsearch]=dirsearch [cloud_enum]=cloud_enum
  [recon-ng]=recon-ng [linkfinder]=linkfinder [metagoofil]=metagoofil
  [toutatis]=toutatis [ghunt]=ghunt [censys]=censys [shodan]=shodan
  [instaloader]=instaloader [snscrape]=snscrape [yt-dlp]=yt-dlp
  [enum4linux-ng]=enum4linux [git-dumper]=git-dumper
  [theHarvester]=theHarvester [sherlock]=sherlock [maigret]=maigret
  [holehe]=holehe [socialscan]=socialscan [h8mail]=h8mail
)
for src_name in "${!SYMLINKS[@]}"; do
  src="$ARGO_VENV/bin/$src_name"
  link="$ARGO_BIN/${SYMLINKS[$src_name]}"
  [ -x "$src" ] || [ -L "$src" ] || continue
  ln -sf "$src" "$link" && ok "$(basename $link)"
done

# ============================================================================
# Step 2 — binari precompilati (Tier 5 + gitleaks)
# ============================================================================
say "Binari precompilati"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GHARCH="linux_amd64"; GHARCH2="amd64";;
  aarch64|arm64) GHARCH="linux_arm64"; GHARCH2="arm64";;
  *) GHARCH=""; GHARCH2="";;
esac

dl_extract() {
  local name="$1" url="$2" inner="$3"
  [ -x "$ARGO_BIN/$name" ] && { ok "$name gia' presente"; return 0; }
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
      local found; found=$(find . -name "$(basename $inner)" -type f -executable 2>/dev/null | head -1)
      if [ -n "$found" ]; then
        install -m 0755 "$found" "$ARGO_BIN/$name" && ok "$name installato (annidato)"
      else
        ko "$name (inner '$inner' non trovato)"
      fi
    fi
  else
    ko "$name (download failed)"
  fi
  popd >/dev/null; rm -rf "$tmp"
}

if [ -n "$GHARCH" ]; then
  dl_extract nuclei      "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_${GHARCH}.zip" "nuclei"
  dl_extract dalfox      "https://github.com/hahwul/dalfox/releases/download/v2.10.0/dalfox_2.10.0_${GHARCH}.tar.gz" "dalfox"
  dl_extract gau         "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_${GHARCH}.tar.gz" "gau"
  dl_extract gospider    "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_${GHARCH}.zip" "gospider_v1.1.6_${GHARCH}/gospider"
  dl_extract hakrawler   "https://github.com/hakluke/hakrawler/releases/download/v2.1/hakrawler_2.1_${GHARCH}.tar.gz" "hakrawler"
  dl_extract waybackurls "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-${GHARCH}-0.1.0.tgz" "waybackurls"
  dl_extract subjack     "https://github.com/haccer/subjack/releases/download/v0.4-rc2/subjack-Linux-amd64.tar.gz" "subjack"
  dl_extract mosint      "https://github.com/alpkeskin/mosint/releases/download/v3.0.6/mosint_3.0.6_${GHARCH}.tar.gz" "mosint"
  if [ ! -x "$ARGO_BIN/gitleaks" ]; then
    GLAR="${GHARCH2}"
    [ "$GLAR" = "amd64" ] && GLAR=x64
    dl_extract gitleaks  "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GLAR}.tar.gz" "gitleaks"
  fi
fi

# ============================================================================
# Step 3 — git clone + wrapper (light)
# ============================================================================
say "Git clone wrapper"
clone_wrap_py() {
  local name="$1" url="$2" entry="$3" deps="${4:-}"
  local dir="$ARGO_REPOS/$name"
  if [ -d "$dir" ] && [ -x "$ARGO_BIN/$name" ]; then ok "$name gia' presente"; return 0; fi
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

clone_wrap_py osintgram    https://github.com/Datalux/Osintgram.git           main.py
clone_wrap_py secretfinder https://github.com/m4ll0k/SecretFinder.git         SecretFinder.py "jsbeautifier requests requests-file"
clone_wrap_py phunter      https://github.com/N0rz3/Phunter.git               phunter.py      "phonenumbers requests rich"
clone_wrap_py blackbird    https://github.com/p1ngul1n0/blackbird.git         blackbird.py

# WhatsMyName dataset
[ -d "$ARGO_REPOS/whatsmyname" ] || \
  git clone --depth 1 https://github.com/WebBreacher/WhatsMyName.git "$ARGO_REPOS/whatsmyname" >/dev/null 2>&1 \
  && ok "WhatsMyName dataset"

# ============================================================================
# Drop-in systemd refresh
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
# Final report
# ============================================================================
say ""
say "Skip definitivi per 1GB RAM (non installabili senza upgrade istanza):"
note "spiderfoot      : daemon ~400MB resident"
note "social-analyzer : Node + headless"
note "EyeWitness      : selenium + chromium"
note "wpscan          : ruby-dev build ~800MB peak"
say ""
say "MEM finale: $(free -m | awk '/^Mem:/ {printf \"used=%dMB free=%dMB avail=%dMB\", $3,$4,$7}')"
say "Fatto."
