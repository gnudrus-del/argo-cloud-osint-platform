#!/usr/bin/env bash
# Argo OSINT — installer v5 — TUTTI i tool richiesti raggiungibili.
#
# Obiettivo: rendere funzionanti (= eseguibile presente + raggiungibile dal
# servizio argo-osint) la lista esplicita richiesta dall'utente:
#   infoga, mosint, instaloader, secretfinder, phunter, spiderfoot,
#   social_analyzer, theHarvester, recon-ng, osintgram, blackbird
#
# Niente skip preventivi: i tool grossi (spiderfoot, social_analyzer) li
# proviamo davvero. La VM 1GB e' supportata da un swap 2GB creato qui.
#
# Idempotente. Resiliente. Se la VM e' gia' stata trattata da v1-v4, salta
# automaticamente.

set -uo pipefail

say()  { echo "[v5] $*"; }
ok()   { echo -e "  \033[32m✓\033[0m $*"; }
ko()   { echo -e "  \033[31m✗\033[0m $*"; }
note() { echo -e "  \033[33m·\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: serve sudo" >&2; exit 1; }

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"
ARGO_REPOS="$ARGO_TOOLS_DIR/repos"
mkdir -p "$ARGO_BIN" "$ARGO_REPOS"

# ============================================================================
# STEP 0 — Swap 2GB (one-shot, persistente)
# ============================================================================
say "Swap 2GB"
if swapon --show 2>/dev/null | grep -q '/swapfile'; then
  ok "swap gia' attivo"
else
  [ -f /swapfile ] && swapoff /swapfile 2>/dev/null || true
  fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile && ok "swap 2GB attivato"
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -w vm.swappiness=20 >/dev/null
  echo 'vm.swappiness = 20' > /etc/sysctl.d/99-argo-swap.conf
fi
free -m | awk '/Mem|Swap/'

# ============================================================================
# STEP 1 — venv condiviso
# ============================================================================
[ -d "$ARGO_VENV" ] || python3 -m venv "$ARGO_VENV"
"$ARGO_VENV/bin/pip" install --no-cache-dir --quiet --upgrade pip 2>/dev/null

# ============================================================================
# STEP 2 — pip dei tool richiesti
# ============================================================================
say "Pip — tool richiesti"
# Order: leggeri prima, pesanti dopo. Ognuno autonomo.
PIPS=(
  "theHarvester:theHarvester"
  "instaloader:instaloader"
  "snscrape:snscrape"
  "shodan:shodan"
  "censys:censys"
  "ghunt:ghunt"
  "toutatis:toutatis"
  "linkfinder:linkfinder"
  "arjun:arjun"
  "dirsearch:dirsearch"
  "metagoofil:metagoofil"
  "cloud-enum:cloud_enum"
  "git-dumper:git-dumper"
  "yt-dlp:yt-dlp"
  "enum4linux-ng:enum4linux"
  "social-analyzer:social-analyzer"
  "recon-ng:recon-ng"
  "spiderfoot:sf"
)
for entry in "${PIPS[@]}"; do
  pkg="${entry%%:*}"; bin="${entry##*:}"
  if "$ARGO_VENV/bin/pip" show "$pkg" >/dev/null 2>&1; then
    ok "pip: $pkg gia' installato"
  else
    if "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet "$pkg" 2>/dev/null; then
      ok "pip: $pkg installato"
    else
      ko "pip: $pkg FAILED"
    fi
  fi
  src="$ARGO_VENV/bin/$bin"
  [ -x "$src" ] || [ -L "$src" ] && ln -sf "$src" "$ARGO_BIN/$bin" 2>/dev/null
done

# Fix alias case-sensitive
[ -x "$ARGO_VENV/bin/theHarvester" ] && ln -sf "$ARGO_VENV/bin/theHarvester" "$ARGO_BIN/theHarvester"
# spiderfoot espone sia "sf" che "spiderfoot"
[ -x "$ARGO_VENV/bin/sf" ] && ln -sf "$ARGO_VENV/bin/sf" "$ARGO_BIN/spiderfoot"
# sherlock/maigret/holehe gia' installati da v1
for t in sherlock maigret holehe socialscan h8mail; do
  [ -x "$ARGO_VENV/bin/$t" ] && ln -sf "$ARGO_VENV/bin/$t" "$ARGO_BIN/$t"
done

# ============================================================================
# STEP 3 — git clone + wrapper per tool senza pip
# ============================================================================
say "Git clone + wrapper"

# Helper: clone_wrap NAME URL ENTRY_RELATIVE [pip_deps]
clone_wrap() {
  local name="$1" url="$2" entry="$3" deps="${4:-}"
  local dir="$ARGO_REPOS/$name"
  if [ -d "$dir" ] && [ -x "$ARGO_BIN/$name" ]; then ok "$name gia' presente"; return 0; fi
  if [ ! -d "$dir" ]; then
    if ! git clone --depth 1 "$url" "$dir" >/dev/null 2>&1; then
      ko "$name clone failed"; return 1
    fi
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

clone_wrap osintgram    https://github.com/Datalux/Osintgram.git    main.py
clone_wrap secretfinder https://github.com/m4ll0k/SecretFinder.git  SecretFinder.py "jsbeautifier requests requests-file"
clone_wrap phunter      https://github.com/N0rz3/Phunter.git        phunter.py      "phonenumbers requests rich"
clone_wrap blackbird    https://github.com/p1ngul1n0/blackbird.git  blackbird.py

# infoga: l'originale m4ll0k e' Python 2 deprecato. Uso fork Python 3 attivo:
# https://github.com/The404Hacking/Infoga (Python 3 port mantenuto).
clone_wrap infoga       https://github.com/The404Hacking/Infoga.git infoga.py       "requests bs4 lxml google"

# ============================================================================
# STEP 4 — binari precompilati (mosint, nuclei, dalfox, ecc.)
# ============================================================================
say "Binari precompilati"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GHARCH="linux_amd64";;
  aarch64|arm64) GHARCH="linux_arm64";;
  *) GHARCH="";;
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
    local found
    if [ -f "$inner" ]; then
      install -m 0755 "$inner" "$ARGO_BIN/$name" && ok "$name installato"
    elif found=$(find . -name "$(basename $inner)" -type f -executable 2>/dev/null | head -1); [ -n "$found" ]; then
      install -m 0755 "$found" "$ARGO_BIN/$name" && ok "$name installato (annidato)"
    else
      ko "$name: inner '$inner' non trovato"
    fi
  else
    ko "$name: download failed"
  fi
  popd >/dev/null; rm -rf "$tmp"
}

if [ -n "$GHARCH" ]; then
  # mosint (priorita' utente)
  dl_extract mosint    "https://github.com/alpkeskin/mosint/releases/download/v3.0.6/mosint_3.0.6_${GHARCH}.tar.gz" "mosint"
  # nuclei
  dl_extract nuclei    "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_${GHARCH}.zip" "nuclei"
  # dalfox
  dl_extract dalfox    "https://github.com/hahwul/dalfox/releases/download/v2.10.0/dalfox_2.10.0_${GHARCH}.tar.gz" "dalfox"
  # gospider
  dl_extract gospider  "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_${GHARCH}.zip" "gospider_v1.1.6_${GHARCH}/gospider"
  # hakrawler
  dl_extract hakrawler "https://github.com/hakluke/hakrawler/releases/download/v2.1/hakrawler_2.1_${GHARCH}.tar.gz" "hakrawler"
  # gitleaks
  GLAR="${GHARCH##linux_}"
  [ "$GLAR" = "amd64" ] && GLAR=x64
  dl_extract gitleaks  "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GLAR}.tar.gz" "gitleaks"
fi

# ============================================================================
# STEP 5 — drop-in systemd + restart
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
# STEP 6 — Verifica copertura della lista utente
# ============================================================================
say ""
say "Verifica lista utente:"
for t in infoga mosint instaloader secretfinder phunter spiderfoot social-analyzer theHarvester recon-ng osintgram blackbird; do
  if [ -x "$ARGO_BIN/$t" ] || [ -L "$ARGO_BIN/$t" ]; then
    ok "$t -> $ARGO_BIN/$t"
  else
    ko "$t MANCANTE"
  fi
done

say ""
say "MEM finale: $(free -m | awk '/^Mem:/ {printf \"used=%dMB avail=%dMB\", $3,$7}'), swap: $(free -m | awk '/^Swap:/ {printf \"%dMB used\", $3}')"
say "Fatto."
