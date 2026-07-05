#!/usr/bin/env bash
# Argo OSINT — installer v7 — fix mirati dei 13 tool ancora rossi dopo v6.
#
# Target:
#   theharvester (symlink) | testssl (symlink) | enum4linux (symlink)
#   naabu | hakrawler | subjack | waybackurls | feroxbuster (URL/build fix)
#   cloud_enum | linkfinder | metagoofil (git clone wrapper)
#   mosint (go install) | wpscan (gem + headers)

set -uo pipefail
say(){ echo "[v7] $*"; }
ok(){ echo -e "  \033[32m✓\033[0m $*"; }
ko(){ echo -e "  \033[31m✗\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: sudo" >&2; exit 1; }

ARGO_VENV="/opt/argo-tools/.venv"
ARGO_BIN="/opt/argo-tools/bin"
ARGO_REPOS="/opt/argo-tools/repos"
mkdir -p "$ARGO_BIN" "$ARGO_REPOS"

# ---------------------------------------------------------------- 1) symlinks
say "Fix symlink mancanti"

# theharvester: pip ha installato theHarvester, ma la SPEC Argo cerca
# 'theHarvester' OPPURE 'theharvester' (executable case-sensitive). v6 ha
# linkato solo theHarvester → manca theharvester.
if [ -x "$ARGO_VENV/bin/theHarvester" ]; then
  ln -sf "$ARGO_VENV/bin/theHarvester" "$ARGO_BIN/theHarvester"
  ln -sf "$ARGO_VENV/bin/theHarvester" "$ARGO_BIN/theharvester"
  ok "theHarvester + theharvester aliased"
fi

# testssl: il package apt 'testssl.sh' installa /usr/bin/testssl.sh — verifico.
TS_PATH=$(command -v testssl.sh 2>/dev/null || echo "")
if [ -n "$TS_PATH" ]; then
  ln -sf "$TS_PATH" "$ARGO_BIN/testssl.sh"
  ln -sf "$TS_PATH" "$ARGO_BIN/testssl"
  ok "testssl symlinked ($TS_PATH)"
else
  ko "testssl.sh apt non trovato (apt-get install testssl.sh fallito?)"
fi

# enum4linux: pip 'enum4linux-ng' installa l'eseguibile come enum4linux-ng.
# La spec Argo cerca 'enum4linux'. Alias.
if [ -x "$ARGO_VENV/bin/enum4linux-ng" ]; then
  ln -sf "$ARGO_VENV/bin/enum4linux-ng" "$ARGO_BIN/enum4linux"
  ln -sf "$ARGO_VENV/bin/enum4linux-ng" "$ARGO_BIN/enum4linux-ng"
  ok "enum4linux aliased da enum4linux-ng"
elif "$ARGO_VENV/bin/pip" install --quiet --no-cache-dir enum4linux-ng 2>/dev/null; then
  ln -sf "$ARGO_VENV/bin/enum4linux-ng" "$ARGO_BIN/enum4linux"
  ok "enum4linux-ng installato + aliased"
else
  ko "enum4linux-ng install failed"
fi

# ---------------------------------------------------------------- 2) git clone wrapper
say "Git clone wrapper"

clone_wrap() {
  local name="$1" url="$2" entry="$3" deps="${4:-}"
  local dir="$ARGO_REPOS/$name"
  [ -d "$dir" ] && [ -x "$ARGO_BIN/$name" ] && { ok "$name presente"; return 0; }
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

# cloud_enum: il pip "cloud-enum" su PyPI installa eseguibile "cloud_enum".
# Sembra fallito → git clone.
clone_wrap cloud_enum https://github.com/initstring/cloud_enum.git cloud_enum.py \
  "requests dnspython msal"

# linkfinder: tool standalone Python
clone_wrap linkfinder https://github.com/GerbenJavado/LinkFinder.git linkfinder.py \
  "argparse jsbeautifier"

# metagoofil: standalone, deps minime
clone_wrap metagoofil https://github.com/opsdisk/metagoofil.git metagoofil.py \
  "requests"

# ---------------------------------------------------------------- 3) binari ARM
say "Binari ARM fix URL"

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
    local found; found=$(find . -name "$(basename $inner)" -type f 2>/dev/null | head -1)
    if [ -n "$found" ]; then
      install -m 0755 "$found" "$ARGO_BIN/$name" && ok "$name installato"
    else
      ko "$name: $inner non trovato in archivio"
    fi
  else
    ko "$name: download failed ($url)"
  fi
  popd >/dev/null; rm -rf "$tmp"
}

# naabu — versione recente con ARM build (v2.3.5 ha aarch64 mancante; provo v2.3.0)
dl_extract naabu "https://github.com/projectdiscovery/naabu/releases/download/v2.3.0/naabu_2.3.0_linux_arm64.zip" "naabu"

# hakrawler — release v2.1 ARM
dl_extract hakrawler "https://github.com/hakluke/hakrawler/releases/download/v2.1/hakrawler_2.1_linux_arm64.tgz" "hakrawler"

# waybackurls — release alternativa (tomnomnom usa tar.gz scheme inconsistent)
dl_extract waybackurls "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-arm64-0.1.0.tgz" "waybackurls"

# feroxbuster — aarch64 release ufficiale
dl_extract feroxbuster "https://github.com/epi052/feroxbuster/releases/download/v2.11.0/aarch64-linux-feroxbuster.tar.gz" "feroxbuster"

# subjack — solo amd64 upstream → vado via Go install se Go presente
if [ ! -x "$ARGO_BIN/subjack" ]; then
  if command -v go >/dev/null 2>&1; then
    GOBIN="$ARGO_BIN" go install github.com/haccer/subjack@latest 2>/dev/null && ok "subjack via go install" || ko "subjack go install failed"
  else
    ko "subjack: serve Go (apt install golang-go)"
  fi
fi

# ---------------------------------------------------------------- 4) Go toolchain + mosint
say "Go toolchain + mosint"
if ! command -v go >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends golang-go >/dev/null 2>&1 && ok "go (apt) installato" || ko "go install failed"
fi
if [ ! -x "$ARGO_BIN/mosint" ] && command -v go >/dev/null 2>&1; then
  GOBIN="$ARGO_BIN" go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest 2>/tmp/mosint.err && ok "mosint via go install" || ko "mosint failed ($(tail -1 /tmp/mosint.err 2>/dev/null | head -c 80))"
fi

# subjack se non installato prima
if [ ! -x "$ARGO_BIN/subjack" ] && command -v go >/dev/null 2>&1; then
  GOBIN="$ARGO_BIN" go install github.com/haccer/subjack@latest 2>/dev/null && ok "subjack via go install" || ko "subjack go install failed"
fi

# ---------------------------------------------------------------- 5) wpscan
say "wpscan (Ruby gem)"
if ! command -v wpscan >/dev/null 2>&1; then
  # Ruby + headers gia' installati da v6. Provo gem install con verbose error capture.
  gem install wpscan --no-document 2>/tmp/wpscan.err && ok "wpscan installato" || ko "wpscan failed: $(tail -1 /tmp/wpscan.err 2>/dev/null | head -c 100)"
fi

# ---------------------------------------------------------------- 6) restart + verify
systemctl restart argo-osint
sleep 2

say ""
say "INVENTARIO FINALE"
PATH=/opt/argo-tools/bin:/opt/argo-tools/go/bin:/usr/local/bin:/usr/bin:/bin \
  /opt/argo-osint/.venv/bin/python -c "
import sys; sys.path.insert(0, '/opt/argo-osint')
from osint_bot.external_tools import _TOOL_HEALTH_CACHE, all_tools_health
_TOOL_HEALTH_CACHE.clear()
h = all_tools_health()
avail = [t['name'] for t in h if t['available']]
miss = [t['name'] for t in h if not t['available']]
print(f'  VERDI: {len(avail)}/{len(h)}')
print(f'  ROSSI ({len(miss)}): {miss}')
"
