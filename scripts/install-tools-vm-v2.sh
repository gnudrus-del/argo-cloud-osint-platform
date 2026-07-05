#!/usr/bin/env bash
# Argo OSINT — installer v2 (extension dei tier del v1).
#
# Aggiunge:
#  - Tier 4 (apt extra)   : nmap, masscan, nikto, enum4linux, snmp, ffmpeg,
#                           fierce, gobuster, ffuf, smbmap, testssl
#  - Tier 5 (Go install)  : dnsx naabu katana nuclei dalfox gospider gau
#                           hakrawler waybackurls subjack mosint
#  - Tier 6 (pip extra)   : arjun dirsearch cloud-enum recon-ng spiderfoot
#                           eyewitness social-analyzer linkfinder metagoofil
#                           toutatis ghunt censys shodan-cli
#  - Tier 7 (git clone)   : osintgram, secretfinder, phunter
#  - Tier 8 (binary)      : gitleaks
#  - Fix bug v1: alias case-sensitive per theHarvester
#  - Skip motivati        : wpscan, infoga (vedi NOTES)
#
# Tutti i tool installati restano "gated" dall'autorizzazione di scope/red-team
# dello spec OPSEC: installare != usare senza permesso.
#
# Idempotente: si puo' rilanciare.

set -uo pipefail

say() { echo "[install-tools-v2] $*"; }
ok()  { echo -e "  \033[32m✓\033[0m $*"; }
ko()  { echo -e "  \033[31m✗\033[0m $*"; }
note(){ echo -e "  \033[33m·\033[0m $*"; }

if [ "$EUID" -ne 0 ]; then
  echo "ERR: serve sudo" >&2; exit 1
fi

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"
ARGO_REPOS="$ARGO_TOOLS_DIR/repos"
ARGO_GOPATH="$ARGO_TOOLS_DIR/go"

mkdir -p "$ARGO_TOOLS_DIR" "$ARGO_BIN" "$ARGO_REPOS" "$ARGO_GOPATH"

# ============================================================================
# FIX bug v1: theHarvester (case-sensitive su Linux)
# ============================================================================
say "Fix v1: alias theHarvester"
if [ -x "$ARGO_VENV/bin/theHarvester" ]; then
  ln -sf "$ARGO_VENV/bin/theHarvester" "$ARGO_BIN/theHarvester"
  ok "theHarvester -> $ARGO_BIN/theHarvester"
fi

# ============================================================================
# TIER 4 — apt extra
# ============================================================================
say "Tier 4 (apt extra)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Set: scanner attivi + utility passivi. Argo li gate-a comunque a livello app.
APT_EXTRA=(
  nmap masscan nikto enum4linux snmp ffmpeg fierce gobuster smbmap testssl.sh
  # ffuf e' nei repo recenti come pacchetto separato:
  ffuf
)
for pkg in "${APT_EXTRA[@]}"; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    ok "apt: $pkg gia' presente"
  else
    if apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
      ok "apt: $pkg installato"
    else
      note "apt: $pkg non disponibile nei repo (skip)"
    fi
  fi
done

# ============================================================================
# TIER 5 — Go install (toolchain + tool)
# ============================================================================
say "Tier 5 (Go install)"
GO_VERSION="1.22.5"
GO_TGZ="/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
GO_INSTALL_DIR="/usr/local/go"
if [ -x "${GO_INSTALL_DIR}/bin/go" ]; then
  ok "go gia' installato: $(${GO_INSTALL_DIR}/bin/go version)"
else
  ARCH=$(dpkg --print-architecture)
  if [ "$ARCH" = "arm64" ]; then GOARCH_TGZ=arm64; else GOARCH_TGZ=amd64; fi
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH_TGZ}.tar.gz" -o "$GO_TGZ"
  rm -rf "$GO_INSTALL_DIR"
  tar -C /usr/local -xzf "$GO_TGZ"
  rm -f "$GO_TGZ"
  ok "go ${GO_VERSION} installato in $GO_INSTALL_DIR"
fi
export PATH="$GO_INSTALL_DIR/bin:$ARGO_BIN:$PATH"
export GOPATH="$ARGO_GOPATH"
export GOBIN="$ARGO_GOPATH/bin"
mkdir -p "$GOBIN"

GO_TOOLS=(
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest|dnsx"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|naabu"
  "github.com/projectdiscovery/katana/cmd/katana@latest|katana"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|nuclei"
  "github.com/hahwul/dalfox/v2@latest|dalfox"
  "github.com/jaeles-project/gospider@latest|gospider"
  "github.com/lc/gau/v2/cmd/gau@latest|gau"
  "github.com/hakluke/hakrawler@latest|hakrawler"
  "github.com/tomnomnom/waybackurls@latest|waybackurls"
  "github.com/haccer/subjack@latest|subjack"
  "github.com/alpkeskin/mosint/v3/cmd/mosint@latest|mosint"
)
for entry in "${GO_TOOLS[@]}"; do
  pkg="${entry%%|*}"
  bin="${entry##*|}"
  if [ -x "$GOBIN/$bin" ]; then
    ok "go: $bin gia' presente"
  else
    if go install "$pkg" 2>/tmp/go_${bin}.err; then
      ln -sf "$GOBIN/$bin" "$ARGO_BIN/$bin"
      ok "go: $bin installato"
    else
      ko "go: $bin failed -> $(tail -1 /tmp/go_${bin}.err | head -c 120)"
    fi
  fi
done

# ============================================================================
# TIER 6 — pip esteso (nel venv condiviso /opt/argo-tools/.venv)
# ============================================================================
say "Tier 6 (pip esteso)"
if [ ! -d "$ARGO_VENV" ]; then
  python3 -m venv "$ARGO_VENV"
fi
# shellcheck disable=SC1091
source "$ARGO_VENV/bin/activate"
pip install --quiet --upgrade pip

# Mappa pacchetto pip -> nome eseguibile finale (puo' differire).
declare -A PIP_TOOLS=(
  [arjun]="arjun"
  [dirsearch]="dirsearch"
  [cloud-enum]="cloud_enum"
  [recon-ng]="recon-ng"
  [spiderfoot]="sf"            # spiderfoot espone "sf" o "spiderfoot"; symlinko entrambi
  [linkfinder]="linkfinder"
  [metagoofil]="metagoofil"
  [toutatis]="toutatis"
  [ghunt]="ghunt"
  [censys]="censys"
  [shodan]="shodan"
  [social-analyzer]="social-analyzer"
  # eyewitness ha deps grosse (selenium, geckodriver) → tentiamo, fallisce con grazia
  [EyeWitness]="eyewitness"
)
for pkg in "${!PIP_TOOLS[@]}"; do
  if pip show "$pkg" >/dev/null 2>&1; then
    ok "pip: $pkg gia' installato"
  else
    if pip install --quiet "$pkg" 2>/tmp/pip_${pkg}.err; then
      ok "pip: $pkg installato"
    else
      ko "pip: $pkg failed -> $(tail -1 /tmp/pip_${pkg}.err | head -c 120)"
    fi
  fi
done
deactivate || true

# Symlink eseguibili dal venv → ARGO_BIN. Spec.executable e' case-sensitive.
say "Symlink CLI dal venv"
for entry in \
    "sherlock:sherlock" \
    "maigret:maigret" \
    "holehe:holehe" \
    "theHarvester:theHarvester" \
    "socialscan:socialscan" \
    "h8mail:h8mail" \
    "arjun:arjun" \
    "dirsearch:dirsearch" \
    "cloud_enum:cloud_enum" \
    "recon-ng:recon-ng" \
    "sf:spiderfoot" \
    "spiderfoot:spiderfoot" \
    "linkfinder:linkfinder" \
    "metagoofil:metagoofil" \
    "toutatis:toutatis" \
    "ghunt:ghunt" \
    "censys:censys" \
    "shodan:shodan" \
    "social-analyzer:social-analyzer" \
    "eyewitness:eyewitness"; do
  src_name="${entry%%:*}"
  link_name="${entry##*:}"
  src="$ARGO_VENV/bin/$src_name"
  if [ -x "$src" ] || [ -L "$src" ]; then
    ln -sf "$src" "$ARGO_BIN/$link_name"
    ok "$link_name -> $src_name"
  fi
done

# ============================================================================
# TIER 7 — git clone + wrapper
# ============================================================================
say "Tier 7 (git clone + wrapper)"

# osintgram: richiede file config session (login Instagram fatto dall'utente)
clone_and_wrap_osintgram() {
  local dir="$ARGO_REPOS/osintgram"
  if [ -d "$dir" ]; then ok "osintgram: repo gia' presente"; return 0; fi
  if git clone --depth 1 https://github.com/Datalux/Osintgram.git "$dir" >/dev/null 2>&1; then
    cd "$dir"
    "$ARGO_VENV/bin/pip" install --quiet -r requirements.txt 2>/dev/null || note "osintgram: requirements parziali"
    cat > "$ARGO_BIN/osintgram" <<EOF
#!/usr/bin/env bash
cd "$dir" && exec "$ARGO_VENV/bin/python" main.py "\$@"
EOF
    chmod +x "$ARGO_BIN/osintgram"
    ok "osintgram: wrapper installato (richiede login IG in $dir/config/)"
  else
    ko "osintgram: git clone failed"
  fi
}

# secretfinder: standalone Python (m4ll0k)
clone_and_wrap_secretfinder() {
  local dir="$ARGO_REPOS/secretfinder"
  if [ -d "$dir" ]; then ok "secretfinder: repo gia' presente"; return 0; fi
  if git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git "$dir" >/dev/null 2>&1; then
    "$ARGO_VENV/bin/pip" install --quiet jsbeautifier requests requests-file 2>/dev/null || true
    cat > "$ARGO_BIN/secretfinder" <<EOF
#!/usr/bin/env bash
exec "$ARGO_VENV/bin/python" "$dir/SecretFinder.py" "\$@"
EOF
    chmod +x "$ARGO_BIN/secretfinder"
    ok "secretfinder: wrapper installato"
  else
    ko "secretfinder: git clone failed"
  fi
}

# phunter: phone OSINT (https://github.com/N0rz3/Phunter)
clone_and_wrap_phunter() {
  local dir="$ARGO_REPOS/phunter"
  if [ -d "$dir" ]; then ok "phunter: repo gia' presente"; return 0; fi
  if git clone --depth 1 https://github.com/N0rz3/Phunter.git "$dir" >/dev/null 2>&1; then
    "$ARGO_VENV/bin/pip" install --quiet phonenumbers requests rich 2>/dev/null || true
    cat > "$ARGO_BIN/phunter" <<EOF
#!/usr/bin/env bash
cd "$dir" && exec "$ARGO_VENV/bin/python" phunter.py "\$@"
EOF
    chmod +x "$ARGO_BIN/phunter"
    ok "phunter: wrapper installato"
  else
    ko "phunter: git clone failed"
  fi
}

clone_and_wrap_osintgram
clone_and_wrap_secretfinder
clone_and_wrap_phunter

# git-dumper (gitdumper in TOOL_SPECS): pip "git-dumper"
say "git-dumper via pip"
if "$ARGO_VENV/bin/pip" install --quiet git-dumper 2>/dev/null && [ -x "$ARGO_VENV/bin/git-dumper" ]; then
  ln -sf "$ARGO_VENV/bin/git-dumper" "$ARGO_BIN/git-dumper"
  ok "git-dumper installato"
else
  ko "git-dumper non installato"
fi

# ============================================================================
# TIER 8 — binary (gitleaks)
# ============================================================================
say "Tier 8 (binary download)"
GITLEAKS_VERSION="8.18.4"
ARCH=$(uname -m); case "$ARCH" in x86_64) GLAR=x64;; aarch64) GLAR=arm64;; *) GLAR="";; esac
if [ -x "$ARGO_BIN/gitleaks" ]; then
  ok "gitleaks gia' presente"
elif [ -n "$GLAR" ]; then
  tmp=$(mktemp -d); pushd "$tmp" >/dev/null
  if curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GLAR}.tar.gz" -o gl.tgz \
     && tar -xzf gl.tgz && [ -f gitleaks ]; then
    install -m 0755 gitleaks "$ARGO_BIN/gitleaks"
    ok "gitleaks ${GITLEAKS_VERSION} installato"
  else
    ko "gitleaks: download failed"
  fi
  popd >/dev/null; rm -rf "$tmp"
fi

# ============================================================================
# Final: drop-in systemd (assicura PATH aggiornato anche se il v1 non era stato eseguito)
# ============================================================================
DROPIN_DIR="/etc/systemd/system/argo-osint.service.d"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN_DIR/tools-path.conf" <<CONF
[Service]
Environment="PATH=$ARGO_BIN:$ARGO_GOPATH/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONF
systemctl daemon-reload
systemctl restart argo-osint
ok "Drop-in systemd aggiornato + servizio riavviato"

# ============================================================================
# Note finali
# ============================================================================
say ""
say "Tool NON installati (motivati):"
note "wpscan       : richiede Ruby + bundler. Install: sudo apt install ruby-dev && gem install wpscan"
note "infoga       : Python 2 deprecato (repo non mantenuto)."
note "ffprobe      : viene da apt 'ffmpeg' (provato sopra)."
note "snmpwalk     : viene da apt 'snmp' (provato sopra)."
say ""
say "Tool installati ma RICHIEDONO CREDENZIALI per funzionare:"
note "ghunt        : richiede cookie Google (vedi: ghunt login)"
note "osintgram    : richiede login Instagram in $ARGO_REPOS/osintgram/config/"
note "censys       : richiede API key (CENSYS_API_ID + CENSYS_API_SECRET)"
note "shodan       : richiede 'shodan init <API_KEY>'"
note "wpscan (se installato): WPSCAN_API_TOKEN"
say ""
say "Fatto. Argo health-check rileva i tool al prossimo refresh (cache 30s)."
