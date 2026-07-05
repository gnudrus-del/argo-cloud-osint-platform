#!/usr/bin/env bash
# Argo OSINT — installer v3 (RAM-light, adatto a VM 1GB).
#
# Cosa fa:
#  1) Completa cio' che v2 non ha finito (interrotto da OOM/disconnect SSH).
#  2) Niente Go install (compila → OOM su 1GB). Usa BINARI PRECOMPILATI
#     dalle release upstream per nuclei, dalfox, gau, gospider, hakrawler,
#     waybackurls, subjack, mosint.
#  3) Pip estesi (Tier 6) per arjun, dirsearch, cloud-enum, recon-ng,
#     spiderfoot, social-analyzer, linkfinder, metagoofil, toutatis, ghunt,
#     censys, shodan, instaloader, snscrape, yt-dlp, enum4linux-ng.
#  4) Tier 7 git clone + wrapper per osintgram, secretfinder, phunter,
#     blackbird.
#  5) Tier 8 gitleaks (binary).
#  6) SKIP motivati: EyeWitness (selenium+chromium = OOM su 1GB),
#     wpscan (ruby+headers = OOM su 1GB), infoga (Python2 deprecato).
#  7) Drop-in systemd ricreato; servizio restartato a fine.
#
# Idempotente. Continuabile.

set -uo pipefail

say() { echo "[v3] $*"; }
ok()  { echo -e "  \033[32m✓\033[0m $*"; }
ko()  { echo -e "  \033[31m✗\033[0m $*"; }
note(){ echo -e "  \033[33m·\033[0m $*"; }

[ "$EUID" -ne 0 ] && { echo "ERR: serve sudo" >&2; exit 1; }

ARGO_TOOLS_DIR="/opt/argo-tools"
ARGO_VENV="$ARGO_TOOLS_DIR/.venv"
ARGO_BIN="$ARGO_TOOLS_DIR/bin"
ARGO_REPOS="$ARGO_TOOLS_DIR/repos"
mkdir -p "$ARGO_BIN" "$ARGO_REPOS"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GHARCH="linux_amd64"; GHARCH2="linux-amd64";;
  aarch64|arm64) GHARCH="linux_arm64"; GHARCH2="linux-arm64";;
  *) GHARCH=""; GHARCH2="";;
esac

# ============================================================================
# Fix alias case-sensitive ereditato dal v1
# ============================================================================
say "Alias case-sensitive (theHarvester)"
[ -x "$ARGO_VENV/bin/theHarvester" ] && \
  ln -sf "$ARGO_VENV/bin/theHarvester" "$ARGO_BIN/theHarvester" && \
  ok "theHarvester aliased"

# ============================================================================
# Tier 6 — pip esteso (piccoli pacchetti, OK su 1GB)
# ============================================================================
say "Tier 6 — pip esteso"
PIPS=(
  arjun dirsearch cloud-enum recon-ng linkfinder metagoofil toutatis
  ghunt censys shodan instaloader snscrape yt-dlp enum4linux-ng
  pyhibp python-whois
  # social-analyzer e' piccolo
  social-analyzer
  # spiderfoot e' pesante ma manageable
  spiderfoot
)
for pkg in "${PIPS[@]}"; do
  if "$ARGO_VENV/bin/pip" show "$pkg" >/dev/null 2>&1; then
    ok "pip: $pkg gia' installato"
  else
    if "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet "$pkg" 2>/dev/null; then
      ok "pip: $pkg installato"
    else
      ko "pip: $pkg failed"
    fi
  fi
done

# Symlink eseguibili dal venv -> ARGO_BIN (case-sensitive corretto)
say "Symlink CLI dal venv"
declare -A SYMLINKS=(
  [arjun]=arjun
  [dirsearch]=dirsearch
  [cloud_enum]=cloud_enum
  [recon-ng]=recon-ng
  [linkfinder]=linkfinder
  [metagoofil]=metagoofil
  [toutatis]=toutatis
  [ghunt]=ghunt
  [censys]=censys
  [shodan]=shodan
  [instaloader]=instaloader
  [snscrape]=snscrape
  [yt-dlp]=yt-dlp
  [enum4linux-ng]=enum4linux       # alias importante: lo spec usa "enum4linux"
  [social-analyzer]=social-analyzer
  [sf]=spiderfoot
  [spiderfoot]=spiderfoot
  [theHarvester]=theHarvester
)
for src_name in "${!SYMLINKS[@]}"; do
  src="$ARGO_VENV/bin/$src_name"
  link="$ARGO_BIN/${SYMLINKS[$src_name]}"
  if [ -x "$src" ] || [ -L "$src" ]; then
    ln -sf "$src" "$link"
    ok "$(basename $link) -> $src_name"
  fi
done

# ============================================================================
# Tier 5 (riscritto) — Binari precompilati invece di Go install
# ============================================================================
say "Tier 5 — binari precompilati (no Go install, RAM-light)"

dl_extract() {
  # $1=name $2=url $3=inner_path_in_archive
  local name="$1" url="$2" inner="$3"
  if [ -x "$ARGO_BIN/$name" ]; then ok "bin: $name gia' presente"; return 0; fi
  local tmp; tmp=$(mktemp -d)
  pushd "$tmp" >/dev/null
  local fname; fname=$(basename "$url")
  if curl -fsSL "$url" -o "$fname" 2>/dev/null; then
    case "$fname" in
      *.tar.gz|*.tgz) tar -xzf "$fname" 2>/dev/null;;
      *.zip)          unzip -q "$fname" 2>/dev/null;;
    esac
    if [ -f "$inner" ]; then
      install -m 0755 "$inner" "$ARGO_BIN/$name" && ok "bin: $name installato"
    else
      # cerca ricorsivo (alcune release annidano in subdir)
      local found; found=$(find . -name "$(basename $inner)" -type f -executable 2>/dev/null | head -1)
      if [ -n "$found" ]; then
        install -m 0755 "$found" "$ARGO_BIN/$name" && ok "bin: $name installato (annidato)"
      else
        ko "bin: $name (inner not found: $inner)"
      fi
    fi
  else
    ko "bin: $name (download failed)"
  fi
  popd >/dev/null; rm -rf "$tmp"
}

if [ -n "$GHARCH" ]; then
  # nuclei — projectdiscovery (sintassi nome leggermente diversa: linux_amd64)
  dl_extract nuclei \
    "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_${GHARCH}.zip" \
    "nuclei"

  # dalfox
  dl_extract dalfox \
    "https://github.com/hahwul/dalfox/releases/download/v2.10.0/dalfox_2.10.0_${GHARCH}.tar.gz" \
    "dalfox"

  # gau v2 — lc/gau
  dl_extract gau \
    "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_${GHARCH}.tar.gz" \
    "gau"

  # gospider
  dl_extract gospider \
    "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_${GHARCH}.zip" \
    "gospider_v1.1.6_${GHARCH}/gospider"

  # hakrawler
  dl_extract hakrawler \
    "https://github.com/hakluke/hakrawler/releases/download/v2.1/hakrawler_2.1_${GHARCH}.tar.gz" \
    "hakrawler"

  # waybackurls
  dl_extract waybackurls \
    "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-${GHARCH}-0.1.0.tgz" \
    "waybackurls"

  # subjack (release schema diverso)
  dl_extract subjack \
    "https://github.com/haccer/subjack/releases/download/v0.4-rc2/subjack-Linux-amd64.tar.gz" \
    "subjack"

  # mosint (release diverse, prova due naming convention)
  if [ ! -x "$ARGO_BIN/mosint" ]; then
    dl_extract mosint \
      "https://github.com/alpkeskin/mosint/releases/download/v3.0.6/mosint_3.0.6_${GHARCH}.tar.gz" \
      "mosint"
  fi

  # gitleaks
  if [ ! -x "$ARGO_BIN/gitleaks" ]; then
    GLAR=${GHARCH##linux_}
    [ "$GLAR" = "amd64" ] && GLAR=x64
    dl_extract gitleaks \
      "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GLAR}.tar.gz" \
      "gitleaks"
  fi
else
  note "Arch '$ARCH' non riconosciuta -> skip binari precompilati"
fi

# ============================================================================
# Tier 7 — git clone + wrapper
# ============================================================================
say "Tier 7 — git clone + wrapper"

clone_wrap_py() {
  local name="$1" url="$2" entry="$3" deps="${4:-}"
  local dir="$ARGO_REPOS/$name"
  if [ -d "$dir" ] && [ -x "$ARGO_BIN/$name" ]; then ok "$name: gia' presente"; return 0; fi
  if [ ! -d "$dir" ]; then
    git clone --depth 1 "$url" "$dir" >/dev/null 2>&1 || { ko "$name: clone failed"; return 1; }
  fi
  [ -n "$deps" ] && "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet $deps 2>/dev/null
  [ -f "$dir/requirements.txt" ] && "$ARGO_VENV/bin/pip" install --no-cache-dir --quiet -r "$dir/requirements.txt" 2>/dev/null
  cat > "$ARGO_BIN/$name" <<EOF
#!/usr/bin/env bash
cd "$dir" && exec "$ARGO_VENV/bin/python" $entry "\$@"
EOF
  chmod +x "$ARGO_BIN/$name"
  ok "$name: wrapper installato"
}

clone_wrap_py osintgram     https://github.com/Datalux/Osintgram.git           main.py
clone_wrap_py secretfinder  https://github.com/m4ll0k/SecretFinder.git         SecretFinder.py "jsbeautifier requests requests-file"
clone_wrap_py phunter       https://github.com/N0rz3/Phunter.git               phunter.py      "phonenumbers requests rich"
clone_wrap_py blackbird     https://github.com/p1ngul1n0/blackbird.git         blackbird.py

# git-dumper via pip (gitdumper)
"$ARGO_VENV/bin/pip" install --no-cache-dir --quiet git-dumper 2>/dev/null \
  && [ -x "$ARGO_VENV/bin/git-dumper" ] \
  && ln -sf "$ARGO_VENV/bin/git-dumper" "$ARGO_BIN/git-dumper" \
  && ok "git-dumper installato" \
  || ko "git-dumper failed"

# WhatsMyName dataset (no executable, solo file JSON usabile da adapter)
if [ ! -d "$ARGO_REPOS/whatsmyname" ]; then
  git clone --depth 1 https://github.com/WebBreacher/WhatsMyName.git "$ARGO_REPOS/whatsmyname" >/dev/null 2>&1 \
    && ok "WhatsMyName dataset clonato in $ARGO_REPOS/whatsmyname" \
    || ko "WhatsMyName clone failed"
fi

# ============================================================================
# Final
# ============================================================================
say "Drop-in systemd refresh + restart servizio"
DROPIN_DIR="/etc/systemd/system/argo-osint.service.d"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN_DIR/tools-path.conf" <<CONF
[Service]
Environment="PATH=$ARGO_BIN:/opt/argo-tools/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONF
systemctl daemon-reload
systemctl restart argo-osint
ok "Servizio riavviato."

say ""
say "Skip motivati su VM 1GB (richiedono RAM/risorse):"
note "EyeWitness  : selenium+chromium → OOM"
note "wpscan      : ruby-dev + libcurl headers → OOM in build"
note "Go install  : compila in-memory → OOM (uso binari precompilati invece)"
note "infoga      : Python2 deprecato"

say "Fatto."
