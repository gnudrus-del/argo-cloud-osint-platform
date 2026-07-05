from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .safety import SafetyError, action_class_for_tool, authorize_action, validate_tool_target


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executable: str
    env_var: str
    args: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class ToolRun:
    name: str
    status: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None


@dataclass(frozen=True)
class ResolvedCommand:
    command: list[str]
    cwd: Path | None = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_TOOL_NAMES = {
    "spiderfoot": "spiderfoot",
    "recon_ng": "recon-ng",
    "osintgram": "osintgram",
}

# Tools whose CLI accepts "--" before the positional target to forbid
# downstream option parsing of the target token. Keep narrow: only tools
# whose argparse-based front-end is known to honour POSIX "--".
TOOLS_WITH_OPTION_TERMINATOR = {
    "nmap",
    "amass",
    "waybackurls",
    "gau",
    "singlefile",
}


TOOL_SPECS = {
    "sherlock": ToolSpec(
        name="sherlock",
        executable="sherlock",
        env_var="SHERLOCK_CMD",
        args=("{target}", "--timeout", "10", "--print-found", "--no-color"),
        description="Username lookup su siti pubblici, se installato localmente.",
    ),
    "maigret": ToolSpec(
        name="maigret",
        executable="maigret",
        env_var="MAIGRET_CMD",
        args=("{target}", "--timeout", "10", "--no-color"),
        description="Username/profile lookup su siti pubblici, se installato localmente.",
    ),
    "holehe": ToolSpec(
        name="holehe",
        executable="holehe",
        env_var="HOLEHE_CMD",
        args=("{target}", "--only-used", "--no-color"),
        description="Email account-presence check, solo con autorizzazione.",
    ),
    "socialscan": ToolSpec(
        name="socialscan",
        executable="socialscan",
        env_var="SOCIALSCAN_CMD",
        args=("{target}",),
        description="Controllo presenza pubblica di username/email, solo con autorizzazione.",
    ),
    "social_analyzer": ToolSpec(
        name="social_analyzer",
        executable="social-analyzer",
        env_var="SOCIAL_ANALYZER_CMD",
        args=("--username", "{target}", "--metadata"),
        description="Analisi username su piattaforme pubbliche, solo con autorizzazione.",
    ),
    "h8mail": ToolSpec(
        name="h8mail",
        executable="h8mail",
        env_var="H8MAIL_CMD",
        args=("-t", "{target}", "--hide"),
        description="Breach intelligence su email autorizzate; non scarica credenziali.",
    ),
    "phoneinfoga": ToolSpec(
        name="phoneinfoga",
        executable="phoneinfoga",
        env_var="PHONEINFOGA_CMD",
        args=("scan", "-n", "{target}"),
        description="Analisi passiva di numeri telefonici autorizzati.",
    ),
    "ghunt": ToolSpec(
        name="ghunt",
        executable="ghunt",
        env_var="GHUNT_CMD",
        args=("email", "{target}"),
        description="Lookup Google OSINT su email autorizzate; richiede configurazione GHunt lecita.",
    ),
    "toutatis": ToolSpec(
        name="toutatis",
        executable="toutatis",
        env_var="TOUTATIS_CMD",
        args=("-u", "{target}"),
        description="Lookup Instagram autorizzato; richiede token/sessione lecita.",
    ),
    "osintgram": ToolSpec(
        name="osintgram",
        executable="osintgram",
        env_var="OSINTGRAM_CMD",
        args=("{target}",),
        description="Analisi Instagram autorizzata; non eseguita senza setup esplicito.",
    ),
    "nmap": ToolSpec(
        name="nmap",
        executable="nmap",
        env_var="NMAP_CMD",
        args=("-Pn", "-sV", "--top-ports", "100", "--version-light", "{target}"),
        description="Network surface scan leggero su asset propri o autorizzati.",
    ),
    "theharvester": ToolSpec(
        name="theharvester",
        executable="theHarvester",
        env_var="THEHARVESTER_CMD",
        args=("-d", "{target}", "-b", "bing"),
        description="Raccolta passiva di email, host e nomi per domini autorizzati.",
    ),
    "spiderfoot": ToolSpec(
        name="spiderfoot",
        executable="spiderfoot",
        env_var="SPIDERFOOT_CMD",
        args=("-s", "{target}"),
        description="Piattaforma SpiderFoot locale, se configurata per esecuzione CLI.",
    ),
    "recon_ng": ToolSpec(
        name="recon_ng",
        executable="recon-ng",
        env_var="RECON_NG_CMD",
        args=("-r", "{target}"),
        description="Framework Recon-ng locale; richiede setup moduli prima dell'uso automatico.",
    ),
    "amass": ToolSpec(
        name="amass",
        executable="amass",
        env_var="AMASS_CMD",
        args=("enum", "-passive", "-d", "{target}"),
        description="Mappatura passiva attack surface e sottodomini autorizzati.",
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        executable="subfinder",
        env_var="SUBFINDER_CMD",
        args=("-silent", "-d", "{target}"),
        description="Enumerazione passiva sottodomini su domini autorizzati.",
    ),
    "waybackurls": ToolSpec(
        name="waybackurls",
        executable="waybackurls",
        env_var="WAYBACKURLS_CMD",
        args=("{target}",),
        description="URL storici pubblici da archivi web per dominio autorizzato.",
    ),
    "gau": ToolSpec(
        name="gau",
        executable="gau",
        env_var="GAU_CMD",
        args=("{target}",),
        description="Raccolta URL pubblici archiviati per dominio autorizzato.",
    ),
    "gitleaks": ToolSpec(
        name="gitleaks",
        executable="gitleaks",
        env_var="GITLEAKS_CMD",
        args=("detect", "--source", "{target}", "--no-banner", "--redact"),
        description="Ricerca segreti in repository/file locali autorizzati.",
    ),
    "singlefile": ToolSpec(
        name="singlefile",
        executable="single-file",
        env_var="SINGLEFILE_CMD",
        args=("{target}", "--dump-content"),
        description="Archiviazione di URL pubblici tramite SingleFile CLI.",
    ),
    "shodan": ToolSpec(
        name="shodan",
        executable="shodan",
        env_var="SHODAN_CMD",
        args=("host", "{target}"),
        description="Lookup passivo Shodan su IP/domini autorizzati; richiede API key configurata.",
    ),
    "censys": ToolSpec(
        name="censys",
        executable="censys",
        env_var="CENSYS_CMD",
        args=("search", "{target}"),
        description="Lookup passivo Censys; richiede API ID/secret configurati.",
    ),
    "exiftool": ToolSpec(
        name="exiftool",
        executable="exiftool",
        env_var="EXIFTOOL_CMD",
        args=("-json", "{target}"),
        description="Estrazione metadati da file media locali, se installato.",
    ),
    "ffprobe": ToolSpec(
        name="ffprobe",
        executable="ffprobe",
        env_var="FFPROBE_CMD",
        args=("-v", "error", "-show_format", "-show_streams", "-of", "json", "{target}"),
        description="Metadati tecnici audio/video da file locali, se installato.",
    ),
    # Reverse-account discovery (Fase 3). Email → social registrations.
    "mosint": ToolSpec(
        name="mosint",
        executable="mosint",
        env_var="MOSINT_CMD",
        args=("{target}",),
        description="Email OSINT aggregator: domini, breach, social. Richiede config delle API keys interne.",
    ),
    "infoga": ToolSpec(
        name="infoga",
        executable="infoga",
        env_var="INFOGA_CMD",
        args=("--domain", "{target}"),
        description="Email enumeration su un dominio autorizzato (passive sources).",
    ),
    # Phone → carrier / location / social
    "phunter": ToolSpec(
        name="phunter",
        executable="phunter",
        env_var="PHUNTER_CMD",
        args=("-t", "{target}"),
        description="Phone OSINT: operatore, paese, possibili social legati al numero.",
    ),
    # Red team augment
    "subjack": ToolSpec(
        name="subjack",
        executable="subjack",
        env_var="SUBJACK_CMD",
        args=("-d", "{target}", "-ssl", "-v"),
        description="Subdomain-takeover detector su un dominio autorizzato.",
    ),
    "trufflehog": ToolSpec(
        name="trufflehog",
        executable="trufflehog",
        env_var="TRUFFLEHOG_CMD",
        args=("filesystem", "{target}", "--no-update", "--json"),
        description="Secret scanner su path locale autorizzato.",
    ),
    "cloud_enum": ToolSpec(
        name="cloud_enum",
        executable="cloud_enum",
        env_var="CLOUD_ENUM_CMD",
        args=("-k", "{target}"),
        description="Discovery di bucket S3/Azure/GCS pubblici per una keyword.",
    ),
    # --- Fase 4: expanded red team / EASM tools ---
    "nuclei": ToolSpec(
        name="nuclei",
        executable="nuclei",
        env_var="NUCLEI_CMD",
        args=("-u", "{target}", "-severity", "medium,high,critical", "-silent", "-json"),
        description="Nuclei: scanner di vulnerabilità e misconfigurazioni con template pubblici.",
    ),
    "httpx": ToolSpec(
        name="httpx",
        executable="httpx",
        env_var="HTTPX_CMD",
        args=("-u", "{target}", "-title", "-tech-detect", "-status-code", "-silent", "-json"),
        description="httpx: fingerprinting HTTP rapido (titolo, tech stack, status). Pillar 2 EASM.",
    ),
    "naabu": ToolSpec(
        name="naabu",
        executable="naabu",
        env_var="NAABU_CMD",
        args=("-host", "{target}", "-top-ports", "100", "-silent", "-json"),
        description="naabu: port scanner veloce su asset autorizzati.",
    ),
    "dnsx": ToolSpec(
        name="dnsx",
        executable="dnsx",
        env_var="DNSX_CMD",
        args=("-d", "{target}", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-silent", "-json"),
        description="dnsx: risoluzione DNS massiva e record discovery.",
    ),
    "katana": ToolSpec(
        name="katana",
        executable="katana",
        env_var="KATANA_CMD",
        args=("-u", "{target}", "-silent", "-d", "3", "-jc"),
        description="katana: web crawler con JavaScript analysis per endpoint discovery.",
    ),
    "feroxbuster": ToolSpec(
        name="feroxbuster",
        executable="feroxbuster",
        env_var="FEROXBUSTER_CMD",
        args=("-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-s", "200,301,302,403", "--silent", "--json"),
        description="feroxbuster: fuzzing path web su target autorizzati.",
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        executable="ffuf",
        env_var="FFUF_CMD",
        args=("-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302", "-of", "json"),
        description="ffuf: web fuzzer per path/endpoint discovery su target autorizzati.",
    ),
    "dalfox": ToolSpec(
        name="dalfox",
        executable="dalfox",
        env_var="DALFOX_CMD",
        args=("url", "{target}", "--skip-bav", "--silence"),
        description="dalfox: XSS scanner passivo/attivo su target autorizzati.",
    ),
    "dnstwist": ToolSpec(
        name="dnstwist",
        executable="dnstwist",
        env_var="DNSTWIST_CMD",
        args=("--format", "json", "{target}"),
        description="dnstwist: generazione e verifica typosquat per brand protection.",
    ),
    "whatweb": ToolSpec(
        name="whatweb",
        executable="whatweb",
        env_var="WHATWEB_CMD",
        args=("-a", "3", "--log-json", "/dev/stdout", "{target}"),
        description="whatweb: tech fingerprinting web su target autorizzati.",
    ),
    "nikto": ToolSpec(
        name="nikto",
        executable="nikto",
        env_var="NIKTO_CMD",
        args=("-h", "{target}", "-Format", "json", "-o", "/dev/stdout"),
        description="nikto: web server vulnerability scanner su target autorizzati.",
    ),
    "wpscan": ToolSpec(
        name="wpscan",
        executable="wpscan",
        env_var="WPSCAN_CMD",
        args=("--url", "{target}", "--format", "json", "--no-banner"),
        description="wpscan: WordPress vulnerability scanner su target autorizzati.",
    ),
    "masscan": ToolSpec(
        name="masscan",
        executable="masscan",
        env_var="MASSCAN_CMD",
        args=("-p", "80,443,8080,8443,22,21,25,3389", "{target}", "--rate", "1000", "-oJ", "-"),
        description="masscan: port scan massiccio su reti di propria competenza (alta velocità).",
    ),
    "testssl": ToolSpec(
        name="testssl",
        executable="testssl.sh",
        env_var="TESTSSL_CMD",
        args=("--json", "{target}"),
        description="testssl.sh: analisi completa configurazione TLS/SSL su target autorizzati.",
    ),
    "dirsearch": ToolSpec(
        name="dirsearch",
        executable="dirsearch",
        env_var="DIRSEARCH_CMD",
        args=("-u", "{target}", "--format", "json", "-q"),
        description="dirsearch: directory e file brute-force su web server autorizzati.",
    ),
    "arjun": ToolSpec(
        name="arjun",
        executable="arjun",
        env_var="ARJUN_CMD",
        args=("-u", "{target}", "--stable", "-oJ", "/dev/stdout"),
        description="arjun: HTTP parameter discovery su endpoint autorizzati.",
    ),
    "eyewitness": ToolSpec(
        name="eyewitness",
        executable="eyewitness",
        env_var="EYEWITNESS_CMD",
        args=("-f", "{target}", "--no-prompt", "--web"),
        description="eyewitness: screenshot web e report visuale di host autorizzati.",
    ),
    "gitdumper": ToolSpec(
        name="gitdumper",
        executable="git-dumper",
        env_var="GITDUMPER_CMD",
        args=("{target}/.git", "/tmp/gitdump"),
        description="git-dumper: estrazione repository git esposti su server autorizzati.",
    ),
    "linkfinder": ToolSpec(
        name="linkfinder",
        executable="linkfinder",
        env_var="LINKFINDER_CMD",
        args=("-i", "{target}", "-o", "cli"),
        description="linkfinder: endpoint e URL discovery da file JavaScript.",
    ),
    "secretfinder": ToolSpec(
        name="secretfinder",
        executable="secretfinder",
        env_var="SECRETFINDER_CMD",
        args=("-i", "{target}", "-o", "cli"),
        description="secretfinder: API key e secret discovery da file JavaScript/HTML.",
    ),
    "gospider": ToolSpec(
        name="gospider",
        executable="gospider",
        env_var="GOSPIDER_CMD",
        args=("-s", "{target}", "-c", "5", "--json"),
        description="gospider: web crawler veloce per link e asset discovery.",
    ),
    "hakrawler": ToolSpec(
        name="hakrawler",
        executable="hakrawler",
        env_var="HAKRAWLER_CMD",
        args=("{target}",),
        description="hakrawler: URL e endpoint discovery via crawling e JavaScript parsing.",
    ),
    "wafw00f": ToolSpec(
        name="wafw00f",
        executable="wafw00f",
        env_var="WAFW00F_CMD",
        args=("{target}", "-o", "-"),
        description="wafw00f: WAF fingerprinting su target autorizzati.",
    ),
    "fierce": ToolSpec(
        name="fierce",
        executable="fierce",
        env_var="FIERCE_CMD",
        args=("--domain", "{target}"),
        description="fierce: DNS enumeration e zone transfer check su domini autorizzati.",
    ),
    "dnsenum": ToolSpec(
        name="dnsenum",
        executable="dnsenum",
        env_var="DNSENUM_CMD",
        args=("--noreverse", "{target}"),
        description="dnsenum: enumerazione DNS completa su domini autorizzati.",
    ),
    "enum4linux": ToolSpec(
        name="enum4linux",
        executable="enum4linux",
        env_var="ENUM4LINUX_CMD",
        args=("-a", "{target}"),
        description="enum4linux: SMB/Windows share enumeration su host autorizzati.",
    ),
    "smbmap": ToolSpec(
        name="smbmap",
        executable="smbmap",
        env_var="SMBMAP_CMD",
        args=("-H", "{target}"),
        description="smbmap: SMB share listing su host autorizzati.",
    ),
    "snmpwalk": ToolSpec(
        name="snmpwalk",
        executable="snmpwalk",
        env_var="SNMPWALK_CMD",
        args=("-v2c", "-c", "public", "{target}"),
        description="snmpwalk: SNMP OID walk su dispositivi autorizzati con community 'public'.",
    ),
    "metagoofil": ToolSpec(
        name="metagoofil",
        executable="metagoofil",
        env_var="METAGOOFIL_CMD",
        args=("-d", "{target}", "-t", "pdf,doc,docx,xls,xlsx,ppt,pptx", "-n", "10"),
        description="metagoofil: metadata extraction da documenti pubblici correlati al dominio.",
    ),
    # ---------- People-search / social aggregation (v3) ----------
    "blackbird": ToolSpec(
        name="blackbird",
        executable="blackbird",
        env_var="BLACKBIRD_CMD",
        args=("--username", "{target}"),
        description="blackbird: ricerca username su 600+ siti pubblici (people-search context).",
    ),
    "instaloader": ToolSpec(
        name="instaloader",
        executable="instaloader",
        env_var="INSTALOADER_CMD",
        args=("--no-pictures", "--no-videos", "--no-metadata-json", "{target}"),
        description="instaloader: metadata di profili Instagram pubblici (no scrape massivo).",
    ),
    "snscrape": ToolSpec(
        name="snscrape",
        executable="snscrape",
        env_var="SNSCRAPE_CMD",
        args=("--jsonl", "--max-results", "20", "twitter-user", "{target}"),
        description="snscrape: scrape multi-piattaforma (X/Twitter, Reddit, Mastodon).",
    ),
    "yt_dlp": ToolSpec(
        name="yt_dlp",
        executable="yt-dlp",
        env_var="YT_DLP_CMD",
        args=("--dump-json", "--no-download", "{target}"),
        description="yt-dlp: estrae solo metadata pubblici di video (no download di file).",
    ),
}


def available_tools() -> list[str]:
    return sorted(TOOL_SPECS)


def run_tool(name: str, target: str, timeout: int, target_type: str = "",
             *, case_id: str | None = None, actor: str = "",
             storage=None) -> ToolRun:
    spec = TOOL_SPECS[name]
    try:
        # Always validate; target_type="" skips per-type charset checks but
        # still rejects leading dashes and control characters.
        safe_target = validate_tool_target(target, target_type)
    except SafetyError as exc:
        return ToolRun(
            name=name,
            status="skipped",
            command=[spec.executable],
            stderr=str(exc),
        )
    # Pillar 0.2: hard RoE gate before we even resolve the command. The gate
    # is no-op when case_id is falsy (legacy CLI flow).
    if case_id:
        try:
            authorize_action(
                action_class=action_class_for_tool(name),
                target_type=target_type or "company",
                target=safe_target,
                case_id=case_id,
                actor=actor,
                storage=storage,
            )
        except SafetyError as exc:
            return ToolRun(
                name=name,
                status="denied",
                command=[spec.executable],
                stderr=str(exc),
            )
    resolved = resolve_command(name, spec, safe_target)
    if not resolved:
        repo_name = REPO_TOOL_NAMES.get(name)
        if repo_name and (PROJECT_ROOT / "tools" / "repos" / repo_name).exists():
            return ToolRun(
                name=name,
                status="manual_setup",
                command=[spec.executable],
                stderr=(
                    f"Repository {repo_name} presente in tools/repos, ma {spec.executable} non e configurato come comando automatico. "
                    f"Configura {spec.env_var} dopo setup/API lecite."
                ),
            )
        return ToolRun(
            name=name,
            status="missing",
            command=[spec.executable],
            stderr=f"{spec.executable} non trovato. Configura {spec.env_var} o installalo nel PATH.",
        )

    effective_timeout = max(timeout, 60) if name in {"sherlock", "maigret", "social_analyzer", "h8mail", "ghunt", "toutatis"} else timeout
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("NO_COLOR", "1")
    env.setdefault("TERM", "dumb")
    # Isolate the child in its own process group so that tools which fork
    # subprocesses (spiderfoot, recon-ng, nmap NSE, etc.) can be terminated
    # as a group on timeout instead of leaving orphans behind.
    popen_kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": str(resolved.cwd) if resolved.cwd else None,
        "env": env,
    }
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True
    else:
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(resolved.command, **popen_kwargs)
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout_bytes, stderr_bytes = exc.stdout or b"", exc.stderr or b""
        return ToolRun(
            name=name,
            status="timeout",
            command=resolved.command,
            stdout=_decode_capture(stdout_bytes)[:4000],
            stderr=_decode_capture(stderr_bytes)[:4000],
        )

    stdout_text = _decode_capture(stdout_bytes)
    stderr_text = _decode_capture(stderr_bytes)
    status = "ok" if process.returncode == 0 else "error"
    return ToolRun(
        name=name,
        status=status,
        command=resolved.command,
        stdout=stdout_text[:8000],
        stderr=stderr_text[:4000],
        return_code=process.returncode,
    )


def _decode_capture(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8", errors="replace")
    except AttributeError:
        return str(data)


def _terminate_process_group(process: subprocess.Popen) -> None:
    """Kill the whole process group spawned by *process*, then the process.

    On POSIX, the child started its own session (start_new_session=True), so
    its PID is the process-group leader and os.killpg targets all descendants.
    On Windows we fall back to taskkill /T to walk the process tree.
    """
    if os.name == "posix":
        import signal as _signal

        try:
            os.killpg(process.pid, _signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
    else:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            try:
                process.kill()
            except OSError:
                pass


def resolve_command(name: str, spec: ToolSpec, target: str) -> ResolvedCommand | None:
    args: list[str] = []
    inject_terminator = name in TOOLS_WITH_OPTION_TERMINATOR
    target_placeholder = "{target}"
    for part in spec.args:
        if inject_terminator and part == target_placeholder:
            args.append("--")
        args.append(part.format(target=target))
    configured = os.getenv(spec.env_var)
    if configured:
        return ResolvedCommand([configured, *args])

    executable = shutil.which(spec.executable)
    if executable:
        return ResolvedCommand([executable, *args])

    local_bin = PROJECT_ROOT / "tools" / "bin"
    for suffix in (".exe", ".cmd", ""):
        candidate = local_bin / f"{spec.executable}{suffix}"
        if candidate.exists():
            return ResolvedCommand([str(candidate), *args])

    node_bin = PROJECT_ROOT / "tools" / "node-tools" / "node_modules" / ".bin"
    for suffix in (".cmd", ".exe", ""):
        candidate = node_bin / f"{spec.executable}{suffix}"
        if candidate.exists():
            return ResolvedCommand([str(candidate), *args])

    scripts_dir = Path(sys.executable).resolve().parent / "Scripts"
    exe_candidate = scripts_dir / f"{spec.executable}.exe"
    if exe_candidate.exists():
        return ResolvedCommand([str(exe_candidate), *args])
    script_candidate = scripts_dir / spec.executable
    if script_candidate.exists():
        return ResolvedCommand([sys.executable, str(script_candidate), *args])

    if name == "sherlock":
        repo = PROJECT_ROOT / "tools" / "repos" / "sherlock"
        if (repo / "sherlock_project" / "__main__.py").exists():
            return ResolvedCommand([sys.executable, "-m", "sherlock_project", *args], cwd=repo)

    return None


# ---------------------------------------------------------------------------
# Health-check con cache TTL — usato dal frontend per i pallini verde/rosso
# ---------------------------------------------------------------------------
import time as _time

_TOOL_HEALTH_CACHE: dict[str, tuple[float, dict]] = {}
_TOOL_HEALTH_TTL_SECONDS = 30


def tool_health_status(name: str, spec: ToolSpec | None = None) -> dict:
    """Return real-time availability for a tool.

    Returns:
        {"name": str, "available": bool, "path": str | None,
         "reason": str, "checked_at": iso_ts}

    Uses a 30-second cache to avoid hammering shutil.which / filesystem.
    """
    cached = _TOOL_HEALTH_CACHE.get(name)
    now = _time.time()
    if cached and now - cached[0] < _TOOL_HEALTH_TTL_SECONDS:
        return cached[1]

    if spec is None:
        spec = TOOL_SPECS.get(name)
    if spec is None:
        result = {
            "name": name,
            "available": False,
            "path": None,
            "reason": "Tool non registrato.",
            "checked_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        }
        _TOOL_HEALTH_CACHE[name] = (now, result)
        return result

    cmd = resolve_command(name, spec, "healthcheck.example")
    if cmd is None:
        reason = (
            f"Eseguibile '{spec.executable}' non trovato in PATH, "
            f"env var ${spec.env_var} non impostata, "
            f"e nessuna copia in tools/bin/ o tools/repos/."
        )
        result = {
            "name": name,
            "available": False,
            "path": None,
            "reason": reason,
            "checked_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        }
    else:
        exe_path = cmd.command[0] if cmd.command else ""
        # Sanity: il file (o env var path) deve esistere
        exists = Path(exe_path).exists() if exe_path else False
        result = {
            "name": name,
            "available": exists,
            "path": exe_path,
            "reason": "ok" if exists else f"Path '{exe_path}' non esiste.",
            "checked_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        }

    _TOOL_HEALTH_CACHE[name] = (now, result)
    return result


def all_tools_health() -> list[dict]:
    """Return health status for every registered tool. Cached per-tool."""
    return [tool_health_status(name, spec) for name, spec in sorted(TOOL_SPECS.items())]


def clear_health_cache() -> None:
    """Force refresh of all health entries on next call."""
    _TOOL_HEALTH_CACHE.clear()
