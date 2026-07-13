from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Protocol

from .custody import command_hash as _cmd_hash
from .custody import save_artifact
from .external_tools import TOOL_SPECS, ToolRun, run_tool
from .models import Evidence, Finding, Provenance
from .safety import SafetyError, assert_external_tool_allowed, redact_email, redact_phone


def _lazy_storage():
    """Return the web-layer Storage if it's already initialised, else None.

    Avoids a hard import cycle between plugins and web. Tests can monkey-patch
    osint_bot.web.STORAGE directly.
    """
    try:
        from . import web as _web
        return _web.STORAGE
    except Exception:
        return None


# Per-tool found-line patterns. For URL-producing tools, group 1 is the URL.
# For holehe, group 1 is the domain name (holehe prints domains, not full URLs).
# Lines that don't match are silently ignored so banners and "[-] not found"
# output never leak into the report as false profiles.
_FOUND_LINE_PATTERNS: dict[str, re.Pattern[str]] = {
    "sherlock": re.compile(r"^\s*\[\+\]\s+\S.*?:\s+(https?://\S+)", re.MULTILINE),
    "maigret": re.compile(r"^\s*\[\+\]\s+\S.*?:\s+(https?://\S+)", re.MULTILINE),
    # holehe prints "[+] twitter.com : email used" — extract the domain name.
    # With --only-used the [-] lines are suppressed at source; the regex adds a
    # second safety layer so stray negative lines are never promoted to findings.
    "holehe": re.compile(r"^\s*\[\+\]\s+([\w.-]+\.[a-z]{2,})\s*:", re.MULTILINE | re.IGNORECASE),
    "social_analyzer": re.compile(
        r"(?:found|profile|url)[^\n]*?(https?://\S+)", re.IGNORECASE | re.MULTILINE
    ),
    "toutatis": re.compile(r"https?://(?:www\.)?instagram\.com/\S+", re.IGNORECASE),
    "osintgram": re.compile(r"https?://(?:www\.)?instagram\.com/\S+", re.IGNORECASE),
}


@dataclass(frozen=True)
class PluginContext:
    target: str
    target_type: str
    confirm_authorization: bool
    include_contact: bool
    allow_network_scan: bool
    timeout: int
    source_route: str = "standard"
    # Pillar 0.2: RoE context. When set, external tool runs pass through the
    # RoE gate (authorize_action). Empty/None is the legacy CLI behavior.
    case_id: str | None = None
    actor: str = ""


@dataclass
class PluginResult:
    plugin: str
    status: str
    started_at: float
    finished_at: float
    findings: list[Finding] = field(default_factory=list)
    output: dict = field(default_factory=dict)
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["duration_ms"] = self.duration_ms
        return data


class OsintPlugin(Protocol):
    name: str
    passive: bool
    gated: bool

    def run(self, context: PluginContext) -> PluginResult:
        ...


class ExternalToolPlugin:
    passive = True
    gated = True

    def __init__(self, name: str):
        self.name = name

    def run(self, context: PluginContext) -> PluginResult:
        started = time.time()
        try:
            assert_external_tool_allowed(
                self.name,
                context.target_type,
                context.confirm_authorization,
                context.allow_network_scan,
            )
            storage = _lazy_storage()
            tool_run = run_tool(
                self.name, context.target, context.timeout,
                target_type=context.target_type,
                case_id=context.case_id,
                actor=context.actor,
                storage=storage,
            )
            # Pillar 0.3: record tool stdout as an artifact when we have a case.
            if tool_run.status == "ok" and tool_run.stdout and context.case_id:
                save_artifact(
                    artifact_type="tool_output",
                    content=tool_run.stdout,
                    job_id="",
                    case_id=context.case_id,
                    tool_name=self.name,
                    argv=tool_run.command,
                    actor=context.actor or "system",
                    storage=storage,
                )
            findings = findings_from_tool_run(tool_run, context)
            return PluginResult(
                plugin=self.name,
                status=tool_run.status,
                started_at=started,
                finished_at=time.time(),
                findings=findings,
                output={
                    "command": redacted_command(tool_run.command),
                    "return_code": tool_run.return_code,
                    "stdout": tool_run.stdout[:2000],
                    "stderr": tool_run.stderr[:1200],
                },
                error=tool_run.stderr if tool_run.status in {"error", "timeout", "missing", "manual_setup"} else "",
            )
        except SafetyError as exc:
            return PluginResult(
                plugin=self.name,
                status="skipped",
                started_at=started,
                finished_at=time.time(),
                error=str(exc),
            )
        except Exception as exc:
            return PluginResult(
                plugin=self.name,
                status="error",
                started_at=started,
                finished_at=time.time(),
                error=str(exc),
            )


class PluginRegistry:
    def __init__(self):
        self._plugins: dict[str, OsintPlugin] = {}

    def register(self, plugin: OsintPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> OsintPlugin:
        if name not in self._plugins:
            raise KeyError(f"Plugin non registrato: {name}")
        return self._plugins[name]

    def names(self) -> list[str]:
        return sorted(self._plugins)


def default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    for name in TOOL_SPECS:
        registry.register(ExternalToolPlugin(name))
    return registry


def run_plugins_parallel(
    plugin_names: list[str],
    context: PluginContext,
    *,
    registry: PluginRegistry | None = None,
    max_workers: int = 4,
) -> list[PluginResult]:
    if not plugin_names:
        return []
    active_registry = registry or default_registry()
    workers = max(1, min(max_workers, len(plugin_names)))
    results: list[PluginResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {}
        for name in plugin_names:
            try:
                plugin = active_registry.get(name)
            except KeyError as exc:
                now = time.time()
                results.append(PluginResult(plugin=name, status="missing", started_at=now, finished_at=now, error=str(exc)))
                continue
            future_map[executor.submit(plugin.run, context)] = name
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                now = time.time()
                results.append(PluginResult(plugin=name, status="error", started_at=now, finished_at=now, error=str(exc)))
    return sorted(results, key=lambda item: item.plugin)


def findings_from_tool_run(tool_run: ToolRun, context: PluginContext) -> list[Finding]:
    if tool_run.status != "ok" or not tool_run.stdout or not external_output_has_signal(tool_run.name, tool_run.stdout):
        return []
    # Pillar 0.3: provenance stamped when a case is attached.
    prov = (
        Provenance(
            tool=tool_run.name,
            collected_at=_collected_at_iso(),
            actor=context.actor or "system",
            case_id=context.case_id or "",
            command_hash=_cmd_hash(tool_run.command) if tool_run.command else "",
        )
        if context.case_id
        else None
    )
    profile_findings = external_profile_findings(tool_run.name, tool_run.stdout)
    if profile_findings:
        return [_stamp_provenance(f, prov) for f in profile_findings]
    safe_value = redact_if_needed(context.target, context.target_type, context.include_contact)
    return [
        Finding(
            kind=f"external_{tool_run.name}",
            value=safe_value,
            confidence=0.45,
            evidence=[Evidence(url=f"tool://{tool_run.name}", title=tool_run.name, quote=one_line(tool_run.stdout[:700]))],
            notes="Output modulo esterno: verificare manualmente prima di usare in un report.",
            provenance=prov,
        )
    ]


def _stamp_provenance(finding: Finding, prov: Provenance | None) -> Finding:
    if prov is None:
        return finding
    from dataclasses import replace
    return replace(finding, provenance=prov)


def _collected_at_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_DOMAIN_ONLY_TOOLS = {"holehe"}


def external_profile_findings(tool_name: str, stdout: str) -> list[Finding]:
    pattern = _FOUND_LINE_PATTERNS.get(tool_name)
    if not pattern:
        return []
    values: list[str] = []
    for match in pattern.finditer(stdout):
        value = match.group(1) if match.lastindex else match.group(0)
        value = value.rstrip(".,;)]}'\"")
        if value not in values:
            values.append(value)
        if len(values) >= 25:
            break
    is_domain_tool = tool_name in _DOMAIN_ONLY_TOOLS
    return [
        Finding(
            kind=f"external_{tool_name}_registration" if is_domain_tool else f"external_{tool_name}_profile",
            value=value,
            confidence=0.60 if is_domain_tool else 0.55,
            evidence=[Evidence(url=f"tool://{tool_name}", title=tool_name, quote=value)],
            notes=(
                f"Email registrata su {value} (rilevato da holehe); verificare che l'account sia effettivamente attivo."
                if is_domain_tool else
                "Profilo pubblico candidato trovato da modulo esterno; attribuzione da verificare manualmente."
            ),
        )
        for value in values
    ]


def external_output_has_signal(tool_name: str, stdout: str) -> bool:
    lowered = stdout.casefold()
    if tool_name == "h8mail" and ("no results found" in lowered or "not compromised" in lowered):
        return False
    return True


def redact_if_needed(target: str, target_type: str, include_contact: bool) -> str:
    if target_type == "email" and not include_contact:
        return redact_email(target)
    if target_type == "phone":
        return redact_phone(target)
    return target


SECRET_FLAGS = {
    "--api-key",
    "--apikey",
    "--api_key",
    "--key",
    "--token",
    "--auth-token",
    "--access-token",
    "--bearer",
    "--password",
    "--passwd",
    "--secret",
    "--client-secret",
    "-k",
    "-p",
}
SECRET_FLAG_PREFIXES = ("--api-key=", "--apikey=", "--token=", "--password=", "--secret=", "--key=")


def redacted_command(command: list[str]) -> list[str]:
    """Mask values that follow known secret-bearing CLI flags before persisting.

    Tools in this project pass API keys via environment variables, but a future
    tool spec — or a user-configured wrapper — could put a secret inline on argv.
    Persisting that to the report JSON would leak it. Mask the value that
    follows a known secret flag, plus inline forms like --api-key=XYZ.
    """
    redacted: list[str] = []
    skip_next = False
    for part in command:
        if skip_next:
            redacted.append("***")
            skip_next = False
            continue
        if part in SECRET_FLAGS:
            redacted.append(part)
            skip_next = True
            continue
        masked_inline = part
        for prefix in SECRET_FLAG_PREFIXES:
            if part.startswith(prefix):
                masked_inline = f"{prefix}***"
                break
        if len(masked_inline) >= 120:
            masked_inline = f"{masked_inline[:117]}..."
        redacted.append(masked_inline)
    return redacted


def one_line(value: str) -> str:
    return " ".join(value.split())[:1200]
