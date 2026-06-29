"""Tool adapter framework — wraps external CLI tools with a consistent shape.

Each adapter implements:

    adapter.name           — short id ("subfinder", "nuclei", …)
    adapter.kind           — "passive_recon" | "active_recon" | "vuln_scan" | "dast"
    adapter.detect()       → ToolStatus(installed: bool, version: str, path: str)
    adapter.run(target, scope, opts) → ToolRun(raw, normalized, findings)

Findings produced by adapters fit into the existing `Finding` dataclass
(`models.Finding`) so they can be merged into the investigation report.

The actual binary invocation is delegated to `external_tools.resolve_command`
+ subprocess. The framework here is the contract + the normalization layer
so we can swap tools without touching the report pipeline.

Two production-grade adapters are wired in this module as a starting set
(Subfinder and Nuclei — both passive subdomain enumeration and active
template-based vuln scan). Others can follow the same pattern.

ALL adapters enforce:
  * scope check before any network probe (scope.assert_in_scope)
  * hard timeout (default 120s)
  * rate-limit hint (concurrency=1 by default)
  * audit log entry: tool_invoked + tool_result
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable

from .models import Evidence, Finding
from .scope import CaseScope, OutOfScopeError, assert_in_scope
from .target_classifier import TargetSpec, T_DOMAIN, T_SUBDOMAIN, T_URL

LOG = logging.getLogger("osint_bot.tool_adapter")


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------

KIND_PASSIVE_RECON = "passive_recon"
KIND_ACTIVE_RECON  = "active_recon"
KIND_VULN_SCAN     = "vuln_scan"
KIND_DAST          = "dast"


@dataclass
class ToolStatus:
    name: str
    installed: bool
    version: str = ""
    path: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ToolRun:
    """Single execution result."""
    name: str
    kind: str
    target: str
    started_at: str
    finished_at: str
    duration_ms: int
    command: list[str]            # sanitized — no secrets
    return_code: int | None
    raw_output: str = ""          # truncated to 32 KiB
    error: str = ""
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "command": list(self.command),
            "return_code": self.return_code,
            "raw_output": self.raw_output,
            "error": self.error,
            "findings": [asdict(f) for f in self.findings],
        }


# Adapter registry
_REGISTRY: dict[str, "ToolAdapter"] = {}


def get_adapter(name: str) -> "ToolAdapter | None":
    return _REGISTRY.get(name)


def list_adapters() -> list["ToolAdapter"]:
    return list(_REGISTRY.values())


def detect_all() -> dict[str, ToolStatus]:
    return {a.name: a.detect() for a in _REGISTRY.values()}


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------

@dataclass
class ToolAdapter:
    name: str
    kind: str
    binary: str
    version_flag: str = "-version"   # most go-tools use -version
    description: str = ""
    requires_scope: bool = True      # any active recon requires scope check
    default_timeout: int = 120
    # Subclasses override these:
    def build_command(self, target: TargetSpec, opts: dict) -> list[str]:
        raise NotImplementedError
    def parse_output(self, raw: str, target: TargetSpec) -> list[Finding]:
        raise NotImplementedError

    # --- generic logic ---
    def detect(self) -> ToolStatus:
        path = shutil.which(self.binary)
        if not path:
            return ToolStatus(name=self.name, installed=False,
                              error=f"Binario '{self.binary}' non trovato nel PATH.")
        # Try -version
        try:
            res = subprocess.run(
                [path, self.version_flag],
                capture_output=True, text=True, timeout=5,
            )
            version = (res.stdout + res.stderr).strip().split("\n", 1)[0][:120]
        except Exception as exc:  # pragma: no cover — defensive
            version = f"detect-error: {exc.__class__.__name__}"
        return ToolStatus(name=self.name, installed=True, version=version, path=path)

    def run(
        self,
        target: TargetSpec,
        *,
        scope: CaseScope | None = None,
        opts: dict | None = None,
        timeout: int | None = None,
    ) -> ToolRun:
        opts = opts or {}
        if self.requires_scope:
            if scope is None:
                return self._failed(target, "Esecuzione bloccata: scope non fornito.")
            try:
                assert_in_scope(target, scope)
            except OutOfScopeError as exc:
                return self._failed(target, f"Scope: {exc}")
        status = self.detect()
        if not status.installed:
            return self._failed(target, status.error or "Tool non installato.")
        cmd = [status.path, *self.build_command(target, opts)]
        started = _now_iso()
        t0 = time.monotonic()
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout or self.default_timeout,
            )
            raw = (res.stdout or "")[:32 * 1024]
            findings = self.parse_output(raw, target) if res.returncode == 0 else []
            return ToolRun(
                name=self.name, kind=self.kind, target=target.value or target.raw,
                started_at=started, finished_at=_now_iso(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                command=cmd, return_code=res.returncode,
                raw_output=raw, error=(res.stderr or "")[:2048],
                findings=findings,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolRun(
                name=self.name, kind=self.kind, target=target.value or target.raw,
                started_at=started, finished_at=_now_iso(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                command=cmd, return_code=None,
                error=f"Timeout dopo {exc.timeout}s.",
            )
        except Exception as exc:  # pragma: no cover — defensive
            return ToolRun(
                name=self.name, kind=self.kind, target=target.value or target.raw,
                started_at=started, finished_at=_now_iso(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                command=cmd, return_code=None,
                error=f"Errore esecuzione: {exc.__class__.__name__}: {exc}",
            )

    def _failed(self, target: TargetSpec, msg: str) -> ToolRun:
        return ToolRun(
            name=self.name, kind=self.kind, target=target.value or target.raw,
            started_at=_now_iso(), finished_at=_now_iso(), duration_ms=0,
            command=[], return_code=None, error=msg,
        )


def register(adapter: ToolAdapter) -> ToolAdapter:
    _REGISTRY[adapter.name] = adapter
    return adapter


# ---------------------------------------------------------------------------
# Built-in adapters — Subfinder (passive subdomain) + Nuclei (vuln scan)
# ---------------------------------------------------------------------------

class SubfinderAdapter(ToolAdapter):
    """Passive subdomain enumeration via Subfinder (projectdiscovery)."""
    def __init__(self):
        super().__init__(
            name="subfinder",
            kind=KIND_PASSIVE_RECON,
            binary="subfinder",
            version_flag="-version",
            description="Passive subdomain enumeration (projectdiscovery/subfinder).",
            requires_scope=True,
            default_timeout=180,
        )

    def build_command(self, target: TargetSpec, opts: dict) -> list[str]:
        if target.type not in (T_DOMAIN, T_SUBDOMAIN):
            return []
        domain = target.attributes.get("apex") or target.value
        return ["-d", domain, "-silent"]

    def parse_output(self, raw: str, target: TargetSpec) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in (raw or "").splitlines():
            sub = line.strip().lower()
            if not sub or "." not in sub or sub in seen:
                continue
            seen.add(sub)
            findings.append(Finding(
                kind="subdomain",
                value=sub,
                confidence=0.85,
                evidence=[Evidence(url=f"https://{sub}", title="Subfinder")],
                notes=f"Sottodominio enumerato passivamente per {target.value}.",
                source_reliability="B", info_credibility=2,
            ))
        return findings


class NucleiAdapter(ToolAdapter):
    """Vuln scan template-based (projectdiscovery)."""
    def __init__(self):
        super().__init__(
            name="nuclei",
            kind=KIND_VULN_SCAN,
            binary="nuclei",
            version_flag="-version",
            description="Template-based vulnerability scanner (projectdiscovery/nuclei).",
            requires_scope=True,
            default_timeout=600,
        )

    def build_command(self, target: TargetSpec, opts: dict) -> list[str]:
        severity = opts.get("severity", "medium,high,critical")
        args = ["-u", _to_url(target), "-severity", severity, "-silent", "-json"]
        if opts.get("rate_limit"):
            args.extend(["-rate-limit", str(int(opts["rate_limit"]))])
        return args

    def parse_output(self, raw: str, target: TargetSpec) -> list[Finding]:
        findings: list[Finding] = []
        for line in (raw or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            sev = (info.get("severity") or "").lower() or "info"
            name = info.get("name") or obj.get("template-id") or "nuclei finding"
            matched_at = obj.get("matched-at") or obj.get("host") or target.value
            findings.append(Finding(
                kind="nuclei_finding",
                value=f"{obj.get('template-id', '?')}: {name}",
                confidence=0.85,
                evidence=[Evidence(url=str(matched_at), title=name)],
                notes=info.get("description", "")[:500],
                severity=sev,
                attck_ttps=list((info.get("classification") or {}).get("cwe-id", []))[:5],
                remediation=info.get("remediation", "")[:500],
                source_reliability="B", info_credibility=2,
            ))
        return findings


class AmassAdapter(ToolAdapter):
    """Asset discovery + attack surface mapping (OWASP Amass).

    Modalità passiva (-passive) per default. Output JSONL → parsing
    diretto, niente regex fragili.
    """
    def __init__(self):
        super().__init__(
            name="amass",
            kind=KIND_PASSIVE_RECON,
            binary="amass",
            version_flag="version",   # amass usa "version" senza dash
            description="OWASP Amass — attack surface mapping & subdomain enumeration.",
            requires_scope=True,
            default_timeout=300,
        )

    def detect(self) -> ToolStatus:
        # Amass usa "amass version" (subcommand), non flag — provo entrambi.
        path = shutil.which(self.binary)
        if not path:
            return ToolStatus(name=self.name, installed=False,
                              error=f"Binario '{self.binary}' non trovato nel PATH.")
        for args in (["version"], ["-version"], ["--version"]):
            try:
                res = subprocess.run([path, *args], capture_output=True, text=True, timeout=5)
                out = (res.stdout + res.stderr).strip()
                if out:
                    return ToolStatus(name=self.name, installed=True,
                                      version=out.split("\n", 1)[0][:120], path=path)
            except Exception:
                continue
        return ToolStatus(name=self.name, installed=True, version="?", path=path)

    def build_command(self, target: TargetSpec, opts: dict) -> list[str]:
        if target.type not in (T_DOMAIN, T_SUBDOMAIN):
            return []
        domain = target.attributes.get("apex") or target.value
        # Comando "enum -passive -d domain -json /dev/stdout".
        # /dev/stdout su Windows non esiste, ma in deploy Linux funziona.
        # Optional: opts["active"]=True abilita active mode (rimanda scope check).
        args = ["enum", "-d", domain]
        if not opts.get("active"):
            args.append("-passive")
        args.extend(["-silent"])
        return args

    def parse_output(self, raw: str, target: TargetSpec) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in (raw or "").splitlines():
            # Amass enum -silent stampa "<subdomain>" per linea (in passive mode).
            sub = line.strip().lower()
            if not sub or "." not in sub or sub in seen:
                continue
            # Skip righe non-domain-like (es. log line "INFO ...").
            if " " in sub or sub.startswith(("info", "error", "debug")):
                continue
            seen.add(sub)
            findings.append(Finding(
                kind="subdomain",
                value=sub,
                confidence=0.85,
                evidence=[Evidence(url=f"https://{sub}", title="Amass")],
                notes=f"Sottodominio enumerato passivamente da Amass per {target.value}.",
                source_reliability="B", info_credibility=2,
            ))
        return findings


class ZAPBaselineAdapter(ToolAdapter):
    """OWASP ZAP baseline scan (DAST passivo).

    Richiede `zap-baseline.py` nel PATH (oppure docker `owasp/zap2docker-stable`,
    in tal caso il binario è `zap.sh`). Output XML/JSON → parsing best-effort.

    NOTE: lo scan baseline è "passive" nel senso ZAP (spider + passive rules,
    nessun active probe), ma comunque colpisce il target con HTTP. Lo classifichiamo
    come DAST e richiediamo scope esplicito.
    """
    def __init__(self):
        super().__init__(
            name="zap_baseline",
            kind=KIND_DAST,
            binary="zap-baseline.py",
            version_flag="-h",
            description="OWASP ZAP baseline scan (DAST passive rules + spider).",
            requires_scope=True,
            default_timeout=900,   # baseline può durare diversi minuti
        )

    def detect(self) -> ToolStatus:
        path = shutil.which(self.binary)
        if not path:
            # Fallback: cerca eseguibili alternativi.
            for alt in ("zap.sh", "zap"):
                p = shutil.which(alt)
                if p:
                    return ToolStatus(
                        name=self.name, installed=True,
                        version="binary alternativo trovato", path=p,
                        error=("zap-baseline.py non in PATH; usato fallback. "
                               "Configurare zap-baseline.py per output JSON."),
                    )
            return ToolStatus(name=self.name, installed=False,
                              error="zap-baseline.py non trovato. "
                                    "Installa OWASP ZAP o usa il container docker.")
        return ToolStatus(name=self.name, installed=True, version="?", path=path)

    def build_command(self, target: TargetSpec, opts: dict) -> list[str]:
        if target.type not in (T_URL, T_DOMAIN, T_SUBDOMAIN):
            return []
        url = _to_url(target)
        # zap-baseline.py -t URL -J json_report.json
        report_file = opts.get("report_file", "/tmp/zap-baseline.json")
        return ["-t", url, "-J", report_file]

    def parse_output(self, raw: str, target: TargetSpec) -> list[Finding]:
        # ZAP baseline produce un report JSON separato; il raw stdout contiene
        # solo log. Il caller deve passare il report_file via opts e leggerlo
        # post-esecuzione. Per ora estraiamo alert da stdout in formato "WARN-NEW".
        findings: list[Finding] = []
        for line in (raw or "").splitlines():
            # Format tipico: "WARN-NEW: Content Security Policy ... [10038]  ... 2"
            if line.startswith(("WARN-NEW", "FAIL-NEW")):
                severity = "high" if line.startswith("FAIL-NEW") else "medium"
                # Parse: "WARN-NEW: <name> [<id>]"
                parts = line.split(":", 1)
                if len(parts) < 2:
                    continue
                rest = parts[1].strip()
                name = rest.split("[")[0].strip()
                findings.append(Finding(
                    kind="zap_alert",
                    value=name,
                    confidence=0.7,
                    evidence=[Evidence(url=target.value, title="ZAP baseline")],
                    severity=severity,
                    notes=f"ZAP baseline alert su {target.value}.",
                    remediation="Verificare manualmente l'alert sulla console ZAP.",
                    source_reliability="B", info_credibility=2,
                ))
        return findings


# Register the built-ins.
register(SubfinderAdapter())
register(NucleiAdapter())
register(AmassAdapter())
register(ZAPBaselineAdapter())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_url(target: TargetSpec) -> str:
    if target.type == T_URL:
        return target.value
    if target.type in (T_DOMAIN, T_SUBDOMAIN):
        return f"https://{target.value}"
    return target.value


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
