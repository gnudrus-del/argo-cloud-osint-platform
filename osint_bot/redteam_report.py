"""Red Team report — variante specializzata di forensic_report.

Stessa struttura a sezioni del forensic_report, ma ottimizzata per output di
attività Red Team / vulnerability assessment / DAST:

  * Severity matrix esplicita (count per severity)
  * Findings tecnici con ID, TTP MITRE ATT&CK, remediation, exploit hint
  * Lista comandi/tool eseguiti (sanitizzata: niente secret/api key)
  * Scope enforcement log
  * Tabella IoC dedicata (subdomain takeover, exposed paths, ecc.)

API:

    build_redteam_report(ctx: RedTeamContext) -> ForensicReport

Restituisce la stessa struttura `ForensicReport` di forensic_report (così la
UI riusa il viewer), con sezioni 9-11-12-16 ricalibrate sui contenuti Red Team.

Vincoli operativi (per accettazione P8/P10 del brief):

  * Ogni finding include ID, target, categoria, tool, comando, fonte, evidenza,
    severità, confidenza, impatto, raccomandazione, limiti, timestamp.
  * Mai trasformare dati incompleti in completi: i contatti mascherati restano
    mascherati, i finding "untested" non diventano "confirmed".
  * Comandi salvati senza segreti (chiavi API espunte).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .forensic_report import (
    CaseContext, ForensicReport, ProviderUsage, ReportContext, ReportSection,
    build_forensic_report, _now_iso, _render_finding_line, _severity_rank,
    _short,
)
from .models import Finding
from .scope import CaseScope


# ---------------------------------------------------------------------------
# Input — estende ReportContext con metadati Red Team
# ---------------------------------------------------------------------------

@dataclass
class ToolExecution:
    """Record sintetico di un comando lanciato (per audit/report)."""
    tool: str                       # "subfinder", "nuclei", "amass", "zap", …
    kind: str                       # "passive_recon", "active_recon", "vuln_scan", …
    target: str
    started_at: str
    finished_at: str
    return_code: int | None
    duration_ms: int
    findings_count: int = 0
    error: str = ""
    # Comando lanciato senza secret. La sanitizzazione avviene in
    # `sanitize_command()` — è responsabilità del caller passare già il
    # comando pulito; questa dataclass non esegue alcun controllo.
    command_sanitized: str = ""


@dataclass
class RedTeamContext(ReportContext):
    """Estensione di ReportContext con esecuzioni e finding Red Team."""
    tool_executions: list[ToolExecution] = field(default_factory=list)
    redteam_findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_redteam_report(ctx: RedTeamContext) -> ForensicReport:
    """Costruisce il report Red Team riusando la struttura forensic + override
    delle sezioni 8/9/11/16."""
    # Tutti i finding Red Team vanno in extra_findings così appaiono ovunque.
    extra = list(ctx.extra_findings or []) + list(ctx.redteam_findings or [])
    ctx.extra_findings = extra

    report = build_forensic_report(ctx)

    # Sostituisco le 4 sezioni che ridefinisco per Red Team.
    overrides = {
        8:  _section_8_redteam_summary(ctx),
        9:  _section_9_redteam_findings(ctx),
        11: _section_11_tool_executions(ctx),
        16: _section_16_redteam_iocs(ctx),
    }
    new_sections: list[ReportSection] = []
    for s in report.sections:
        new_sections.append(overrides.get(s.number, s))
    report.sections = new_sections
    return report


# ---------------------------------------------------------------------------
# Sezioni Red Team specifiche
# ---------------------------------------------------------------------------

def _section_8_redteam_summary(ctx: RedTeamContext) -> ReportSection:
    findings = list(ctx.redteam_findings) + [
        f for f in (ctx.investigation.findings or [])
        if f.severity in {"critical", "high", "medium", "low"}
    ]
    counts = _severity_counts(findings)
    n_exec = len(ctx.tool_executions)
    failures = sum(1 for e in ctx.tool_executions if e.return_code not in (0, None))

    if not findings and not ctx.tool_executions:
        body = (
            "- Nessuna attività Red Team eseguita per questo job (probabilmente "
            "perché lo scope autorizzato è vuoto o i tool non sono configurati). "
            "Consulta *Falsi positivi e limiti* per i dettagli."
        )
    else:
        lines = [
            f"- **Esecuzioni tool**: {n_exec} (di cui {failures} con errore/timeout).",
            f"- **Findings raccolti**: {len(findings)} (severity matrix qui sotto).",
        ]
        if counts:
            cells = " · ".join(f"`{sev}`: {n}" for sev, n in counts.items())
            lines.append(f"- **Severity matrix**: {cells}")
        # Highlight critical/high
        if counts.get("critical", 0) > 0:
            lines.append(
                f"- ⚠ **{counts['critical']} finding CRITICAL** richiedono "
                "verifica immediata e remediation."
            )
        elif counts.get("high", 0) > 0:
            lines.append(
                f"- {counts['high']} finding HIGH richiedono triage prioritario."
            )
        body = "\n".join(lines)
    return ReportSection(number=8, title="Executive summary (Red Team)", body_markdown=body)


def _section_9_redteam_findings(ctx: RedTeamContext) -> ReportSection:
    findings = list(ctx.redteam_findings) + [
        f for f in (ctx.investigation.findings or [])
        if f.severity in {"critical", "high", "medium", "low"}
    ]
    if not findings:
        body = "_— nessun finding Red Team da riportare —_"
    else:
        # Ordina per severity desc + confidence desc.
        findings = sorted(
            findings,
            key=lambda f: (-_severity_rank(f.severity), -f.confidence),
        )
        rows = [
            "| ID | Severity | Conf. | Target / IoC | Tool | TTPs | Note |",
            "|---|---|---:|---|---|---|---|",
        ]
        for idx, f in enumerate(findings[:50], start=1):
            fid = _finding_id(f, idx)
            sev = f"**{f.severity}**" if f.severity in {"critical", "high"} else f.severity
            # Target/IoC: preferiamo l'URL evidence (più informativo), ma se
            # f.value contiene un identificativo distinto (CVE, address, …),
            # lo accodiamo per non perdere informazione critica.
            target_or_ev = f.evidence[0].url if f.evidence else f.value
            if f.evidence and f.value and f.value not in target_or_ev:
                target_or_ev = f"{target_or_ev} · {f.value}"
            tool = _tool_from_finding(f)
            ttps = ", ".join(f.attck_ttps) if f.attck_ttps else "—"
            note = _short(f.notes or f.remediation or "", 80)
            rows.append(
                f"| `{fid}` | {sev} | {f.confidence:.2f} | "
                f"{_short(target_or_ev, 80)} | {tool} | {ttps} | {note} |"
            )
        body = "\n".join(rows)
    return ReportSection(number=9, title="Findings Red Team", body_markdown=body)


def _section_11_tool_executions(ctx: RedTeamContext) -> ReportSection:
    if not ctx.tool_executions:
        body = "_— nessun tool Red Team è stato lanciato per questo job —_"
    else:
        rows = [
            "| Tool | Kind | Target | RC | Durata | Findings | Comando |",
            "|---|---|---|---:|---:|---:|---|",
        ]
        for e in ctx.tool_executions:
            rc = "—" if e.return_code is None else str(e.return_code)
            cmd_safe = _short(e.command_sanitized, 60)
            rows.append(
                f"| {e.tool} | {e.kind} | {_short(e.target, 30)} | {rc} | "
                f"{e.duration_ms} ms | {e.findings_count} | `{cmd_safe}` |"
            )
        body = "\n".join(rows)
        if any(e.error for e in ctx.tool_executions):
            body += "\n\n**Errori riportati:**\n"
            for e in ctx.tool_executions:
                if e.error:
                    body += f"- `{e.tool}`: {_short(e.error, 200)}\n"
    return ReportSection(number=11, title="Esecuzioni tool Red Team", body_markdown=body)


def _section_16_redteam_iocs(ctx: RedTeamContext) -> ReportSection:
    findings = list(ctx.redteam_findings) + list(ctx.investigation.findings or [])
    iocs: dict[str, list[str]] = {
        "Sottodomini": [],
        "Path esposti": [],
        "Subdomain takeover": [],
        "Credenziali esposte": [],
        "Vulnerabilità": [],
        "Altri indicatori": [],
    }
    for f in findings:
        kind = f.kind
        if kind == "subdomain":
            iocs["Sottodomini"].append(f"`{f.value}` (conf {f.confidence:.2f})")
        elif "exposed_path" in kind or "wayback_url" in kind:
            iocs["Path esposti"].append(f"`{f.value}`")
        elif "takeover" in kind:
            sev = f" **{f.severity}**" if f.severity else ""
            iocs["Subdomain takeover"].append(f"`{f.value}`{sev}")
        elif kind.startswith("opsec_possible_") or kind == "credential_exposure":
            iocs["Credenziali esposte"].append(f"`{kind}` · {_short(f.value, 80)}")
        elif kind == "nuclei_finding" and f.severity in {"high", "critical"}:
            iocs["Vulnerabilità"].append(f"**{f.severity}** · {_short(f.value, 100)}")
        elif kind in {"ip", "url", "file_hash"} or kind.startswith("crypto_"):
            iocs["Altri indicatori"].append(f"`{kind}` · `{f.value}`")

    blocks: list[str] = []
    for label, items in iocs.items():
        if items:
            blocks.append(f"**{label}** ({len(items)}):\n" +
                          "\n".join(f"- {x}" for x in items[:25]))
    body = "\n\n".join(blocks) if blocks else "_— nessun IoC tecnico estratto —_"
    return ReportSection(number=16, title="Indicatori tecnici (IoC Red Team)",
                         body_markdown=body)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Pattern per ripulire comandi dai segreti più comuni (best-effort).
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|token|secret|password|auth)([=:\s])[^\s\"']+"),
     r"\1\2***REDACTED***"),
    (re.compile(r"(Bearer )[A-Za-z0-9._\-]+"), r"\1***REDACTED***"),
    (re.compile(r"(ghp_|gho_|re_|sk-)[A-Za-z0-9_]+"), r"***REDACTED***"),
]


def sanitize_command(command: list[str] | str) -> str:
    """Serializza un comando rimuovendo segreti noti.

    Non garantisce assenza assoluta di leak (best-effort). Caller dovrebbe
    comunque evitare di passare API key in argv.
    """
    if isinstance(command, list):
        text = " ".join(_shell_quote(c) for c in command)
    else:
        text = str(command)
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def _shell_quote(s: str) -> str:
    # Non usiamo shlex.quote per evitare dependency overhead; serializzazione
    # è solo per UI/report, non per esecuzione.
    if not s:
        return "''"
    if re.search(r"[\s\"'\\$`!]", s):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if f.severity:
            out[f.severity] = out.get(f.severity, 0) + 1
    # Order: critical → low
    order = ["critical", "high", "medium", "low", "info"]
    return {k: out[k] for k in order if k in out}


def _finding_id(f: Finding, idx: int) -> str:
    """ID stabile per un finding (kind+value+severity hashed sui primi 6 char)."""
    import hashlib
    key = f"{f.kind}:{f.value}:{f.severity}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:6].upper()
    return f"RT-{idx:03d}-{h}"


def _tool_from_finding(f: Finding) -> str:
    """Best-effort estrazione del tool d'origine dal finding."""
    if f.evidence and f.evidence[0].title:
        return _short(f.evidence[0].title, 16)
    if f.kind.startswith("opsec_"):
        return "opsec"
    if f.kind.startswith("nuclei_"):
        return "nuclei"
    if f.kind == "subdomain":
        return "subfinder/amass"
    return f.kind.split("_", 1)[0]
