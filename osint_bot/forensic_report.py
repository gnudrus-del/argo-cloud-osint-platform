"""Forensic-grade OSINT report — 19 sezioni standard, leggibile da analisti.

Il report sostituisce le narrazioni generiche ("Sono state trovate informazioni
interessanti", "Il target sembra sospetto") con asserzioni basate su evidenza
concreta: fonte, timestamp, dato osservato, livello di confidenza, rilevanza
investigativa, limite.

Struttura standard (Priorità 3 del brief):

  1. Titolo del caso
  2. Data e ora della ricerca
  3. Target analizzato
  4. Base giuridica/finalità indicata nel caso
  5. Scope autorizzato
  6. Metodologia OSINT usata
  7. Tool/API utilizzati e relativo stato
  8. Executive summary
  9. Evidenze principali
  10. Tabella fonti
  11. Analisi tecnica
  12. Analisi forense (se applicabile)
  13. Valutazione attendibilità
  14. Falsi positivi o limiti dell'indagine
  15. Timeline (se disponibile)
  16. Indicatori tecnici (IoC)
  17. Conclusioni operative
  18. Raccomandazioni successive
  19. Appendice JSON con dati grezzi normalizzati

API pubblica:

    build_forensic_report(ctx: ReportContext) -> ForensicReport
    to_markdown(report) -> str
    to_json(report) -> dict (per appendice / API)

Il modulo è puro: non fa I/O. Caller salva il file su disco.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from .contact_discovery import Contact, ContactReport
from .models import Finding, Investigation
from .ranking import RankedResult
from .scope import CaseScope
from .target_classifier import TargetSpec

# ---------------------------------------------------------------------------
# Input context
# ---------------------------------------------------------------------------

@dataclass
class CaseContext:
    """Informazioni sul caso che inquadrano il report (sezioni 1-5)."""
    case_id: str
    title: str
    purpose: str = ""               # finalità GDPR / scopo investigativo
    legal_basis_type: str = ""      # consent | contract | legitimate_interest | …
    legal_basis_reference: str = "" # SOW-2026-018, ordinanza N°, mandato …
    owner: str = ""                 # username dell'analista
    collaborators: list[str] = field(default_factory=list)
    retention_until: str = ""       # data ISO (YYYY-MM-DD)


@dataclass
class ProviderUsage:
    """Stato di un provider/tool usato durante la ricerca."""
    name: str
    state: str                      # ok|auth_error|quota_exceeded|untested|…
    message: str = ""
    items_returned: int = 0


@dataclass
class ReportContext:
    """Tutto il necessario per generare il report."""
    case: CaseContext
    target: TargetSpec
    investigation: Investigation
    ranked_results: list[RankedResult]
    contacts: ContactReport | None = None
    scope: CaseScope | None = None
    providers: list[ProviderUsage] = field(default_factory=list)
    methodology: list[str] = field(default_factory=list)
    extra_findings: list[Finding] = field(default_factory=list)
    generated_at: str = ""


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

@dataclass
class ReportSection:
    number: int
    title: str
    body_markdown: str = ""
    structured: dict = field(default_factory=dict)


@dataclass
class ForensicReport:
    case_id: str
    target: str
    target_type: str
    generated_at: str
    sections: list[ReportSection]

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "target": self.target,
            "target_type": self.target_type,
            "generated_at": self.generated_at,
            "sections": [asdict(s) for s in self.sections],
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_forensic_report(ctx: ReportContext) -> ForensicReport:
    """Costruisce il report a 19 sezioni a partire dal contesto."""
    when = ctx.generated_at or _now_iso()
    sections: list[ReportSection] = []

    sections.append(_section_1_titolo(ctx))
    sections.append(_section_2_datetime(ctx, when))
    sections.append(_section_3_target(ctx))
    sections.append(_section_4_base_giuridica(ctx))
    sections.append(_section_5_scope(ctx))
    sections.append(_section_6_metodologia(ctx))
    sections.append(_section_7_tool_status(ctx))
    sections.append(_section_8_executive_summary(ctx))
    sections.append(_section_9_evidenze_principali(ctx))
    sections.append(_section_10_tabella_fonti(ctx))
    sections.append(_section_11_analisi_tecnica(ctx))
    sections.append(_section_12_analisi_forense(ctx))
    sections.append(_section_13_attendibilita(ctx))
    sections.append(_section_14_falsi_positivi(ctx))
    sections.append(_section_15_timeline(ctx))
    sections.append(_section_16_indicatori_tecnici(ctx))
    sections.append(_section_17_conclusioni(ctx))
    sections.append(_section_18_raccomandazioni(ctx))
    sections.append(_section_19_appendice_json(ctx))

    return ForensicReport(
        case_id=ctx.case.case_id,
        target=ctx.target.value or ctx.target.raw,
        target_type=ctx.target.type,
        generated_at=when,
        sections=sections,
    )


def to_markdown(report: ForensicReport) -> str:
    """Render del report in Markdown."""
    out: list[str] = []
    out.append(f"# {report.sections[0].body_markdown.strip() or report.target}\n")
    out.append(f"_Caso `{report.case_id}` · target `{report.target}` ({report.target_type}) · "
               f"generato {report.generated_at}_\n")
    out.append("\n---\n")
    for sec in report.sections:
        out.append(f"\n## {sec.number}. {sec.title}\n")
        body = (sec.body_markdown or "_— nessun dato disponibile per questa sezione —_").strip()
        out.append(body + "\n")
    return "".join(out)


def to_json(report: ForensicReport) -> dict:
    return report.to_dict()


# ---------------------------------------------------------------------------
# Sezioni
# ---------------------------------------------------------------------------

def _section_1_titolo(ctx: ReportContext) -> ReportSection:
    title = ctx.case.title or f"Indagine OSINT su {ctx.target.value or ctx.target.raw}"
    return ReportSection(number=1, title="Titolo del caso", body_markdown=title)


def _section_2_datetime(ctx: ReportContext, when: str) -> ReportSection:
    body = (
        f"- **Data/ora generazione (UTC)**: {when}\n"
        f"- **Inizio raccolta**: {ctx.investigation.generated_at or '—'}\n"
        f"- **Operatore**: {ctx.case.owner or '—'}\n"
    )
    return ReportSection(number=2, title="Data e ora della ricerca", body_markdown=body)


def _section_3_target(ctx: ReportContext) -> ReportSection:
    t = ctx.target
    attrs = "\n".join(f"  - {k}: `{v}`" for k, v in (t.attributes or {}).items())
    warnings = ("\n  - " + "\n  - ".join(t.warnings)) if t.warnings else " nessuno"
    body = (
        f"- **Valore**: `{t.value or t.raw}`\n"
        f"- **Tipo classificato**: `{t.type}`\n"
        f"- **Confidenza classificazione**: {t.confidence:.2f}\n"
        f"- **Motivazione**: {t.rationale}\n"
        f"- **Attributi**:\n{attrs or '  - —'}\n"
        f"- **Avvertenze**:{warnings}\n"
    )
    return ReportSection(number=3, title="Target analizzato", body_markdown=body)


def _section_4_base_giuridica(ctx: ReportContext) -> ReportSection:
    c = ctx.case
    body = (
        f"- **Tipo base giuridica**: {c.legal_basis_type or '— non dichiarato —'}\n"
        f"- **Riferimento mandato/contratto**: {c.legal_basis_reference or '—'}\n"
        f"- **Finalità dichiarata**: {c.purpose.strip() or '—'}\n"
        f"- **Owner**: {c.owner or '—'}\n"
        f"- **Collaboratori autorizzati**: {', '.join(c.collaborators) or '—'}\n"
        f"- **Retention dichiarata**: {c.retention_until or 'nessuna scadenza specificata'}\n"
    )
    return ReportSection(number=4, title="Base giuridica e finalità", body_markdown=body)


def _section_5_scope(ctx: ReportContext) -> ReportSection:
    if not ctx.scope or not ctx.scope.entries:
        body = (
            "- **Scope autorizzato**: non dichiarato.\n"
            "- I moduli Red Team/active e le ricerche invasive sono pertanto disabilitati.\n"
        )
    else:
        rows = "\n".join(
            f"- `{e.kind}` · `{e.value}` · {e.note or 'senza note'}"
            for e in ctx.scope.entries
        )
        body = f"Allowlist autorizzata per il caso ({len(ctx.scope.entries)} regole):\n{rows}\n"
    return ReportSection(number=5, title="Scope autorizzato", body_markdown=body)


def _section_6_metodologia(ctx: ReportContext) -> ReportSection:
    default = [
        "Classificazione del target con `target_classifier` (validazione formato + normalizzazione).",
        "Raccolta passiva da provider OSINT pubblici (search API, registri pubblici).",
        "Estrazione contatti email/telefono con anti-falso-positivo (`contact_discovery`).",
        "Deduplicazione URL canonical + scoring multi-asse (`ranking`).",
        "Attribuzione provenance + grading Admiralty/NATO per ogni finding.",
    ]
    items = ctx.methodology or default
    body = "\n".join(f"- {line}" for line in items)
    return ReportSection(number=6, title="Metodologia OSINT applicata", body_markdown=body)


def _section_7_tool_status(ctx: ReportContext) -> ReportSection:
    if not ctx.providers:
        body = "_— nessun provider/tool registrato per questa indagine —_"
    else:
        rows = ["| Provider | Stato | Risultati | Note |", "|---|---|---:|---|"]
        for p in ctx.providers:
            rows.append(f"| {p.name} | `{p.state}` | {p.items_returned} | {p.message or '—'} |")
        body = "\n".join(rows)
    return ReportSection(number=7, title="Tool e API utilizzati", body_markdown=body)


def _section_8_executive_summary(ctx: ReportContext) -> ReportSection:
    n_results = len(ctx.ranked_results)
    n_certain = len(ctx.contacts.certain) if ctx.contacts else 0
    n_probable = len(ctx.contacts.probable) if ctx.contacts else 0
    n_findings = len(ctx.investigation.findings) + len(ctx.extra_findings)
    severities = _severity_counts(ctx)

    lines = [
        f"- Sono state esaminate **{n_results} fonti pubbliche** correlate al target.",
        f"- I contatti pubblici associati con alta confidenza sono **{n_certain}** "
        f"(con altri {n_probable} a confidenza media).",
        f"- Sono state registrate **{n_findings} evidenze** di vario tipo.",
    ]
    if severities:
        sev_line = ", ".join(f"{k}: {v}" for k, v in severities.items())
        lines.append(f"- Distribuzione severità: {sev_line}.")

    # Se non c'è nulla, dire esplicitamente che non si è trovato nulla.
    if n_results == 0 and n_findings == 0 and n_certain == 0:
        lines = [
            "- Nessuna evidenza pubblica rilevante è stata raccolta per il target con "
            "i provider attualmente configurati. Vedere la sezione *Limiti dell'indagine*.",
        ]

    body = "\n".join(lines)
    return ReportSection(number=8, title="Executive summary", body_markdown=body)


def _section_9_evidenze_principali(ctx: ReportContext) -> ReportSection:
    items: list[str] = []
    if ctx.contacts:
        for c in ctx.contacts.certain[:10]:
            items.append(_render_contact_line(c))
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    # Ordina per severità (critical/high → primi) e poi confidenza.
    findings_sorted = sorted(
        findings,
        key=lambda f: (-_severity_rank(f.severity), -f.confidence),
    )
    for f in findings_sorted[:15]:
        items.append(_render_finding_line(f))
    if not items:
        body = "_— nessuna evidenza di rilievo —_"
    else:
        body = "\n".join(f"- {line}" for line in items)
    return ReportSection(number=9, title="Evidenze principali", body_markdown=body)


def _section_10_tabella_fonti(ctx: ReportContext) -> ReportSection:
    if not ctx.ranked_results:
        body = "_— nessuna fonte ranked —_"
    else:
        rows = [
            "| # | Fonte | Provider | Score | Conf. associazione | Note |",
            "|---:|---|---|---:|---:|---|",
        ]
        for idx, r in enumerate(ctx.ranked_results[:50], start=1):
            note = "; ".join(r.reasons[:2]) if r.reasons else ""
            rows.append(
                f"| {idx} | [{_short(r.original.title or r.canonical_url, 60)}]({r.canonical_url}) "
                f"| {r.original.provider} | {r.score:.2f} | {r.target_match:.2f} | {note} |"
            )
        body = "\n".join(rows)
    return ReportSection(number=10, title="Tabella fonti", body_markdown=body)


def _section_11_analisi_tecnica(ctx: ReportContext) -> ReportSection:
    """Conteggi per tipo di finding + breakdown contatti."""
    by_kind = _findings_by_kind(ctx)
    lines: list[str] = []
    if by_kind:
        lines.append("**Findings per tipo:**")
        for kind, count in sorted(by_kind.items(), key=lambda x: -x[1]):
            lines.append(f"- `{kind}`: {count}")
    if ctx.contacts:
        cnt = ctx.contacts.count_by_kind()
        lines.append("")
        lines.append("**Contatti raccolti:**")
        lines.append(f"- Email: {cnt.get('email', 0)}")
        lines.append(f"- Telefono: {cnt.get('phone', 0)}")
        lines.append(f"- Fonti distinte con hit: {ctx.contacts.sources_with_hits}")
        lines.append(f"- Pagine scansionate: {ctx.contacts.pages_scanned}")
    body = "\n".join(lines) if lines else "_— nessun dato tecnico da analizzare —_"
    return ReportSection(number=11, title="Analisi tecnica", body_markdown=body)


def _section_12_analisi_forense(ctx: ReportContext) -> ReportSection:
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    forensic = [f for f in findings if f.kind.startswith("media_") or f.kind == "exif"]
    if not forensic:
        body = "_— nessun artefatto digitale soggetto ad analisi forense in questo report —_"
    else:
        lines = []
        for f in forensic:
            lines.append(_render_finding_line(f))
        body = "\n".join(f"- {l}" for l in lines)
    return ReportSection(number=12, title="Analisi forense", body_markdown=body)


def _section_13_attendibilita(ctx: ReportContext) -> ReportSection:
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    if not findings:
        body = "_— nessuna evidenza su cui valutare l'attendibilità —_"
    else:
        grade_counts: dict[str, int] = {}
        for f in findings:
            key = f"{f.source_reliability}{f.info_credibility}"
            grade_counts[key] = grade_counts.get(key, 0) + 1
        rows = ["| Grado Admiralty | N° findings |", "|---|---:|"]
        for g, c in sorted(grade_counts.items()):
            rows.append(f"| {g} | {c} |")
        body = "\n".join(rows)
    return ReportSection(number=13, title="Valutazione attendibilità (Admiralty)",
                         body_markdown=body)


def _section_14_falsi_positivi(ctx: ReportContext) -> ReportSection:
    notes: list[str] = []
    if ctx.contacts and ctx.contacts.unconfirmed:
        notes.append(
            f"- {len(ctx.contacts.unconfirmed)} contatti non confermati (bassa "
            f"associazione al target): mostrati separatamente nell'appendice."
        )
    skipped = getattr(ctx.investigation, "skipped_urls", []) or []
    if skipped:
        notes.append(f"- {len(skipped)} URL saltati durante la raccolta (errore o policy).")
    if ctx.target.warnings:
        notes.append("- Classificazione target: " + "; ".join(ctx.target.warnings))
    if not ctx.providers:
        notes.append(
            "- Nessun provider OSINT configurato: la copertura è limitata ai dati "
            "ottenibili senza API. Inserire chiavi nei provider per ampliarla."
        )
    if not notes:
        notes.append("- Nessun limite specifico identificato per questa indagine.")
    body = "\n".join(notes)
    return ReportSection(number=14, title="Falsi positivi e limiti dell'indagine",
                         body_markdown=body)


def _section_15_timeline(ctx: ReportContext) -> ReportSection:
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    years = [f for f in findings if f.kind in {"timeline_year_mention", "year_mention"}]
    events: list[tuple[str, str]] = []
    for f in years:
        events.append((f.value, f.notes[:120]))
    # Inserisci la generazione del report come ultimo evento.
    events.append((ctx.generated_at or _now_iso(), f"Generazione report (caso `{ctx.case.case_id}`)."))
    if len(events) <= 1:
        body = "_— nessun evento storico estratto dalle fonti —_"
    else:
        events.sort(key=lambda x: x[0])
        body = "\n".join(f"- **{when}** — {what}" for when, what in events)
    return ReportSection(number=15, title="Timeline ricostruita", body_markdown=body)


def _section_16_indicatori_tecnici(ctx: ReportContext) -> ReportSection:
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    iocs: list[str] = []
    for f in findings:
        if f.kind in {"subdomain", "ip", "url", "file_hash"} or f.kind.startswith("crypto_"):
            iocs.append(f"- `{f.kind}` · `{f.value}` (conf {f.confidence:.2f})")
        elif f.kind == "nuclei_finding" and f.severity in {"high", "critical"}:
            iocs.append(f"- **{f.severity}** · {f.value}")
    if not iocs:
        body = "_— nessun indicatore tecnico estratto —_"
    else:
        body = "\n".join(iocs[:50])
    return ReportSection(number=16, title="Indicatori tecnici (IoC)", body_markdown=body)


def _section_17_conclusioni(ctx: ReportContext) -> ReportSection:
    n_results = len(ctx.ranked_results)
    n_contacts = len(ctx.contacts.all()) if ctx.contacts else 0
    n_findings = len(ctx.investigation.findings) + len(ctx.extra_findings)
    severities = _severity_counts(ctx)
    if n_results == 0 and n_findings == 0:
        body = (
            "Sulla base dei provider attivi e dello scope dichiarato, non sono emerse "
            "evidenze pubbliche rilevanti per il target. Le ragioni più probabili sono "
            "indicate in *Falsi positivi e limiti*: estendere il numero di provider "
            "configurati e/o l'autorizzazione esplicita su moduli avanzati."
        )
    else:
        bits = [
            f"L'indagine ha esaminato **{n_results} fonti** e raccolto "
            f"**{n_contacts} contatti** + **{n_findings} evidenze** correlate al target.",
        ]
        critical = severities.get("critical", 0)
        high = severities.get("high", 0)
        if critical:
            bits.append(f"Sono presenti **{critical} evidenze critical** che richiedono "
                        "una verifica immediata.")
        elif high:
            bits.append(f"Sono presenti **{high} evidenze high** che richiedono triage prioritario.")
        else:
            bits.append("Nessuna evidenza ad alta severità è emersa nei controlli automatici.")
        body = " ".join(bits)
    return ReportSection(number=17, title="Conclusioni operative", body_markdown=body)


def _section_18_raccomandazioni(ctx: ReportContext) -> ReportSection:
    recs: list[str] = []
    severities = _severity_counts(ctx)
    if severities.get("critical") or severities.get("high"):
        recs.append(
            "Aprire un sotto-caso per ciascuna evidenza high/critical e tracciare "
            "remediation + verifica."
        )
    if ctx.contacts and ctx.contacts.probable:
        recs.append(
            f"Verificare manualmente i {len(ctx.contacts.probable)} contatti a confidenza "
            "media (sezione 9): la fonte è pubblica ma l'associazione al target richiede "
            "conferma da analista."
        )
    if not any(p.state == "ok" for p in ctx.providers):
        recs.append(
            "Configurare almeno un provider OSINT (Brave/Bing/Serper/Shodan/VirusTotal) "
            "nella sezione *Chiavi API* per estendere la copertura."
        )
    if ctx.scope is None or not ctx.scope.entries:
        recs.append(
            "Dichiarare uno scope autorizzato sul caso per abilitare i moduli active/Red Team."
        )
    if not recs:
        recs = ["Mantenere la documentazione del caso aggiornata e archiviare gli artefatti."]
    body = "\n".join(f"- {r}" for r in recs)
    return ReportSection(number=18, title="Raccomandazioni successive", body_markdown=body)


def _section_19_appendice_json(ctx: ReportContext) -> ReportSection:
    raw = {
        "case": asdict(ctx.case),
        "target": _target_to_dict(ctx.target),
        "ranked_results": [r.to_dict() for r in ctx.ranked_results[:200]],
        "contacts": _contacts_to_dict(ctx.contacts) if ctx.contacts else {},
        "providers": [asdict(p) for p in ctx.providers],
        "findings": [asdict(f) for f in (ctx.investigation.findings or [])],
        "extra_findings": [asdict(f) for f in (ctx.extra_findings or [])],
        "scope": ctx.scope.to_dict() if ctx.scope else None,
        "investigation_meta": {
            "generated_at": ctx.investigation.generated_at,
            "queries": list(ctx.investigation.queries or []),
            "pages_count": len(ctx.investigation.pages or []),
            "skipped_urls": list(ctx.investigation.skipped_urls or []),
        },
    }
    body = "```json\n" + json.dumps(raw, indent=2, ensure_ascii=False) + "\n```"
    return ReportSection(
        number=19, title="Appendice — dati grezzi normalizzati",
        body_markdown=body, structured=raw,
    )


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------

def _render_contact_line(c: Contact) -> str:
    val = c.display or c.value
    incomplete = " ⚠ incompleto" if c.incomplete else ""
    src = f"[fonte]({c.source_url})"
    return (
        f"**{c.kind}**: `{val}` · cat: {c.category} · conf {c.confidence:.2f} "
        f"({c.confidence_label}){incomplete} · {src}"
    )


def _render_finding_line(f: Finding) -> str:
    sev = f" · sev: **{f.severity}**" if f.severity else ""
    ev = (f" · ev: {f.evidence[0].url}" if f.evidence else "")
    grade = f"{f.source_reliability}{f.info_credibility}"
    return (
        f"`{f.kind}` · `{f.value}` · conf {f.confidence:.2f}{sev} · Admiralty {grade}{ev}"
    )


def _short(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _severity_rank(s: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(s, 0)


def _severity_counts(ctx: ReportContext) -> dict[str, int]:
    findings = (ctx.investigation.findings or []) + list(ctx.extra_findings or [])
    out: dict[str, int] = {}
    for f in findings:
        if f.severity:
            out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _findings_by_kind(ctx: ReportContext) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in (ctx.investigation.findings or []):
        out[f.kind] = out.get(f.kind, 0) + 1
    for f in (ctx.extra_findings or []):
        out[f.kind] = out.get(f.kind, 0) + 1
    return out


def _target_to_dict(t: TargetSpec) -> dict:
    return {
        "type": t.type, "value": t.value, "raw": t.raw,
        "confidence": t.confidence, "rationale": t.rationale,
        "attributes": dict(t.attributes), "warnings": list(t.warnings),
    }


def _contacts_to_dict(report: ContactReport) -> dict:
    def _c(items): return [asdict(c) for c in items]
    return {
        "target": report.target,
        "target_type": report.target_type,
        "pages_scanned": report.pages_scanned,
        "sources_with_hits": report.sources_with_hits,
        "certain": _c(report.certain),
        "probable": _c(report.probable),
        "unconfirmed": _c(report.unconfirmed),
    }


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
