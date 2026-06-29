"""Tests for forensic_report.py — 19-section structure + content quality."""
from __future__ import annotations

import json

import pytest

from osint_bot.contact_discovery import Contact, ContactReport
from osint_bot.forensic_report import (
    CaseContext, ForensicReport, ProviderUsage, ReportContext, ReportSection,
    build_forensic_report, to_json, to_markdown,
)
from osint_bot.models import Evidence, Finding, Investigation, SearchResult
from osint_bot.ranking import rank_results
from osint_bot.scope import CaseScope, parse_entry
from osint_bot.target_classifier import classify_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_ctx(**overrides):
    case = overrides.pop("case", CaseContext(
        case_id="C-1",
        title="Indagine OSINT Acme",
        purpose="Verifica perimetro per ingaggio bug bounty.",
        legal_basis_type="contract",
        legal_basis_reference="SOW-2026-018",
        owner="alice",
        collaborators=["bob"],
    ))
    target = overrides.pop("target", classify_target("acme.com"))
    investigation = overrides.pop("investigation", Investigation.create(
        target="acme.com",
        target_type="domain",
        safety_note="",
        queries=["site:acme.com contact"],
        search_results=[],
        pages=[],
        findings=[],
    ))
    ranked = overrides.pop("ranked_results", [])
    return ReportContext(
        case=case, target=target, investigation=investigation,
        ranked_results=ranked, generated_at="2026-06-27T15:00:00Z",
        **overrides,
    )


# ---------------------------------------------------------------------------
# Structure: 19 sezioni
# ---------------------------------------------------------------------------

class TestStructure:
    def test_19_sections(self):
        report = build_forensic_report(_minimal_ctx())
        assert len(report.sections) == 19
        assert [s.number for s in report.sections] == list(range(1, 20))

    def test_titles_in_italian(self):
        report = build_forensic_report(_minimal_ctx())
        titles = [s.title.lower() for s in report.sections]
        # Verifico chiavi italiane attese.
        assert any("titolo" in t for t in titles)
        assert any("base giuridica" in t for t in titles)
        assert any("metodologia" in t for t in titles)
        assert any("raccomandazioni" in t for t in titles)
        assert any("indicatori tecnici" in t for t in titles)

    def test_every_section_has_body(self):
        report = build_forensic_report(_minimal_ctx())
        for s in report.sections:
            assert s.body_markdown, f"Section {s.number} ({s.title}) has empty body"


# ---------------------------------------------------------------------------
# Contenuto: anti-frasi-generiche
# ---------------------------------------------------------------------------

class TestContentQuality:
    def test_executive_summary_no_generic_phrases(self):
        ctx = _minimal_ctx()
        report = build_forensic_report(ctx)
        exec_sec = next(s for s in report.sections if s.number == 8)
        body = exec_sec.body_markdown.lower()
        banned = [
            "sono state trovate informazioni interessanti",
            "il target sembra sospetto",
            "analisi completata con successo",
            "sono presenti dati online",
        ]
        for phrase in banned:
            assert phrase not in body, f"Frase generica vietata: {phrase!r}"

    def test_empty_investigation_says_so(self):
        ctx = _minimal_ctx()  # no providers, no results, no findings
        report = build_forensic_report(ctx)
        exec_sec = next(s for s in report.sections if s.number == 8).body_markdown.lower()
        assert "nessuna evidenza" in exec_sec

    def test_conclusions_distinguish_empty_vs_findings(self):
        # Empty case
        rpt_empty = build_forensic_report(_minimal_ctx())
        concl_empty = next(s for s in rpt_empty.sections if s.number == 17).body_markdown.lower()
        assert "nessuna" in concl_empty or "non sono emerse" in concl_empty

        # Case with critical finding
        f = Finding(kind="nuclei_finding", value="exposed-config", confidence=0.9,
                    severity="critical")
        inv = Investigation.create(
            target="acme.com", target_type="domain", safety_note="",
            queries=[], search_results=[], pages=[], findings=[f],
        )
        rpt_full = build_forensic_report(_minimal_ctx(investigation=inv))
        concl = next(s for s in rpt_full.sections if s.number == 17).body_markdown.lower()
        assert "critical" in concl


# ---------------------------------------------------------------------------
# Sezione 4: base giuridica
# ---------------------------------------------------------------------------

class TestLegalBasis:
    def test_includes_purpose_and_reference(self):
        report = build_forensic_report(_minimal_ctx())
        sec = next(s for s in report.sections if s.number == 4).body_markdown
        assert "SOW-2026-018" in sec
        assert "contract" in sec
        assert "bug bounty" in sec
        assert "alice" in sec

    def test_missing_legal_basis_explicit(self):
        ctx = _minimal_ctx(case=CaseContext(case_id="C", title="t"))
        report = build_forensic_report(ctx)
        sec = next(s for s in report.sections if s.number == 4).body_markdown
        assert "non dichiarato" in sec.lower() or "—" in sec


# ---------------------------------------------------------------------------
# Sezione 5: scope
# ---------------------------------------------------------------------------

class TestScope:
    def test_empty_scope_disables_redteam(self):
        report = build_forensic_report(_minimal_ctx())
        sec = next(s for s in report.sections if s.number == 5).body_markdown.lower()
        assert "disabilitati" in sec or "non dichiarato" in sec

    def test_scope_entries_listed(self):
        scope = CaseScope(case_id="C-1")
        scope.add(parse_entry("acme.com"))
        scope.add(parse_entry("*.acme.com"))
        scope.add(parse_entry("10.0.0.0/24"))
        report = build_forensic_report(_minimal_ctx(scope=scope))
        sec = next(s for s in report.sections if s.number == 5).body_markdown
        assert "acme.com" in sec
        assert "10.0.0.0/24" in sec
        assert "3 regole" in sec


# ---------------------------------------------------------------------------
# Sezione 7: tool/API status
# ---------------------------------------------------------------------------

class TestProviderStatus:
    def test_table_when_providers_present(self):
        providers = [
            ProviderUsage(name="brave", state="ok", items_returned=10),
            ProviderUsage(name="hibp", state="auth_error", message="Chiave non valida"),
        ]
        report = build_forensic_report(_minimal_ctx(providers=providers))
        sec = next(s for s in report.sections if s.number == 7).body_markdown
        assert "brave" in sec and "hibp" in sec
        assert "ok" in sec
        assert "auth_error" in sec
        assert "Chiave non valida" in sec


# ---------------------------------------------------------------------------
# Sezione 9: evidenze
# ---------------------------------------------------------------------------

class TestEvidence:
    def test_includes_certain_contacts(self):
        target = classify_target("acme.com")
        contact = Contact(
            kind="email", value="info@acme.com", display="info@acme.com",
            source_url="https://acme.com/contact", source_title="x",
            timestamp="2026-01-01T00:00:00Z", category="business",
            confidence=0.9, confidence_label="certo",
            rationale="dominio coincide",
        )
        report = ContactReport(target="acme.com", target_type="domain")
        report.certain.append(contact)
        rpt = build_forensic_report(_minimal_ctx(contacts=report))
        sec = next(s for s in rpt.sections if s.number == 9).body_markdown
        assert "info@acme.com" in sec
        assert "business" in sec

    def test_orders_by_severity(self):
        crit = Finding(kind="x", value="x1", confidence=0.7, severity="critical")
        low = Finding(kind="y", value="y1", confidence=0.9, severity="low")
        inv = Investigation.create(
            target="t", target_type="domain", safety_note="",
            queries=[], search_results=[], pages=[],
            findings=[low, crit],   # critical inserted second
        )
        rpt = build_forensic_report(_minimal_ctx(investigation=inv))
        sec = next(s for s in rpt.sections if s.number == 9).body_markdown
        # Critical should appear before low.
        assert sec.index("x1") < sec.index("y1")


# ---------------------------------------------------------------------------
# Sezione 10: tabella fonti
# ---------------------------------------------------------------------------

class TestSourceTable:
    def test_table_format(self):
        target = classify_target("acme.com")
        results = [
            SearchResult(title="Contatti", url="https://acme.com/contatti", snippet=""),
            SearchResult(title="About", url="https://acme.com/about", snippet=""),
        ]
        ranked = rank_results(results, target)
        rpt = build_forensic_report(_minimal_ctx(ranked_results=ranked))
        sec = next(s for s in rpt.sections if s.number == 10).body_markdown
        assert "| Fonte" in sec or "Fonte" in sec
        assert "acme.com" in sec


# ---------------------------------------------------------------------------
# Sezione 19: JSON appendix
# ---------------------------------------------------------------------------

class TestJsonAppendix:
    def test_json_valid(self):
        rpt = build_forensic_report(_minimal_ctx())
        sec = next(s for s in rpt.sections if s.number == 19)
        # body should contain json fence
        assert "```json" in sec.body_markdown
        # structured field is the actual dict
        assert isinstance(sec.structured, dict)
        # Should be serializable
        s = json.dumps(sec.structured, ensure_ascii=False)
        reloaded = json.loads(s)
        assert reloaded["case"]["case_id"] == "C-1"
        assert reloaded["target"]["type"] == "domain"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TestMarkdown:
    def test_renders_h1_and_h2(self):
        rpt = build_forensic_report(_minimal_ctx())
        md = to_markdown(rpt)
        assert md.startswith("# ")
        assert "\n## 1." in md
        assert "\n## 19." in md
        assert "## 8. Executive summary" in md

    def test_to_json_serializable(self):
        rpt = build_forensic_report(_minimal_ctx())
        d = to_json(rpt)
        # Round-trip JSON
        s = json.dumps(d, ensure_ascii=False)
        reloaded = json.loads(s)
        assert reloaded["case_id"] == "C-1"
        assert len(reloaded["sections"]) == 19
