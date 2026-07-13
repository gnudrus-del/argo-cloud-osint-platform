from __future__ import annotations

import json
import re
import urllib.parse
from collections import defaultdict
from pathlib import Path

from .grading import distribution as grade_distribution
from .models import Entity, Finding, Investigation, Relationship
from .safety import redact_email, redact_phone

KIND_LABELS = {
    "web_presence": "presenza web",
    "related_domain": "domini e sottodomini",
    "public_document": "documenti pubblici",
    "possible_profile": "profili pubblici candidati",
    "socmint_public_profile_reference": "profili social pubblici",
    "technology_mention": "tecnologie citate",
    "redacted_contact_email": "email pubbliche redatte",
    "contact_email": "email pubbliche",
    "timeline_year_mention": "timeline",
    "agent_web_coverage": "copertura web",
    "opsec_possible_token": "possibili esposizioni OPSEC",
    "opsec_possible_private_key": "possibili chiavi private",
    "opsec_possible_aws_access_key": "possibili chiavi cloud",
    "opsec_sensitive_path_reference": "path sensibili citati",
    "crypto_address": "address crypto",
    "geo_coordinate_mention": "coordinate pubbliche",
    "geo_map_link": "link mappa",
    "phone_format": "telefono",
    "media_file_metadata": "metadati media",
    "public_media_reference": "media pubblici",
    "external_sherlock_profile": "profili pubblici trovati da Sherlock",
    "external_maigret_profile": "profili pubblici trovati da Maigret",
    "external_social_analyzer_profile": "profili pubblici trovati da Social Analyzer",
    "external_toutatis_profile": "profili pubblici trovati da Toutatis",
    "external_osintgram_profile": "profili pubblici trovati da Osintgram",
    "reverse_account_match": "registrazioni social associate a email o telefono",
    "red_team_takeover_candidate": "host candidati a subdomain takeover",
    "red_team_exposed_path": "path esposti pubblicamente",
    "humint_interview_plan": "piano HUMINT etico",
}

# Italian narrative voice for the "what we ran" paragraph in reports.
TOOL_HUMAN_NAMES = {
    "sherlock": "Sherlock",
    "maigret": "Maigret",
    "social_analyzer": "Social Analyzer",
    "holehe": "Holehe",
    "h8mail": "h8mail",
    "ghunt": "GHunt",
    "mosint": "Mosint",
    "socialscan": "SocialScan",
    "phoneinfoga": "PhoneInfoga",
    "phunter": "Phunter",
    "toutatis": "Toutatis",
    "osintgram": "Osintgram",
    "nmap": "nmap",
    "theharvester": "theHarvester",
    "spiderfoot": "SpiderFoot",
    "recon_ng": "Recon-ng",
    "amass": "amass",
    "subfinder": "Subfinder",
    "waybackurls": "waybackurls",
    "gau": "gau",
    "gitleaks": "Gitleaks",
    "trufflehog": "TruffleHog",
    "singlefile": "SingleFile",
    "shodan": "Shodan",
    "censys": "Censys",
    "exiftool": "ExifTool",
    "ffprobe": "ffprobe",
    "subjack": "Subjack",
    "cloud_enum": "cloud_enum",
    "infoga": "Infoga",
}
AGENT_HUMAN_NAMES = {
    "planner": "Pianificatore",
    "web": "Raccolta web",
    "external_tools": "Strumenti esterni",
    "opsec": "OPSEC",
    "crypto": "Crypto",
    "media": "Media",
    "geo": "Geolocalizzazione",
    "socmint": "SOCMINT",
    "phone": "Telefono",
    "darkweb": "Deep/dark web",
    "humint": "HUMINT",
    "reverse_account": "Reverse-account",
    "red_team": "Red team",
}

UTILITY_HOSTS = {
    "bing.com",
    "crt.sh",
    "duckduckgo.com",
    "google.com",
    "hunter.io",
    "intelx.io",
    "search.censys.io",
    "shodan.io",
    "urlscan.io",
    "web.archive.org",
    "yandex.com",
}


def save_report(investigation: Investigation, output_dir: Path, formats: str) -> tuple[Path | None, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = safe_stem(display_target(investigation))
    markdown_path = output_dir / f"{stem}.md"
    json_path = output_dir / f"{stem}.json"

    wrote_markdown: Path | None = None
    wrote_json: Path | None = None
    if formats in {"both", "markdown"}:
        markdown_path.write_text(to_markdown(investigation), encoding="utf-8")
        wrote_markdown = markdown_path
    if formats in {"both", "json"}:
        json_path.write_text(json.dumps(investigation.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        wrote_json = json_path
    return wrote_markdown, wrote_json


def to_markdown(investigation: Investigation) -> str:
    shown_target = display_target(investigation)
    grouped = group_findings(investigation.findings)
    ok_pages = [page for page in investigation.pages if not page.error]
    failed_pages = [page for page in investigation.pages if page.error]
    external_notes = [
        note
        for result in investigation.agent_results
        for note in result.notes
        if "missing" in note.casefold() or "non trovato" in note.casefold()
    ]

    lines = [
        f"# Rapporto investigativo OSINT - {shown_target}",
        "",
        f"**Tipo obiettivo:** `{investigation.target_type}`  ",
        f"**Generato:** `{investigation.generated_at}`",
        "",
        "## Sintesi discorsiva",
        "",
        narrative_summary(investigation, grouped, ok_pages, failed_pages),
        "",
        "## Copertura della ricerca",
        "",
        coverage_text(investigation, ok_pages, failed_pages, external_notes),
        "",
        "## Query e dork utilizzati",
        "",
    ]
    lines.extend(query_lines(investigation.queries))
    lines.extend(
        [
            "",
            "## Cosa emerge",
            "",
        ]
    )

    if investigation.findings:
        for kind, findings in grouped.items():
            lines.extend(section_for_kind(kind, findings))
    else:
        lines.extend(
            [
                "Non sono emerse evidenze strutturate sufficienti. Questo di solito significa che mancano fonti seed,",
                "chiavi API di ricerca o strumenti esterni installati. Il target potrebbe anche avere una presenza pubblica limitata.",
                "",
            ]
        )

    lines.extend(entity_graph_section(investigation))

    lines.extend(
        [
            "## Fascicolo finale: fatti, inferenze e ipotesi",
            "",
        ]
    )
    lines.extend(analytic_dossier(investigation, grouped))

    lines.extend(
        [
            "## Checklist di verifica manuale",
            "",
        ]
    )
    lines.extend(manual_verification_checklist(investigation))

    lines.extend(
        [
            "## Valutazione operativa",
            "",
            operational_assessment(investigation),
            "",
            "## Prossimi passi consigliati",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in recommended_next_steps(investigation, external_notes))

    lines.extend(["", "## Fonti principali", ""])
    if investigation.search_results:
        for result in investigation.search_results[:30]:
            snippet = f" - {escape_md(result.snippet[:220])}" if result.snippet else ""
            lines.append(f"- [{escape_md(result.title or result.url)}]({result.url}) - `{result.provider}`{snippet}")
    else:
        lines.append("- Nessun risultato motore di ricerca disponibile.")

    lines.extend(["", "## Pagine analizzate", ""])
    if investigation.pages:
        for page in investigation.pages[:40]:
            if page.error:
                lines.append(f"- [{escape_md(page.title or page.url)}]({page.url}) - non acquisita: {escape_md(page.error)}")
            else:
                description = f" - {escape_md(page.description[:160])}" if page.description else ""
                lines.append(f"- [{escape_md(page.title or page.url)}]({page.url}) - acquisita{description}")
    else:
        lines.append("- Nessuna pagina scaricata.")

    if investigation.agent_results:
        lines.extend(["", "## Stato agenti", ""])
        for result in investigation.agent_results:
            lines.append(f"- **{italian_agent_name(result.name)}**: {escape_md(result.summary)} (`{result.status}`)")
            note_limit = 30 if result.name == "external_tools" else 4
            for note in result.notes[:note_limit]:
                lines.append(f"  - {escape_md(note)}")

    lines.extend(["", "## Affidabilità delle evidenze (Admiralty)", ""])
    lines.extend(admiralty_summary_lines(investigation))

    lines.extend(["", "## Cosa abbiamo eseguito", ""])
    lines.extend(narrative_runbook(investigation))

    lines.extend(
        [
            "",
            "## Nota metodologica",
            "",
            "Questo report separa dati osservati e inferenze. Le evidenze vanno verificate manualmente prima di usarle",
            "in un contesto operativo, legale o investigativo. Per target personali o identificatori individuali applicare",
            "minimizzazione, autorizzazione esplicita e controllo delle omonimie.",
            "",
        ]
    )
    return "\n".join(lines)


def narrative_summary(
    investigation: Investigation,
    grouped: dict[str, list[Finding]],
    ok_pages: list,
    failed_pages: list,
) -> str:
    total = len(investigation.findings)
    if total == 0:
        return (
            f"La ricerca su **{escape_md(display_target(investigation))}** non ha prodotto ancora evidenze forti. "
            f"Sono state generate {len(investigation.queries)} query e sono state acquisite {len(ok_pages)} pagine, "
            f"mentre {len(failed_pages)} fonti non sono risultate accessibili o non erano HTML/testo. "
            "Il passo piu utile e configurare Bing API o aggiungere URL seed affidabili."
        )

    top_categories = ", ".join(label_kind(kind) for kind in list(grouped)[:5])
    return (
        f"La ricerca su **{escape_md(display_target(investigation))}** ha prodotto **{total} evidenze organizzate**. "
        f"Le aree piu rilevanti sono: {top_categories}. "
        f"Sono state acquisite {len(ok_pages)} pagine pubbliche e {len(investigation.search_results)} fonti/risultati iniziali. "
        "Il quadro va letto come una mappa investigativa: utile per orientare verifiche, non come attribuzione definitiva."
    )


def coverage_text(investigation: Investigation, ok_pages: list, failed_pages: list, external_notes: list[str]) -> str:
    provider_names = sorted({result.provider for result in investigation.search_results}) or ["nessun provider"]
    parts = [
        f"La raccolta ha usato questi provider o seed: **{', '.join(provider_names)}**.",
        f"Sono state preparate **{len(investigation.queries)} query** e sono state lette **{len(ok_pages)} pagine**.",
    ]
    if failed_pages:
        parts.append(f"**{len(failed_pages)} fonti** non sono state scaricate per errori rete, robots.txt o formato non testuale.")
    if external_notes:
        parts.append("Alcuni strumenti esterni risultano non installati o non configurati; la piattaforma li ha segnalati senza bloccare il report.")
    if not any(is_search_api_result(result.provider) for result in investigation.search_results):
        parts.append("Non risulta configurata una API di ricerca web: per copertura ampia imposta `BING_SEARCH_API_KEY` o un provider equivalente.")
    return " ".join(parts)


def query_lines(queries: list[str]) -> list[str]:
    if not queries:
        return ["- Nessuna query registrata."]
    lines = []
    for query in queries[:40]:
        lines.append(f"- `{escape_md(query)}`")
    if len(queries) > 40:
        lines.append(f"- Altre {len(queries) - 40} query nella versione JSON.")
    return lines


def section_for_kind(kind: str, findings: list[Finding]) -> list[str]:
    title = label_kind(kind).capitalize()
    lines = [f"### {title}", ""]
    intro = intro_for_kind(kind, findings)
    if intro:
        lines.extend([intro, ""])
    for finding in findings[:12]:
        lines.extend(format_finding_discursive(finding))
    if len(findings) > 12:
        lines.append(f"Sono presenti altre {len(findings) - 12} evidenze nella versione JSON.")
    lines.append("")
    return lines


def intro_for_kind(kind: str, findings: list[Finding]) -> str:
    label = label_kind(kind)
    if kind.startswith("external_"):
        return f"Gli strumenti esterni hanno prodotto {len(findings)} segnali. Trattali come output grezzo da confermare."
    if "opsec" in kind:
        return "Queste evidenze indicano possibili superfici esposte o riferimenti sensibili pubblici."
    if "socmint" in kind or "profile" in kind:
        return "Questi riferimenti possono indicare profili pubblici candidati; l'attribuzione richiede conferme indipendenti."
    return f"Sono state raccolte {len(findings)} evidenze nella categoria {label}."


def format_finding_discursive(finding: Finding) -> list[str]:
    confidence = confidence_label(finding.confidence)
    grade_code = f"{finding.source_reliability}{finding.info_credibility}"
    lines = [
        f"- **{escape_md(finding.value)}** — grado **{grade_code}** "
        f"— confidenza {confidence} (`{finding.confidence:.2f}`)."
    ]
    if finding.notes:
        lines.append(f"  {escape_md(finding.notes)}")
    for evidence in finding.evidence[:3]:
        label = escape_md(evidence.title or evidence.url)
        quote = f" Estratto: \"{escape_md(evidence.quote[:220])}\"" if evidence.quote else ""
        lines.append(f"  Fonte: [{label}]({evidence.url}).{quote}")
    return lines


def entity_graph_section(investigation: Investigation) -> list[str]:
    lines = ["## Entita e relazioni", ""]
    if not investigation.entities:
        lines.extend(["Nessuna entita normalizzata generata.", ""])
        return lines

    lines.append("### Entita normalizzate")
    lines.append("")
    shown_entities = display_entities(investigation)
    for entity in shown_entities[:25]:
        sources = f" - fonti: {len(entity.sources)}" if entity.sources else ""
        grade = f"{entity.source_reliability}{entity.info_credibility}"
        lines.append(
            f"- **{escape_md(entity.display_value or entity.value)}** (`{entity.type}`) "
            f"grado `{grade}` confidenza `{entity.confidence:.2f}`{sources}"
        )
    hidden_entities = len(investigation.entities) - min(len(shown_entities), 25)
    if hidden_entities > 0:
        lines.append(f"- Altre {hidden_entities} entita tecniche o di dettaglio nella versione JSON.")

    lines.extend(["", "### Relazioni principali", ""])
    if not investigation.relationships:
        lines.extend(["- Nessuna relazione strutturata.", ""])
        return lines
    entity_by_id = {entity.id: entity for entity in investigation.entities}
    shown_relationships = display_relationships(investigation, entity_by_id)
    for relation in shown_relationships[:25]:
        source = entity_by_id.get(relation.source)
        target = entity_by_id.get(relation.target)
        source_label = entity_label(source, relation.source)
        target_label = entity_label(target, relation.target)
        evidence = f"; fonte: {relation.evidence_url}" if relation.evidence_url else ""
        lines.append(
            f"- **{escape_md(source_label)}** -> **{escape_md(target_label)}** "
            f"(`{relation.kind}`, `{relation.confidence:.2f}`){escape_md(evidence)}"
        )
    hidden_relationships = len(investigation.relationships) - min(len(shown_relationships), 25)
    if hidden_relationships > 0:
        lines.append(f"- Altre {hidden_relationships} relazioni tecniche o di dettaglio nella versione JSON.")
    lines.append("")
    return lines


def display_entities(investigation: Investigation) -> list[Entity]:
    target = investigation.target.casefold().strip()
    entities = [entity for entity in investigation.entities if not is_utility_entity(entity, target)]
    return sorted(entities, key=lambda item: (item.attributes.get("role") != "target", item.type, item.value))


def display_relationships(investigation: Investigation, entity_by_id: dict[str, Entity]) -> list[Relationship]:
    target = investigation.target.casefold().strip()
    relationships = [
        relation
        for relation in investigation.relationships
        if not relationship_is_utility_only(relation, entity_by_id, target)
    ]
    priority = {"has_finding": 0, "mentions": 1, "observed_page": 2, "searched_or_seeded": 3, "links_to": 4, "hosted_on": 5}
    return sorted(relationships, key=lambda item: (priority.get(item.kind, 9), -item.confidence, item.evidence_url))


def relationship_is_utility_only(relation: Relationship, entity_by_id: dict[str, Entity], target: str) -> bool:
    source = entity_by_id.get(relation.source)
    target_entity = entity_by_id.get(relation.target)
    if relation.kind == "searched_or_seeded" and target_entity and is_utility_entity(target_entity, target):
        return True
    return any(entity and is_utility_entity(entity, target) for entity in (source, target_entity)) and relation.kind in {
        "hosted_on",
        "links_to",
        "searched_or_seeded",
    }


def is_utility_entity(entity: Entity, target: str) -> bool:
    value = entity.value.casefold()
    if value == target or value.removeprefix("www.") == target.removeprefix("www."):
        return False
    host = url_host(value) if entity.type == "url" else value
    return host in UTILITY_HOSTS


def url_host(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.casefold().removeprefix("www.")


def entity_label(entity: Entity | None, fallback: str) -> str:
    if not entity:
        return fallback
    return entity.display_value or entity.value


def operational_assessment(investigation: Investigation) -> str:
    kinds = {finding.kind for finding in investigation.findings}
    if any("opsec" in kind or "external_nmap" in kind for kind in kinds):
        return (
            "Il profilo ha valore operativo per una verifica autorizzata: emergono elementi da validare su esposizione, "
            "superficie pubblica o igiene OPSEC. Non ci sono prove sufficienti per azioni invasive; procedere con controlli manuali."
        )
    if any("socmint" in kind or "profile" in kind for kind in kinds):
        return (
            "Il profilo contiene indicatori social o identitari candidati. La priorita e evitare falsi positivi: confrontare fonti, date, "
            "contesto linguistico e relazioni pubbliche prima di concludere."
        )
    if investigation.findings:
        return "Il profilo e utile come base di ricognizione. La prossima fase dovrebbe aumentare copertura fonti e qualita delle citazioni."
    return "La copertura e ancora insufficiente per una valutazione forte. Serve configurare provider, seed o tool esterni."


def analytic_dossier(investigation: Investigation, grouped: dict[str, list[Finding]]) -> list[str]:
    lines = ["### Fatti osservati", ""]
    facts = observed_facts(grouped)
    lines.extend(facts or ["- Nessun fatto osservato strutturato: aumentare copertura con Bing API, URL seed o tool esterni."])
    lines.extend(["", "### Inferenze", ""])
    inferences = analytic_inferences(grouped)
    lines.extend(inferences or ["- Nessuna inferenza robusta: la raccolta non contiene ancora evidenze sufficienti."])
    lines.extend(["", "### Ipotesi operative", ""])
    lines.extend(operational_hypotheses(investigation, grouped))
    lines.append("")
    return lines


def observed_facts(grouped: dict[str, list[Finding]]) -> list[str]:
    facts: list[str] = []
    for kind, findings in grouped.items():
        for finding in findings[:3]:
            source = "output agente"
            if finding.evidence:
                first = finding.evidence[0]
                label = escape_md(first.title or first.url)
                source = f"[{label}]({first.url})"
            facts.append(
                f"- Fatto osservato: **{escape_md(finding.value)}** nella categoria "
                f"**{label_kind(kind)}**. Fonte primaria: {source}."
            )
            if len(facts) >= 12:
                return facts
    return facts


def analytic_inferences(grouped: dict[str, list[Finding]]) -> list[str]:
    inferences: list[str] = []
    for kind, findings in grouped.items():
        label = label_kind(kind)
        count = len(findings)
        if kind.startswith("external_"):
            inferences.append(
                f"- Inferenza: lo strumento **{label}** ha prodotto {count} segnali; trattarli come output tecnico da confermare."
            )
        elif "opsec" in kind:
            inferences.append(
                f"- Inferenza: la categoria **{label}** suggerisce una possibile superficie OPSEC pubblica da verificare manualmente."
            )
        elif kind == "agent_web_coverage":
            inferences.append(
                f"- Inferenza: la **{label}** descrive l'ampiezza e i limiti della raccolta; non prova da sola presenza, attribuzione o esposizione."
            )
        elif kind in {"related_domain", "web_presence"}:
            inferences.append(
                f"- Inferenza: le evidenze di **{label}** indicano una presenza web mappabile e utile per ricostruire il perimetro pubblico."
            )
        elif "profile" in kind or "socmint" in kind:
            inferences.append(
                f"- Inferenza: i riferimenti di **{label}** sono candidati, non attribuzioni definitive; servono riscontri indipendenti."
            )
        elif "geo" in kind:
            inferences.append(
                f"- Inferenza: i segnali di **{label}** forniscono contesto geografico pubblico, non prova autonoma di presenza fisica."
            )
        elif "crypto" in kind:
            inferences.append(
                f"- Inferenza: gli elementi **{label}** vanno confrontati con explorer pubblici e cronologia transazioni prima di attribuirli."
            )
        if len(inferences) >= 8:
            break
    return unique_lines(inferences)


def operational_hypotheses(investigation: Investigation, grouped: dict[str, list[Finding]]) -> list[str]:
    hypotheses: list[str] = []
    providers = {result.provider for result in investigation.search_results}
    kinds = set(grouped)
    if not any(is_search_api_result(provider) for provider in providers):
        hypotheses.append(
            "- Ipotesi operativa: il quadro e sottocampionato; configurare `BING_SEARCH_API_KEY` o aggiungere seed affidabili prima di trarre conclusioni."
        )
    if investigation.target_type in {"domain", "ip"}:
        hypotheses.append(
            "- Ipotesi operativa: per asset autorizzati, la priorita e confrontare sito ufficiale, sottodomini, archivi e superfici OPSEC pubbliche."
        )
    if investigation.target_type in {"person", "email", "handle", "phone"}:
        hypotheses.append(
            "- Ipotesi operativa: ogni corrispondenza personale va trattata come candidata fino a verifica di omonimie, date e contesto."
        )
    if investigation.target_type == "crypto" or any("crypto" in kind for kind in kinds):
        hypotheses.append(
            "- Ipotesi operativa: l'analisi crypto richiede conferma su explorer pubblici, cluster noti e timestamp, senza attribuzioni automatiche."
        )
    if investigation.target_type == "media" or any("media" in kind for kind in kinds):
        hypotheses.append(
            "- Ipotesi operativa: i metadati media aiutano la triage tecnica, ma non bastano da soli per attribuire autore, luogo o momento."
        )
    if not hypotheses:
        hypotheses.append(
            "- Ipotesi operativa: aumentare copertura fonti, poi rivedere manualmente le evidenze ad alta confidenza."
        )
    return hypotheses


def manual_verification_checklist(investigation: Investigation) -> list[str]:
    urls: list[tuple[str, str]] = []
    for finding in investigation.findings:
        for evidence in finding.evidence:
            urls.append((evidence.title or evidence.url, evidence.url))
            if len(urls) >= 8:
                break
        if len(urls) >= 8:
            break
    if not urls:
        urls = [(result.title or result.url, result.url) for result in investigation.search_results[:8]]
    if not urls:
        return [
            "- Nessuna fonte da verificare: aggiungere URL seed affidabili o configurare un provider di ricerca.",
            "",
        ]

    lines = [
        "- Per ogni fonte: aprire il link, annotare autore/data/titolo, salvare eventuale snapshot e segnare se conferma o smentisce il fatto collegato.",
    ]
    for title, url in urls:
        lines.append(f"- Verifica fonte: [{escape_md(title)}]({url}).")
    lines.append("")
    return lines


def recommended_next_steps(investigation: Investigation, external_notes: list[str]) -> list[str]:
    steps = [
        "Verificare manualmente le evidenze piu importanti aprendo le fonti citate.",
        "Aggiungere URL seed affidabili quando il motore di ricerca non restituisce risultati.",
        "Separare fatti osservati, inferenze e ipotesi operative nel fascicolo finale.",
    ]
    if external_notes:
        steps.insert(0, "Installare o configurare gli strumenti esterni segnalati come mancanti.")
    if not any(is_search_api_result(result.provider) for result in investigation.search_results):
        steps.insert(0, "Configurare `BING_SEARCH_API_KEY` per ricerche web ampie e ripetibili.")
    if investigation.target_type in {"domain", "ip"}:
        steps.append("Per red-team autorizzato, abilitare network scan solo su asset propri o con permesso scritto.")
    if investigation.target_type in {"person", "email", "handle", "phone"}:
        steps.append("Per identificatori personali, mantenere report redatti e controllare omonimie prima di qualsiasi conclusione.")
    return steps


def group_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in sorted(findings, key=lambda item: (kind_priority(item.kind), -item.confidence, item.value.casefold())):
        grouped[finding.kind].append(finding)
    return dict(grouped)


def kind_priority(kind: str) -> int:
    if kind.startswith("opsec") or kind.startswith("external"):
        return 0
    if kind in {"web_presence", "related_domain", "agent_web_coverage"}:
        return 1
    if "socmint" in kind or "profile" in kind:
        return 2
    if "geo" in kind or "crypto" in kind:
        return 3
    return 4


def label_kind(kind: str) -> str:
    if kind in KIND_LABELS:
        return KIND_LABELS[kind]
    if kind.startswith("external_"):
        return f"strumento {kind.removeprefix('external_')}"
    return kind.replace("_", " ")


def confidence_label(value: float) -> str:
    if value >= 0.75:
        return "alta"
    if value >= 0.5:
        return "media"
    return "bassa"


def is_search_api_result(provider: str) -> bool:
    return provider in {"bing", "brave", "serper"}


def unique_lines(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def admiralty_summary_lines(investigation: Investigation) -> list[str]:
    """Distribution of finding grades + a one-line analyst interpretation."""
    if not investigation.findings:
        return ["Nessuna evidenza registrata."]
    dist = grade_distribution(investigation.findings)
    total = sum(dist.values())
    # Group: gold (A1-B2), solid (B3-C2), candidate (C3-D4), weak (D5-F6)
    gold = sum(n for g, n in dist.items() if g in {"A1", "A2", "B1", "B2"})
    solid = sum(n for g, n in dist.items() if g in {"B3", "C1", "C2"})
    candidate = sum(n for g, n in dist.items() if g in {"C3", "D1", "D2", "D3", "D4"})
    weak = total - gold - solid - candidate
    parts = [
        f"Su **{total}** evidenze: **{gold}** gold (A1–B2), **{solid}** solide (B3–C2), "
        f"**{candidate}** candidate da verificare (C3–D4), **{weak}** deboli o non valutabili.",
        "",
        "Distribuzione per grado:",
    ]
    for code, n in sorted(dist.items()):
        parts.append(f"- `{code}` — {n} evidenza/e")
    parts.append("")
    parts.append(
        "Il grado segue lo standard Admiralty/NATO (STANAG 2511): la prima lettera è l'affidabilità della fonte (A=completamente affidabile, F=non valutabile), il numero è la credibilità dell'informazione (1=confermata, 6=non valutabile)."
    )
    return parts


def narrative_runbook(investigation: Investigation) -> list[str]:
    """A discursive paragraph that recounts which agents and tools ran, in IT.

    The previous version of the report listed everything as bullets. This
    produces flowing sentences instead — the analyst reads the *intent* of
    each phase, not a wall of CLI names. Empty agents are mentioned briefly.
    """
    if not investigation.agent_results:
        return ["Nessun agente eseguito: la pipeline si è fermata prima del dispatch."]

    sentences: list[str] = []
    agents = investigation.agent_results

    intro_bits = []
    for agent in agents:
        if agent.status == "ok" and agent.findings:
            intro_bits.append(_describe_agent_outcome(agent))
    if intro_bits:
        sentences.append("La pipeline ha completato " + _natural_join(intro_bits) + ".")
    else:
        sentences.append("La pipeline ha eseguito tutti gli agenti previsti, ma nessuno ha prodotto evidenze strutturate.")

    # Per-agent details with a focus on tools used (via notes).
    for agent in agents:
        sentences.append(_describe_agent_details(agent))

    # Skipped agents (status="skipped") get a single closing sentence so the
    # analyst knows what was intentionally NOT run.
    skipped = [a for a in agents if a.status == "skipped"]
    if skipped:
        names = _natural_join([AGENT_HUMAN_NAMES.get(a.name, a.name) for a in skipped])
        sentences.append(f"Sono stati saltati: {names} — verificare le opzioni `--confirm-authorization`, `--allow-darkweb` o l'idoneità del target.")

    return [s for s in sentences if s]


def _describe_agent_outcome(agent) -> str:
    label = AGENT_HUMAN_NAMES.get(agent.name, agent.name)
    n = len(agent.findings)
    if n == 1:
        return f"l'agente {label} con 1 evidenza"
    return f"l'agente {label} con {n} evidenze"


def _describe_agent_details(agent) -> str:
    label = AGENT_HUMAN_NAMES.get(agent.name, agent.name)
    summary = (agent.summary or "").strip()
    if not summary:
        summary = "ha completato senza output di sintesi"
    tools_mentioned: list[str] = []
    for note in agent.notes:
        for tool_id, human in TOOL_HUMAN_NAMES.items():
            if tool_id in note and human not in tools_mentioned:
                tools_mentioned.append(human)
    tools_suffix = ""
    if tools_mentioned:
        tools_suffix = f" Strumenti esterni invocati: {_natural_join(tools_mentioned)}."
    return f"**{label}** — {summary}{tools_suffix}"


def _natural_join(items: list[str]) -> str:
    items = [item for item in items if item]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} e {items[1]}"
    return ", ".join(items[:-1]) + f" e {items[-1]}"


def italian_agent_name(name: str) -> str:
    names = {
        "planner": "Pianificatore",
        "web": "Raccolta web",
        "external_tools": "Strumenti esterni",
        "opsec": "OPSEC",
        "crypto": "Crypto",
        "media": "Media",
        "geo": "Geolocalizzazione",
        "socmint": "SOCMINT",
        "phone": "Telefono",
        "darkweb": "Deep/dark web",
        "humint": "HUMINT",
    }
    return names.get(name, name)


def safe_stem(target: str) -> str:
    stem = re.sub(r"[^a-zA-Z0-9._-]+", "_", target.strip()).strip("._-")
    return stem[:80] or "report"


def display_target(investigation: Investigation) -> str:
    if investigation.target_type == "phone":
        return redact_phone(investigation.target)
    if investigation.target_type == "email":
        return redact_email(investigation.target)
    return investigation.target


def display_query(query: str, investigation: Investigation) -> str:
    if investigation.target_type in {"phone", "email"}:
        return query.replace(investigation.target, display_target(investigation))
    return query


def escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()
