from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agents import AgentContext, run_agents
from .analyze import analyze
from .discovery import automatic_seed_results
from .dorks import build_dorks, dork_results
from .entities import enrich_investigation_entities
from .explainability import enrich_investigation_explanations
from .external_tools import available_tools
from .fetch import FetchConfig, Fetcher
from .grading import apply_default_grades, level_breakdown
from .high_risk import detect_high_risk
from .models import Investigation, SearchResult
from .orchestrator import plan_from_command
from .report import save_report
from .safety import SafetyError, assess_request
from .search import SearchConfig, SearchError, build_queries, dedupe_results, search_many
from .service_links import service_link_results

TARGET_TYPES = ("domain", "company", "org", "person", "handle", "email", "phone", "crypto", "ip", "media")
AGENTS = ("all", "planner", "web", "external", "opsec", "crypto", "media", "geo", "socmint", "phone", "darkweb", "humint")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-bot",
        description="Defensive OSINT bot that writes sourced Markdown and JSON reports.",
    )
    parser.add_argument("target", nargs="?", default="", help="Dominio, azienda, handle, email o persona autorizzata da analizzare.")
    parser.add_argument("--type", choices=TARGET_TYPES, default="company", help="Tipo di target.")
    parser.add_argument("--command", help="Comando naturale: il bot sceglie target, agenti e tool compatibili.")
    parser.add_argument("--depth", type=int, choices=(1, 2, 3), default=1, help="Ampiezza del piano query.")
    parser.add_argument("--provider", choices=("all", "auto", "bing", "brave", "serper", "none"), default="all")
    parser.add_argument("--seed-url", action="append", default=[], help="URL pubblico di partenza; ripetibile.")
    parser.add_argument("--max-results", type=int, default=10, help="Risultati massimi per query.")
    parser.add_argument("--max-pages", type=int, default=12, help="Pagine HTML massime da scaricare.")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout rete in secondi.")
    parser.add_argument("--output-dir", default="reports", help="Directory report.")
    parser.add_argument("--format", choices=("both", "markdown", "json"), default="both")
    parser.add_argument("--agent", action="append", choices=AGENTS, default=None, help="Agente da eseguire; ripetibile.")
    parser.add_argument(
        "--external-tool",
        action="append",
        choices=available_tools(),
        default=[],
        help="Tool OSINT locale da eseguire tramite wrapper policy; ripetibile.",
    )
    parser.add_argument(
        "--allow-network-scan",
        action="store_true",
        help="Consente nmap solo su asset propri o esplicitamente autorizzati.",
    )
    parser.add_argument(
        "--allow-darkweb",
        action="store_true",
        help="Abilita agent dark/deep web solo per monitoraggio difensivo con fonti seed autorizzate.",
    )
    parser.add_argument("--include-contact", action="store_true", help="Non redigere email pubbliche.")
    parser.add_argument(
        "--confirm-authorization",
        action="store_true",
        help="Conferma che il target personale e autorizzato o di pubblico interesse.",
    )
    parser.add_argument(
        "--case-id",
        default=None,
        help=(
            "ID di un caso creato via web UI/API. Se impostato, ogni tool esterno e "
            "connettore invocato da questa run passa dal gate RoE/scope dello stesso "
            "caso (stessa policy della web UI, non solo i flag --confirm-authorization/ "
            "--allow-network-scan/--allow-darkweb qui sotto). Senza --case-id il "
            "comportamento resta quello storico della CLI: nessun controllo di scope "
            "dichiarato, solo i flag di consenso espliciti."
        ),
    )
    parser.add_argument(
        "--actor",
        default="",
        help="Nome analista da registrare nella catena audit per le azioni gated da --case-id.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Fase 6 — HighRiskResearchMode: stessi vincoli compliance della UI web.
    # Stampa banner e ragioni PRIMA di eseguire, cosi' l'operatore sa in che
    # modalita' sta lavorando e puo' interrompere se non e' quel che voleva.
    _print_opsec_banner_if_needed(args)

    try:
        markdown_path, json_path = run_investigation(args)
    except (SafetyError, SearchError) as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 2

    if markdown_path:
        print(f"Markdown: {markdown_path}")
    if json_path:
        print(f"JSON: {json_path}")
    return 0


def _print_opsec_banner_if_needed(args: argparse.Namespace) -> None:
    """Stampa il banner OPSEC se la ricerca attiva HighRiskResearchMode."""
    ctx = detect_high_risk(
        target=args.target or "",
        target_type=args.type or "",
        command=getattr(args, "command", "") or "",
        modules=[],  # CLI usa --agent, non modules; allow_darkweb e' gia' coperto sotto
        allow_darkweb=bool(getattr(args, "allow_darkweb", False)),
        seed_urls=list(getattr(args, "seed_url", []) or []),
    )
    if not ctx.active:
        return
    print("=" * 70, file=sys.stderr)
    print("🛡  " + ctx.banner, file=sys.stderr)
    print("Motivi di attivazione:", file=sys.stderr)
    for r in ctx.reasons:
        print(f"  - {r}", file=sys.stderr)
    print("Restrizioni applicate:", file=sys.stderr)
    for key, label in ctx.restrictions[:6]:
        print(f"  · {label}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


def _print_evidence_breakdown(findings) -> None:
    """Stampa la classificazione operativa dei finding (Fase 6).

    Distingue dato verificato / probabile / non verificato / non disponibile,
    cosi' l'operatore CLI ha gli stessi 4 livelli della piattaforma web.
    """
    if not findings:
        return
    levels = level_breakdown(findings)
    print("Livelli di affidabilita' (Admiralty -> operativi):", file=sys.stderr)
    print(f"  ✓ verificato      : {levels['verificato']}", file=sys.stderr)
    print(f"  ~ probabile       : {levels['probabile']}", file=sys.stderr)
    print(f"  ? non_verificato  : {levels['non_verificato']}", file=sys.stderr)
    print(f"  - non_disponibile : {levels['non_disponibile']}", file=sys.stderr)


def run_investigation(args: argparse.Namespace) -> tuple[Path | None, Path | None]:
    if getattr(args, "command", None):
        profile = plan_from_command(
            args.command,
            target=args.target,
            target_type=args.type if args.type != "company" else "",
            confirm_authorization=args.confirm_authorization,
            allow_network_scan=args.allow_network_scan,
            allow_darkweb=args.allow_darkweb,
        )
        args.target = profile.target
        args.type = profile.target_type
        args.agent = profile.agents
        args.external_tool = profile.external_tools
        args.seed_url = [*args.seed_url, *profile.seed_urls]
        args.depth = max(args.depth, profile.depth)
        args.max_pages = max(args.max_pages, profile.max_pages)

    if not args.target:
        raise SafetyError("Specifica un target oppure usa --command con un comando da cui inferirlo.")

    decision = assess_request(args.target, args.type, args.confirm_authorization)
    queries = build_queries(args.target, args.type, args.depth)
    dorks = build_dorks(args.target, args.type, args.depth)
    all_queries = [*queries, *dorks]
    api_keys = dict(getattr(args, "api_keys", {}) or {})
    search_results = search_many(
        queries,
        SearchConfig(
            provider=args.provider,
            max_results=args.max_results,
            timeout=args.timeout,
            api_keys=api_keys,
        ),
    )

    manual_results = [SearchResult(title=url, url=url, provider="manual") for url in args.seed_url]
    seed_results = automatic_seed_results(args.target, args.type)
    service_results = service_link_results(args.target, args.type)
    all_results = dedupe_results([*manual_results, *seed_results, *dork_results(dorks), *service_results, *search_results])

    fetcher = Fetcher(FetchConfig(timeout=args.timeout, proxy_url=getattr(args, "proxy_url", "")))
    pages = []
    skipped = []
    for result in all_results:
        if len(pages) >= args.max_pages:
            break
        if result.provider.endswith("_dork") or result.provider.endswith("_link"):
            continue
        page = fetcher.fetch(result.url)
        if page.error and page.error == "Bloccato da robots.txt.":
            skipped.append(result.url)
        pages.append(page)

    findings = analyze(args.target, args.type, all_results, pages, args.include_contact)
    agent_results = run_agents(
        AgentContext(
            target=args.target,
            target_type=args.type,
            confirm_authorization=args.confirm_authorization,
            include_contact=args.include_contact,
            allow_network_scan=args.allow_network_scan,
            allow_darkweb=args.allow_darkweb,
            search_results=all_results,
            pages=pages,
            external_tools=args.external_tool,
            timeout=args.timeout,
            case_id=getattr(args, "case_id", None),
            actor=getattr(args, "actor", ""),
        ),
        args.agent or ["all"],
    )
    findings.extend(finding for result in agent_results for finding in result.findings)
    # Pillar 0.5: back-fill Admiralty grades for findings that didn't set one
    # explicitly. Agents that already graded their findings are not overwritten.
    apply_default_grades(findings)
    investigation = Investigation.create(
        target=args.target,
        target_type=args.type,
        safety_note=decision.note,
        queries=all_queries,
        search_results=all_results,
        pages=pages,
        findings=findings,
        agent_results=agent_results,
        skipped_urls=skipped,
    )
    enrich_investigation_entities(investigation)
    # Fase 7 — spiegabilita': perche' collegato + cosa manca per confermare.
    enrich_investigation_explanations(investigation)

    # Fase 6 — breakdown operativo dei finding (verificato/probabile/...).
    _print_evidence_breakdown(findings)

    return save_report(investigation, Path(args.output_dir), args.format)


if __name__ == "__main__":
    raise SystemExit(main())
