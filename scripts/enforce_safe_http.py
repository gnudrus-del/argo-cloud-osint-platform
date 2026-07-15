#!/usr/bin/env python3
"""CI check: enforce that outbound HTTP goes through _safe_http.

Rule: no module under osint_bot/ may import a bare HTTP client
(urllib.request, http.client, httpx, requests, aiohttp) UNLESS it is
one of the following allow-listed files:

  * osint_bot/_safe_http.py            — the sanctioned gateway itself
  * osint_bot/tools/*.py               — vendored third-party tools
  * files that only reference the module inside a comment or a string

The check catches direct imports (import statements). It does NOT
catch dynamic imports via importlib — those are exceedingly rare in
the codebase and reviewed manually.

Existing connectors that predate this rule are enumerated in the
GRANDFATHERED set below with an issue reference; each of them is
tracked for migration to _safe_http and must be removed from the set
after migration. New code paths MUST NOT be added to GRANDFATHERED.
"""
from __future__ import annotations

import ast
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CONNECTORS_DIR = REPO_ROOT / "osint_bot" / "connectors"

# Non-connector modules that also perform outbound HTTP against an
# analyst-or-operator-supplied URL (as opposed to a fixed, internal
# service endpoint) and must therefore be covered by the same guard.
# Do NOT add internal-service clients here (neo4j_sync.py,
# opensearch_index.py, provider_health.py, ...): those legitimately talk
# to operator-configured private-network endpoints that guard_ssrf's
# default RFC1918/loopback block would break.
EXTRA_SCAN_FILES = [
    REPO_ROOT / "osint_bot" / "fetch.py",
    REPO_ROOT / "osint_bot" / "llm_client.py",
    REPO_ROOT / "osint_bot" / "tsa_client.py",
]

# Modules whose direct import from a connector triggers the guard.
BANNED_MODULES = {
    "urllib.request",
    "http.client",
    "httpx",
    "requests",
    "aiohttp",
}

# Files exempted from the guard because they legitimately talk to the
# network via lower-level primitives (the _safe_http gateway itself,
# vendored tools, health probes bound to localhost, etc.).
ALLOWLIST_PATHS = {
    "osint_bot/_safe_http.py",
}

# EMPTY — the migration is complete. Every connector now routes outbound
# HTTP through _safe_http (which applies guard_ssrf on the initial URL and
# on every redirect). This set MUST stay empty: a new entry would mean a
# connector regressed to a direct urllib/httpx/requests/aiohttp call and
# bypassed the SSRF gateway. Fix the connector instead of adding it here —
# use _safe_http.get_json(...) / get_text(...) / post_json(...) / open_url(...).
GRANDFATHERED: set[str] = set()


def _iter_python_files(root: pathlib.Path):
    for path in root.rglob("*.py"):
        if any(part.startswith(".") for part in path.parts):
            continue
        yield path


def _iter_scan_targets():
    yield from _iter_python_files(CONNECTORS_DIR)
    for path in EXTRA_SCAN_FILES:
        if path.is_file():
            yield path


def _module_imports(source: str) -> set[str]:
    """Return the set of fully-qualified module names imported."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
    return imports


def _rel(path: pathlib.Path) -> str:
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def check() -> int:
    violations: list[tuple[str, set[str]]] = []
    seed_candidates: set[str] = set()

    for path in _iter_scan_targets():
        rel = _rel(path)
        if rel in ALLOWLIST_PATHS:
            continue
        imports = _module_imports(path.read_text(encoding="utf-8"))
        banned = imports & BANNED_MODULES
        if not banned:
            continue
        if rel in GRANDFATHERED:
            # Existing debt — allowed for now, tracked in #H2.
            continue
        violations.append((rel, banned))
        seed_candidates.add(rel)

    if violations:
        print("SSRF guard: violations detected", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for rel, banned in sorted(violations):
            print(f"  {rel}", file=sys.stderr)
            for mod in sorted(banned):
                print(f"    imports banned module: {mod}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Rule: outbound HTTP must go through osint_bot._safe_http.", file=sys.stderr)
        print("      Use guard_ssrf(url) before opening a connection, or", file=sys.stderr)
        print("      the get_json()/get_text() helpers exported from _safe_http.", file=sys.stderr)
        print("", file=sys.stderr)
        print("If this is legacy connector code, add its path to", file=sys.stderr)
        print("GRANDFATHERED in scripts/enforce_safe_http.py and open an", file=sys.stderr)
        print("issue against #H2 to plan its migration.", file=sys.stderr)
        return 1

    print(f"SSRF guard: OK ({sum(1 for _ in _iter_scan_targets())} files scanned, "
          f"{len(GRANDFATHERED)} grandfathered).")
    return 0


def _seed() -> int:
    """Print an initial GRANDFATHERED set. Used to bootstrap the check."""
    entries: set[str] = set()
    for path in _iter_scan_targets():
        rel = _rel(path)
        if rel in ALLOWLIST_PATHS:
            continue
        imports = _module_imports(path.read_text(encoding="utf-8"))
        if imports & BANNED_MODULES:
            entries.add(rel)
    print("GRANDFATHERED = {")
    for e in sorted(entries):
        print(f'    "{e}",')
    print("}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--seed":
        raise SystemExit(_seed())
    raise SystemExit(check())
