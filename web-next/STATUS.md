# `web-next/` — status: **experimental, frozen**

This directory contains a Next.js frontend that was scaffolded as a
richer alternative to the Python-served web UI in
`osint_bot/web_static/`. **It is not the production frontend.**

## What is production

The user-facing web UI shipped with Argo is the one served by
`osint_bot/web` — the Python backend embeds its own static files
(`osint_bot/web_static/`) and is what runs behind Caddy on the demo
instance and inside the Docker image.

## What `web-next/` is

- A prototype that predates the current production UI.
- Missing pieces at the time of writing:
  - No CSRF token exchange on state-changing requests.
  - No wiring into the production Docker image / docker-compose.
  - No end-to-end tests.
  - No production-grade auth flow.
- Because it depends on `next` + `react`, npm audits and Dependabot
  activity here are load-bearing (a stale dep here can look critical
  in GitHub's dependency graph even though nothing production ships
  it).

## Why we keep it

1. It compiles and typechecks (validated in CI).
2. The `GraphView` component is a candidate for a future graph
   visualisation upgrade of the production UI.
3. Removing it would drop a working reference implementation of the
   Argo REST API against a modern React stack.

## Consuming this directory

Nothing outside `web-next/` imports anything inside it. Removing the
directory would not break the platform.

## Roadmap

Two mutually-exclusive tracks are on the roadmap:

- **A) Complete it.** Add CSRF, wire into `docker-compose.yml` as its
  own service, add e2e tests, promote to production frontend for
  visualisation-heavy views.
- **B) Delete it.** Extract the `GraphView` component into a small
  vanilla-JS bundle for `osint_bot/web_static/` and remove the whole
  Next.js surface.

The decision is tracked as issue `#H4`. It was not made before the
`v0.2` cut — `web-next/` remains frozen and undecided, and this file
is the current source of truth on its status until `#H4` closes.
