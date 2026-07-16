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
- Resolved since the gaps below were first written down:
  - **CSRF token exchange** — `lib/session.ts` fetches the token from
    `GET /api/auth/status` (this console has no login of its own; it
    rides the Python backend's session cookie) and `lib/api.ts`
    attaches it as `X-CSRF-Token` on every POST/PUT/PATCH/DELETE,
    matching `require_auth()`'s server-side check exactly. A `403`
    invalidates the cached token so the next call re-fetches instead
    of looping on a stale one.
  - **Docker wiring** — `web-next/Dockerfile` (multi-stage Node build)
    + a `web-next` service in the root `docker-compose.yml`, gated
    behind the `web-next` Compose profile (`docker compose --profile
    web-next up`) so it stays opt-in and a plain `docker compose up`
    behavior is unchanged.
  - **End-to-end tests** — `web-next/e2e/` (Playwright, `npm run
    test:e2e`) covers all four routes rendering without a client-side
    exception, the CSRF token being attached with its exact value on a
    state-changing call and that call being rejected when
    `/api/auth/status` comes back unauthenticated, the reset-on-403
    re-fetch actually triggering a fresh token fetch, and the Sidebar
    links routing to the right pages. Every `/api/*` call is mocked
    in-browser via Playwright's `page.route()`, so no real Python
    backend is needed; it runs as a step in the `web-next` CI job right
    after the build.
- Still missing:
  - No production-grade auth flow of its own (by design — see CSRF
    note above; this console is not meant to run without the Python
    backend already up and an analyst already logged into it).
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

- **A) Complete it.** CSRF and Docker wiring are done (see above); e2e
  tests and promotion to production frontend for visualisation-heavy
  views are not.
- **B) Delete it.** Extract the `GraphView` component into a small
  vanilla-JS bundle for `osint_bot/web_static/` and remove the whole
  Next.js surface.

The decision between finishing track A the rest of the way versus
switching to track B is tracked as issue `#H4` and is **still open** —
closing the CSRF/Docker gaps was a prerequisite for either track (an
unauthenticated or undeployable prototype isn't a fair basis for
deciding whether to invest further or cut it), not a decision that
`web-next/` is now the production frontend. It stays frozen (opt-in
Compose profile, not part of `docker compose up` by default; not
linked from anywhere in `osint_bot/web_static/`) until `#H4` closes.
