# Argo OSINT — Frontend Next.js

Console operativa moderna (Next.js 14 App Router + React 18 + TypeScript) che
parla con il backend Python esistente (`osint_bot.web`) via proxy.

## Cosa include

- **Dashboard** (`/`): conteggi live di agenti, tool, provider, AI locale, coda.
- **Casi** (`/cases`): elenco casi con scope autorizzato e base giuridica.
- **Ricerca** (`/search`): anteprima piano (agenti attivi) + avvio job.
- **Grafo** (`/graph/[jobId]`): visualizzazione force-directed entità-relazioni
  (`react-force-graph-2d`), polling stato job, export PDF/JSON/Forensic/STIX/MISP.

Il frontend NON duplica la logica: consuma le API già esposte dal backend
(`/api/capabilities`, `/api/cases`, `/api/jobs`, `/api/plan`, `/api/graph/:id`,
`/api/jobs/:id/{report,forensic,stix,misp}`).

## Avvio in sviluppo

```bash
cd web-next
cp .env.local.example .env.local     # imposta ARGO_API_BASE se il backend non è su :8765
npm install
npm run dev                          # http://localhost:3000
```

Il backend Python deve girare in parallelo:

```bash
python -m osint_bot.web --port 8765
```

Le chiamate `/api/*` dal frontend vengono proxy-ate su `ARGO_API_BASE`
(default `http://127.0.0.1:8765`) — vedi `next.config.mjs`. Il cookie di
sessione del backend viaggia con `credentials: "include"`, quindi
l'autenticazione resta quella del backend legacy.

## Build produzione

```bash
npm run build && npm run start       # SSR su :3000
# oppure dietro lo stesso reverse proxy (Caddy) del backend, path /console
```

## Type-check

```bash
npm run typecheck
```

## Rapporto con il frontend legacy

Il frontend classico in `osint_bot/web_static/` resta invariato e servito dal
backend. Questo scaffold è il percorso di migrazione verso una SPA moderna:
si può adottare pagina per pagina senza toccare l'API.
