// Dati mock che rispecchiano le forme di lib/types.ts — usati per
// intercettare le chiamate /api/* nei test e2e (Playwright page.route()),
// senza bisogno di un backend Python reale. Se lib/types.ts cambia forma,
// questi fixture vanno aggiornati di conseguenza (il typecheck lo segnala).

import type { CaseRecord, Capabilities, GraphData, Job } from "../lib/types";

// Token usato in tutti i test per verificare che venga propagato esattamente
// (non un valore qualsiasi, non un header assente).
export const CSRF_TOKEN = "e2e-csrf-token-12345";

export const AUTH_STATUS_AUTHENTICATED = {
  authenticated: true,
  csrf: CSRF_TOKEN,
};

// Sessione non autenticata: niente campo csrf, come farebbe il backend reale
// quando l'analista non ha ancora fatto login sulla web UI legacy.
export const AUTH_STATUS_UNAUTHENTICATED = {
  authenticated: false,
};

export const CAPABILITIES_FIXTURE: Capabilities = {
  agents: ["planner", "web", "opsec"],
  always_on_agents: ["planner", "web"],
  gated_agents: ["darkweb"],
  ai_enrichment: { ocr: true, ner: false },
  tools: [
    { name: "holehe", available: true },
    { name: "maigret", available: false, health_reason: "not installed" },
  ],
  search_providers: [{ name: "shodan", configured: true, env_var: "SHODAN_API_KEY" }],
  queue: { pending: 2 },
};

export const CASES_FIXTURE: CaseRecord[] = [
  {
    id: "case-1",
    title: "Caso di test",
    status: "open",
    owner: "analyst@example.com",
    purpose: "Verifica e2e",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    allowed_targets: ["example.com"],
  },
];

export const JOBS_FIXTURE: Job[] = [
  {
    id: "job-1234567890",
    status: "complete",
    target: "example.com",
    target_type: "domain",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    agents: ["planner", "web"],
  },
];

// Job "complete" così la pagina /graph/[jobId] fa anche la seconda fetch
// (api.graph) invece di fermarsi al solo polling dello stato.
export const JOB_COMPLETE_FIXTURE: Job = {
  id: "e2e-job-1",
  status: "complete",
  target: "example.com",
  target_type: "domain",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  agents: ["planner", "web", "opsec"],
  progress: [{ at: "2026-01-01T00:00:01Z", stage: "plan", message: "Piano generato" }],
};

export const GRAPH_FIXTURE: GraphData = {
  nodes: [
    {
      id: "n1",
      kind: "domain",
      label: "example.com",
      value: "example.com",
      confidence: 0.9,
      severity: "medium",
      degree: 2,
      sources: ["whois"],
    },
    {
      id: "n2",
      kind: "email",
      label: "a@example.com",
      value: "a@example.com",
      confidence: 0.7,
      severity: "low",
      degree: 1,
      sources: ["breach"],
    },
  ],
  links: [
    { id: "l1", source: "n1", target: "n2", kind: "related", confidence: 0.8, evidence_url: "https://example.com/evidence" },
  ],
  meta: {},
};

// Forma di risposta di POST /api/plan (api.plan in lib/api.ts si aspetta
// { profile: Job & { agents: string[] } }).
export const PLAN_RESPONSE_FIXTURE = {
  profile: {
    id: "job-preview",
    status: "planned",
    target: "example.com",
    target_type: "domain",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    agents: ["planner", "web", "opsec"],
  },
};
