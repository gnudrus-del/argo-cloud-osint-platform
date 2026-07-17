// Client API minimale verso il backend Python. Le chiamate passano dal proxy
// Next (/api/* -> ARGO_API_BASE) definito in next.config.mjs, quindi qui usiamo
// sempre path relativi. credentials:"include" propaga il cookie di sessione.

import type {
  Capabilities,
  CaseRecord,
  GraphData,
  Job,
} from "./types";
import { getCsrfToken, resetCsrfToken } from "./session";

// Metodi che il backend Python gate-a dietro il controllo CSRF
// (require_auth() in web.py confronta X-CSRF-Token contro session["csrf"]).
// GET/HEAD non lo richiedono.
const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (STATE_CHANGING_METHODS.has(method)) {
    headers["X-CSRF-Token"] = await getCsrfToken();
  }
  const res = await fetch(path, {
    credentials: "include",
    ...init,
    headers,
  });
  if (res.status === 403 && STATE_CHANGING_METHODS.has(method)) {
    // Il token in cache potrebbe essere di una sessione scaduta/ruotata —
    // scartalo così la prossima richiesta ne recupera uno fresco invece di
    // ripetere all'infinito lo stesso 403.
    resetCsrfToken();
  }
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body?.error || body?.message || "";
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

export const api = {
  capabilities: () => req<Capabilities>("/api/capabilities"),
  cases: () => req<{ cases: CaseRecord[] }>("/api/cases"),
  jobs: () => req<{ jobs: Job[] }>("/api/jobs"),
  job: (id: string) => req<Job>(`/api/jobs/${id}`),
  graph: (jobId: string) => req<GraphData>(`/api/graph/${jobId}`),
  plan: (payload: Record<string, unknown>) =>
    req<{ profile: Job & { agents: string[] } }>("/api/plan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createJob: (payload: Record<string, unknown>) =>
    req<Job>("/api/jobs", { method: "POST", body: JSON.stringify(payload) }),
  enrichText: (text: string) =>
    req<Record<string, unknown>>("/api/enrich/text", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
};

// Link diretti agli export (aperti in nuova tab, non serializzati come JSON).
export const links = {
  reportJson: (id: string) => `/api/jobs/${id}/report.json`,
  reportPdf: (id: string) => `/api/jobs/${id}/report.pdf`,
  forensicMd: (id: string) => `/api/jobs/${id}/forensic.md`,
  stix: (id: string) => `/api/jobs/${id}/stix.json`,
  misp: (id: string) => `/api/jobs/${id}/misp.json`,
};
