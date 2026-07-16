// Bootstrap CSRF per il client Next.js.
//
// Questa console non ha un proprio flusso di login: si appoggia al cookie di
// sessione emesso dal backend Python (`osint_bot/web.py`), propagato via
// `credentials: "include"`. Il token CSRF che il backend richiede su ogni
// richiesta che cambia stato (`X-CSRF-Token`, confrontato a tempo costante
// contro `session["csrf"]` — vedi `require_auth()` in web.py) va quindi
// recuperato separatamente, non deriva dal cookie stesso.
//
// `GET /api/auth/status` restituisce il token quando la sessione è già
// autenticata: lo richiediamo una volta e lo teniamo in cache in memoria per
// tutta la vita della pagina.

let csrfPromise: Promise<string> | null = null;

async function fetchCsrf(): Promise<string> {
  const res = await fetch("/api/auth/status", { credentials: "include" });
  if (!res.ok) {
    throw new Error(`Impossibile verificare la sessione (HTTP ${res.status}).`);
  }
  const data = (await res.json()) as { authenticated?: boolean; csrf?: string };
  if (!data.authenticated || !data.csrf) {
    throw new Error(
      "Sessione non autenticata. Accedi dalla web UI principale di Argo " +
        "(stesso dominio) prima di usare questa console — non ha un proprio login."
    );
  }
  return data.csrf;
}

/** Token CSRF per la sessione corrente, recuperato una sola volta e riusato. */
export function getCsrfToken(): Promise<string> {
  if (!csrfPromise) csrfPromise = fetchCsrf();
  return csrfPromise;
}

/**
 * Invalida il token in cache. Da chiamare dopo un 403 su una richiesta di
 * scrittura: il token potrebbe essere di una sessione scaduta/ruotata, la
 * prossima getCsrfToken() lo ri-recupera invece di ripetere lo stesso token
 * ormai invalido all'infinito.
 */
export function resetCsrfToken(): void {
  csrfPromise = null;
}
