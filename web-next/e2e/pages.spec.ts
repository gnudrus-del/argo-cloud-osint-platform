// Smoke test per le quattro route dell'app: ognuna deve renderizzare senza
// eccezioni client-side, con /api/auth/status mockato come autenticato (il
// setup che il task richiede in modo uniforme, anche per le pagine che non
// lo chiamano al mount — solo /search lo usa, e solo on-demand al click).
import { test, expect } from "@playwright/test";
import {
  AUTH_STATUS_AUTHENTICATED,
  CAPABILITIES_FIXTURE,
  CASES_FIXTURE,
  GRAPH_FIXTURE,
  JOBS_FIXTURE,
  JOB_COMPLETE_FIXTURE,
} from "./fixtures";
import { mockJson } from "./helpers";

test.describe("route smoke tests", () => {
  test.beforeEach(async ({ page }) => {
    await mockJson(page, "**/api/auth/status", AUTH_STATUS_AUTHENTICATED);
  });

  test("/ (dashboard) renders without a client-side exception", async ({ page }) => {
    await mockJson(page, "**/api/capabilities", CAPABILITIES_FIXTURE);
    await mockJson(page, "**/api/jobs", { jobs: JOBS_FIXTURE });

    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    // I dati del mock sono arrivati e sono stati renderizzati (job più recente).
    await expect(page.getByText("example.com")).toBeVisible();
    expect(pageErrors).toEqual([]);
  });

  test("/cases renders without a client-side exception", async ({ page }) => {
    await mockJson(page, "**/api/cases", { cases: CASES_FIXTURE });

    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto("/cases");

    await expect(page.getByRole("heading", { name: "Casi" })).toBeVisible();
    await expect(page.getByText("Caso di test")).toBeVisible();
    expect(pageErrors).toEqual([]);
  });

  test("/search renders without a client-side exception", async ({ page }) => {
    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto("/search");

    await expect(page.getByRole("heading", { name: "Nuova ricerca" })).toBeVisible();
    expect(pageErrors).toEqual([]);
  });

  test("/graph/[jobId] renders without a client-side exception (mocked graph data)", async ({ page }) => {
    await mockJson(page, `**/api/jobs/${JOB_COMPLETE_FIXTURE.id}`, JOB_COMPLETE_FIXTURE);
    await mockJson(page, `**/api/graph/${JOB_COMPLETE_FIXTURE.id}`, GRAPH_FIXTURE);

    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto(`/graph/${JOB_COMPLETE_FIXTURE.id}`);

    await expect(page.locator("h1")).toContainText("Job");
    // Smoke check soltanto: la pagina ha ricevuto e renderizzato il grafo
    // mockato (conteggio nodi/relazioni). Non testiamo il rendering interno
    // di react-force-graph-2d — è una libreria di terze parti, fuori scope.
    await expect(page.getByText(`${GRAPH_FIXTURE.nodes.length} nodi`)).toBeVisible({ timeout: 15_000 });
    expect(pageErrors).toEqual([]);
  });
});
