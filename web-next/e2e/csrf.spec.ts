// Copertura della parte security-sensitive appena arrivata su questo branch:
// lib/session.ts (getCsrfToken/resetCsrfToken) + lib/api.ts (req(), che
// allega X-CSRF-Token a ogni POST/PUT/PATCH/DELETE e invalida il token
// cache su un 403). Zero copertura di test prima di questo file.
//
// Il trigger UI usato è il bottone "Anteprima piano" nella pagina /search,
// che chiama api.plan(...) — l'unica azione che cambia stato raggiungibile
// da UI senza dover anche seguire una navigazione post-successo.
import { test, expect, type Page } from "@playwright/test";
import {
  AUTH_STATUS_AUTHENTICATED,
  AUTH_STATUS_UNAUTHENTICATED,
  CSRF_TOKEN,
  PLAN_RESPONSE_FIXTURE,
} from "./fixtures";
import { mockJson } from "./helpers";

async function fillTargetAndPreview(page: Page) {
  await page.goto("/search");
  await page.getByPlaceholder(/example\.com/).fill("example.com");
  await page.getByRole("button", { name: "Anteprima piano" }).click();
}

test.describe("CSRF flow", () => {
  test("attaches the exact CSRF token from /api/auth/status to a state-changing request", async ({ page }) => {
    await mockJson(page, "**/api/auth/status", AUTH_STATUS_AUTHENTICATED);

    const csrfHeaders: (string | undefined)[] = [];
    await page.route("**/api/plan", async (route) => {
      csrfHeaders.push(route.request().headers()["x-csrf-token"]);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(PLAN_RESPONSE_FIXTURE),
      });
    });

    await fillTargetAndPreview(page);

    await expect(page.getByText("Piano automatico")).toBeVisible();
    expect(csrfHeaders).toEqual([CSRF_TOKEN]);
  });

  test("an unauthenticated auth/status response rejects the call instead of sending no header", async ({ page }) => {
    await mockJson(page, "**/api/auth/status", AUTH_STATUS_UNAUTHENTICATED);

    let planWasCalled = false;
    await page.route("**/api/plan", async (route) => {
      planWasCalled = true;
      await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });

    await fillTargetAndPreview(page);

    // getCsrfToken() lancia prima ancora che req() esegua il fetch verso
    // /api/plan: nessuna richiesta parte, niente header mancante silenzioso.
    await expect(page.getByText(/Sessione non autenticata/)).toBeVisible();
    expect(planWasCalled).toBe(false);
  });

  test("a 403 on a state-changing request forces the next one to re-fetch the CSRF token", async ({ page }) => {
    let authCalls = 0;
    await page.route("**/api/auth/status", async (route) => {
      authCalls += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ authenticated: true, csrf: `csrf-token-${authCalls}` }),
      });
    });

    let planCalls = 0;
    const csrfHeaders: (string | undefined)[] = [];
    await page.route("**/api/plan", async (route) => {
      planCalls += 1;
      csrfHeaders.push(route.request().headers()["x-csrf-token"]);
      if (planCalls === 1) {
        await route.fulfill({
          status: 403,
          contentType: "application/json",
          body: JSON.stringify({ error: "CSRF non valido" }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(PLAN_RESPONSE_FIXTURE),
        });
      }
    });

    await page.goto("/search");
    await page.getByPlaceholder(/example\.com/).fill("example.com");
    const previewButton = page.getByRole("button", { name: "Anteprima piano" });

    // Primo tentativo: il backend rifiuta con 403 -> resetCsrfToken() viene
    // invocato in lib/api.ts, l'errore arriva in UI.
    await previewButton.click();
    await expect(page.getByText("CSRF non valido")).toBeVisible();

    // Secondo tentativo: senza resetCsrfToken() questo riuserebbe per sempre
    // il token scaduto (niente nuova GET /api/auth/status, stesso header).
    // Con il fix in lib/session.ts deve ri-recuperare un token fresco.
    await previewButton.click();
    await expect(page.getByText("Piano automatico")).toBeVisible();

    expect(authCalls).toBe(2);
    expect(csrfHeaders).toEqual(["csrf-token-1", "csrf-token-2"]);
  });
});
