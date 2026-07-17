// Verifica che i link della Sidebar puntino davvero alla pagina giusta
// (Dashboard / Casi / Ricerca — /graph/[jobId] è dinamica e non compare in
// components/Sidebar.tsx, quindi non c'è nulla da testare lì).
import { test, expect } from "@playwright/test";
import { AUTH_STATUS_AUTHENTICATED, CAPABILITIES_FIXTURE, CASES_FIXTURE, JOBS_FIXTURE } from "./fixtures";
import { mockJson } from "./helpers";

test.describe("sidebar navigation", () => {
  test.beforeEach(async ({ page }) => {
    await mockJson(page, "**/api/auth/status", AUTH_STATUS_AUTHENTICATED);
    await mockJson(page, "**/api/capabilities", CAPABILITIES_FIXTURE);
    await mockJson(page, "**/api/jobs", { jobs: JOBS_FIXTURE });
    await mockJson(page, "**/api/cases", { cases: CASES_FIXTURE });
  });

  test("Dashboard / Casi / Ricerca links route to the right pages", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL("/");
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

    // Scope alla <nav> della Sidebar: la pagina /cases ha anche un link
    // "Nuova ricerca nel caso" il cui nome accessibile contiene "Ricerca"
    // come sottostringa e farebbe fallire un getByRole non scoped (strict
    // mode violation — trovato mentre scrivevo questo test).
    const sidebarNav = page.locator("aside nav");

    await sidebarNav.getByRole("link", { name: "Casi" }).click();
    await expect(page).toHaveURL(/\/cases$/);
    await expect(page.getByRole("heading", { name: "Casi" })).toBeVisible();

    await sidebarNav.getByRole("link", { name: "Ricerca" }).click();
    await expect(page).toHaveURL(/\/search$/);
    await expect(page.getByRole("heading", { name: "Nuova ricerca" })).toBeVisible();

    await sidebarNav.getByRole("link", { name: "Dashboard" }).click();
    await expect(page).toHaveURL("/");
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  });
});
