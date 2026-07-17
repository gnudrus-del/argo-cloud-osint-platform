// Helper condivisi per interceptare /api/* nei test e2e via page.route()
// (mock in-browser, nessun server Node/Express separato da tenere in sync
// con lib/types.ts — vedi web-next/STATUS.md per il perché di questa scelta).

import type { Page, Route } from "@playwright/test";

/** Registra una route che risponde sempre con lo stesso body JSON. */
export async function mockJson(
  page: Page,
  urlPattern: string | RegExp,
  body: unknown,
  status = 200
): Promise<void> {
  await page.route(urlPattern, async (route: Route) => {
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
}
