import { defineConfig, devices } from "@playwright/test";

// Config e2e minimale per il prototipo web-next: un solo browser (chromium
// — coerente con `npx playwright install --with-deps chromium`), nessun
// backend Python reale. Ogni test intercetta le proprie /api/* via
// page.route() (vedi e2e/helpers.ts e e2e/fixtures.ts), quindi il webServer
// qui sotto serve solo a servire l'HTML/JS del frontend.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  use: {
    baseURL: "http://localhost:3000",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  webServer: {
    // In CI lo step "Build" gira già prima nel job web-next, quindi `npm run
    // start` riusa quell'output (più veloce, più vicino a produzione). In
    // locale usiamo `next dev` così `npm run test:e2e` funziona anche da un
    // checkout pulito senza dover buildare a mano prima.
    command: process.env.CI ? "npm run start" : "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
