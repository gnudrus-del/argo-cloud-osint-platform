// Regression check (run: `node tests/js/dashboard_frontend.test.js`).
//
// Proves the dashboard is SERVER-BACKED: loadDashboard() must render from the
// /api/dashboard payload and must NOT depend on client-side caches
// (state.jobs / state.cases / state._lastCaps). We poison those caches with
// misleading values and assert the rendered DOM reflects the backend, not them.
//
// There is no JS test runner wired into this Python project; this is a
// standalone Node smoke/regression check kept alongside the backend tests.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const appPath = path.join(__dirname, "..", "..", "osint_bot", "web_static", "app.js");
const src = fs.readFileSync(appPath, "utf8");

// --- DOM stub that RECORDS innerHTML/textContent per element id ---------------
const store = {};            // id -> { innerHTML, textContent }
function el(id) {
  const node = {
    _id: id,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    style: {}, dataset: {}, options: [],
    addEventListener() {}, removeEventListener() {}, focus() {},
    appendChild() {}, insertAdjacentHTML() {}, setAttribute() {},
    querySelector() { return el(id + ":q"); }, querySelectorAll() { return []; },
    set innerHTML(v) { if (id) store[id] = Object.assign(store[id] || {}, { innerHTML: v }); },
    get innerHTML() { return (store[id] || {}).innerHTML || ""; },
    set textContent(v) { if (id) store[id] = Object.assign(store[id] || {}, { textContent: String(v) }); },
    get textContent() { return (store[id] || {}).textContent || ""; },
    set value(v) {}, get value() { return ""; },
  };
  return node;
}
const elById = {};
const document = {
  getElementById(id) { return (elById[id] = elById[id] || el(id)); },
  querySelector() { return el(""); },
  querySelectorAll() { return []; },
  createElement() { return el(""); },
  body: el("body"), documentElement: el("html"),
};
const localStorage = { getItem() { return null; }, setItem() {} };
// Default fetch (used by boot()): not authenticated => boot exits early.
// NB: api() reads response.text() then JSON.parse — so stubs return JSON as text.
let fetchImpl = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ authenticated: false, signup_enabled: false }) });
function fetch(...a) { return fetchImpl(...a); }

const sandbox = { document, localStorage, fetch, window: {}, console, URL,
  setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0 };
vm.createContext(sandbox);
vm.runInContext(src, sandbox, { filename: "app.js" });

// --- the backend payload we expect to be rendered ----------------------------
const PAYLOAD = {
  stats: { queued: 1, running: 2, complete: 5, error: 3 },
  totals: { cases: 4, jobs: 11 },
  coverage: { providers_configured: 7, providers_total: 15, tools_available: 9, tools_total: 59 },
  warnings: [{ level: "warning", message: "Caso «X» senza base giuridica chiara." }],
  recent_cases: [{ id: "abc", title: "Caso BACKEND", status: "open", legal_basis: "contract" }],
  recent_jobs: [{ id: "def", title: "t", target: "backend.example", target_type: "domain", status: "complete", updated_at: "2026-06-29" }],
  cases_select: [{ id: "abc", title: "Caso BACKEND" }, { id: "ghi", title: "Caso 2" }],
};

let failures = 0;
function assert(name, cond) { console.log((cond ? "PASS" : "FAIL") + ": " + name); if (!cond) failures++; }

(async () => {
  // Serve the backend payload for /api/dashboard.
  fetchImpl = async (urlPath) => {
    if (String(urlPath).includes("/api/dashboard")) {
      return { ok: true, status: 200, text: async () => JSON.stringify(PAYLOAD) };
    }
    return { ok: true, status: 200, text: async () => "{}" };
  };

  // POISON the client caches (inside the VM context, where `state` lives) with
  // values that, if the dashboard used them, would NOT match PAYLOAD. Then run
  // loadDashboard in the same context.
  await vm.runInContext(`(async () => {
    state.jobs = [{ status: "complete", profile: { target: "CLIENT-CACHE", target_type: "x" } }];
    state.cases = [{ id: "zzz", title: "Caso CLIENT-CACHE", legal_basis: { type: "unspecified" } }];
    state._lastCaps = { search_providers: [{ service: "x", state: "ok", label: "CLIENT" }] };
    await loadDashboard();
  })()`, sandbox);

  const stats = store.dashStats ? store.dashStats.innerHTML : "";
  assert("stats render from backend (complete=5, not client 1)", stats.includes(">5<"));
  assert("stats job total from backend totals.jobs=11", (store.dashJobTotal || {}).textContent === "11");
  assert("stats do NOT show client-cache value (1)", !stats.includes(">1<") || stats.includes(">5<"));

  const cov = store.dashCoverage ? store.dashCoverage.innerHTML : "";
  assert("coverage from backend (7 / 15)", cov.includes("7 / 15"));
  assert("coverage tools from backend (9 / 59)", cov.includes("9 / 59"));
  assert("coverage ignores client _lastCaps label", !cov.includes("CLIENT"));

  const cases = store.dashCases ? store.dashCases.innerHTML : "";
  assert("recent cases from backend", cases.includes("Caso BACKEND"));
  assert("recent cases ignore client cache", !cases.includes("CLIENT-CACHE"));

  const jobs = store.dashJobs ? store.dashJobs.innerHTML : "";
  assert("recent jobs from backend", jobs.includes("backend.example"));

  const warns = store.dashWarnings ? store.dashWarnings.innerHTML : "";
  assert("warnings from backend", warns.includes("senza base giuridica"));

  // --- error handling: /api/dashboard fails => UI shows error, no crash ------
  fetchImpl = async () => { throw new Error("boom 503"); };
  let threw = false;
  try { await vm.runInContext("loadDashboard()", sandbox); } catch (e) { threw = true; }
  assert("loadDashboard does not throw on API failure", !threw);
  assert("error surfaced in UI (not silent)", (store.dashStats.innerHTML || "").toLowerCase().includes("boom") ||
    (store.dashStats.innerHTML || "").toLowerCase().includes("errore"));

  console.log(failures ? `\n${failures} FAILED` : "\nALL PASSED");
  process.exit(failures ? 1 : 0);
})();
