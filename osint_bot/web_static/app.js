const state = {
  currentJob: null,
  pollTimer: null,
  csrf: "",
  authMode: "login",
  user: null,
  lastReport: null,
  activeSocial: null,
  socialHandles: {},
  currentMode: "handle",
  currentPanel: "dashboard",
};

const SOCIAL_NETWORKS = [
  { id: "instagram",  label: "Instagram",  prefix: "@" },
  { id: "twitter",    label: "X / Twitter", prefix: "@" },
  { id: "facebook",   label: "Facebook",   prefix: "" },
  { id: "tiktok",     label: "TikTok",     prefix: "@" },
  { id: "linkedin",   label: "LinkedIn",   prefix: "" },
  { id: "telegram",   label: "Telegram",   prefix: "@" },
  { id: "youtube",    label: "YouTube",    prefix: "@" },
  { id: "reddit",     label: "Reddit",     prefix: "u/" },
  { id: "threads",    label: "Threads",    prefix: "@" },
  { id: "snapchat",   label: "Snapchat",   prefix: "" },
  { id: "github",     label: "GitHub",     prefix: "" },
  { id: "twitch",     label: "Twitch",     prefix: "" },
  { id: "mastodon",   label: "Mastodon",   prefix: "@" },
  { id: "bluesky",    label: "Bluesky",    prefix: "@" },
  { id: "pinterest",  label: "Pinterest",  prefix: "" },
  { id: "discord",    label: "Discord",    prefix: "" },
];

const modePresets = {
  // NB: the per-mode placeholder/hint text lives in the i18n dictionary
  // (mp.<mode>.hint, resolved by applyMode via t()); only the behavioural
  // fields (type/modules/provider/authorized) stay here.
  handle: {
    type: "handle",
    modules: ["socmint", "phone_email"],
    provider: "all",
    authorized: true,
  },
  domain: {
    type: "domain",
    modules: ["company_domain", "opsec", "geo"],
    provider: "all",
    authorized: false,
  },
  contact: {
    type: "email",
    modules: ["phone_email", "socmint"],
    provider: "all",
    authorized: true,
  },
  media: {
    type: "media",
    modules: ["media", "geo"],
    provider: "none",
    authorized: false,
  },
  crypto: {
    type: "crypto",
    modules: ["crypto", "opsec"],
    provider: "all",
    authorized: false,
  },
};

const $ = (id) => document.getElementById(id);

// i18n shortcut — resolves against the shared dictionary in i18n.js.
// Falls back to the key if the engine isn't loaded yet.
const t = (key, params) => (window.I18N ? window.I18N.t(key, params) : key);

document.querySelectorAll(".nav").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    $(`panel-${button.dataset.panel}`).classList.add("active");
    updateTopbar(button.dataset.panel);
    if (button.dataset.panel === "dashboard") loadDashboard();
    if (button.dataset.panel === "jobs") loadJobs();
    if (button.dataset.panel === "keys") loadApiKeys();
    if (button.dataset.panel === "cases") loadCases();
  });
});

// Panel topbar copy, keyed to the i18n dictionary (resolved at render time
// so it re-translates on language switch).
const TOPBAR_COPY = {
  dashboard: ["pt.dashboard.h", "pt.dashboard.p"],
  cases: ["pt.cases.h", "pt.cases.p"],
  investigate: ["topbar.title", "topbar.sub"],
  jobs: ["jobs.title", "pt.jobs.p"],
  media: ["side.media", "pt.media.p"],
  keys: ["pt.keys.h", "pt.keys.p"],
  opsec: ["side.opsec", "pt.opsec.p"],
};

function updateTopbar(panel) {
  if (panel) state.currentPanel = panel;
  const copy = TOPBAR_COPY[state.currentPanel];
  if (!copy) return;
  const head = document.querySelector(".topbar h1");
  const sub = document.querySelector(".topbar p");
  if (head) head.textContent = t(copy[0]);
  if (sub) sub.textContent = t(copy[1]);
}

// Re-render language-dependent dynamic bits when the user switches language.
document.addEventListener("i18n:changed", () => {
  updateTopbar();
  if (typeof setAuthMode === "function") setAuthMode(state.authMode);
  const activeMode = document.querySelector(".quickMode.active");
  if (activeMode) applyMode(activeMode.dataset.mode);
});

$("loginTab").addEventListener("click", () => setAuthMode("login"));
$("signupTab").addEventListener("click", () => setAuthMode("signup"));
$("authSubmit").addEventListener("click", submitAuth);
$("logoutBtn").addEventListener("click", logout);
setAuthMode(state.authMode); // translate the submit label on load (button has no static data-i18n)
// Palette unica: ambra (selector rimosso dalla UI)
// $("themeSelect") rimosso — la palette è fissa "ambra".
$("planBtn").addEventListener("click", plan);
$("runBtn").addEventListener("click", runJob);
$("refreshJobs").addEventListener("click", loadJobs);
if ($("mediaFile")) $("mediaFile").addEventListener("change", uploadMedia);
if ($("mediaFileInline")) $("mediaFileInline").addEventListener("change", uploadMediaInline);
if ($("caseCreateBtn")) $("caseCreateBtn").addEventListener("click", createCase);
if ($("aiNarrativeBtn")) $("aiNarrativeBtn").addEventListener("click", generateAiNarrative);
if ($("aiTriageBtn")) $("aiTriageBtn").addEventListener("click", generateAiTriage);
if ($("sealBadge")) $("sealBadge").addEventListener("click", toggleSealPanel);
if ($("tsaTimestampBtn")) $("tsaTimestampBtn").addEventListener("click", requestTsaTimestamp);
document.querySelectorAll(".quickMode").forEach((button) => {
  button.addEventListener("click", () => applyMode(button.dataset.mode));
});
// Refresh privacy badge quando cambia caso o tipo (target type)
document.addEventListener("change", (e) => {
  if (e.target && (e.target.id === "currentCase" || e.target.id === "targetType")) {
    if (typeof updatePrivacyBadge === "function") updatePrivacyBadge();
  }
});
if ($("globalSearchBtn")) $("globalSearchBtn").addEventListener("click", () => routeGlobalSearch($("globalSearch").value));
if ($("globalSearch")) {
  $("globalSearch").addEventListener("input", () => updateDetectedType($("globalSearch").value));
  $("globalSearch").addEventListener("keydown", (e) => {
    if (e.key === "Enter") routeGlobalSearch($("globalSearch").value);
  });
}
buildSocialGrid();
setupReportTabs();

boot();

async function boot() {
  setTheme("ambra"); // palette fissa
  applyMode(document.querySelector(".quickMode.active")?.dataset.mode || "handle");
  const status = await api("/api/auth/status", {}, true, false);
  if (!status.authenticated) {
    $("authScreen").classList.remove("hidden");
    $("appShell").classList.add("hidden");
    $("signupTab").disabled = !status.signup_enabled;
    if (!status.signup_enabled) setAuthMode("login");
    if (status.google_login_enabled && status.google_client_id) {
      setupGoogleSignIn(status.google_client_id);
    }
    return;
  }
  state.user = status.user;
  state.csrf = status.csrf;
  $("authScreen").classList.add("hidden");
  $("appShell").classList.remove("hidden");
  $("accountPlan").textContent = `${status.user.username} · ${nomePiano(status.user.plan)}`;
  $("planBadge").textContent = nomePiano(status.user.plan);
  updateTopbar("dashboard");
  await health();
  await loadCapabilities();
  await loadJobs();
  await loadCases();
  await loadDashboard();
}

function setTheme(_theme) {
  const theme = "ambra"; // palette unica, ignora valori legacy
  document.body.dataset.theme = theme;
  localStorage.setItem("argo-theme", theme);
  if ($("themeSelect")) $("themeSelect").value = theme;
}

function setAuthMode(mode) {
  state.authMode = mode;
  $("loginTab").classList.toggle("active", mode === "login");
  $("signupTab").classList.toggle("active", mode === "signup");
  $("authSubmit").textContent = mode === "login" ? t("auth.submit") : t("auth.submit.signup");
  $("authEmailRow").classList.toggle("hidden", mode !== "signup");
  $("authMessage").textContent = "";
}

async function submitAuth() {
  const username = $("authUser").value.trim();
  const password = $("authPass").value;
  const email = ($("authEmail") && $("authEmail").value || "").trim();
  const path = state.authMode === "login" ? "/api/auth/login" : "/api/auth/signup";
  const body = state.authMode === "signup"
    ? { username, password, email }
    : { username, password };
  try {
    const data = await api(path, {
      method: "POST",
      body: JSON.stringify(body),
    }, true, false);
    if (state.authMode === "signup" && data.status === "pending_verification") {
      $("authMessage").style.color = "#65a8ff";
      $("authMessage").textContent = data.message
        || t("auth.verifySent", { email: data.email });
      $("authPass").value = "";
      return;
    }
    state.user = data.user;
    state.csrf = data.csrf;
    $("authPass").value = "";
    await boot();
  } catch (error) {
    $("authMessage").style.color = "";
    $("authMessage").textContent = error.message;
  }
}

// --- Google Sign-In (additional login door, alongside email+password) -----
let _googleScriptPromise = null;

function loadGoogleScript() {
  if (_googleScriptPromise) return _googleScriptPromise;
  _googleScriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = () => reject(new Error("Impossibile caricare Google Identity Services."));
    document.head.appendChild(script);
  });
  return _googleScriptPromise;
}

async function setupGoogleSignIn(clientId) {
  try {
    await loadGoogleScript();
    if (!window.google || !window.google.accounts || !window.google.accounts.id) return;
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: handleGoogleCredential,
    });
    $("googleAuthDivider").classList.remove("hidden");
    $("googleAuthBox").classList.remove("hidden");
    window.google.accounts.id.renderButton($("googleAuthBox"), {
      theme: "outline", size: "large", width: 280,
      text: "signin_with", locale: (window.I18N && window.I18N.get()) || "it",
    });
  } catch (err) {
    // Feature-detect failure (e.g. offline, ad-blocker) — fail silently,
    // the email+password form underneath still works.
    console.warn("Google Sign-In non disponibile:", err.message);
  }
}

async function handleGoogleCredential(response) {
  try {
    const data = await api("/api/auth/google", {
      method: "POST",
      body: JSON.stringify({ credential: response.credential }),
    }, true, false);
    state.user = data.user;
    state.csrf = data.csrf;
    await boot();
  } catch (error) {
    $("authMessage").style.color = "";
    $("authMessage").textContent = error.message;
  }
}

async function logout() {
  await api("/api/auth/logout", { method: "POST" });
  state.user = null;
  state.csrf = "";
  $("appShell").classList.add("hidden");
  $("authScreen").classList.remove("hidden");
}

// Default-active modules: tutte tranne deep/dark web e red team
const DEFAULT_MODULES = [
  "company_domain", "opsec", "geo", "media", "phone_email",
  "crypto", "socmint", "humint",
];

function selectedModules() {
  // I moduli dei preset aggressivi attivi si sommano ai default (dedup finale).
  const mods = new Set([...DEFAULT_MODULES, ...(state.activeModules || [])]);
  if ($("darkweb") && $("darkweb").checked) mods.add("darkweb");
  if ($("redTeamFlag") && $("redTeamFlag").checked) mods.add("red_team");
  return [...mods];
}

function collectSocialHandles() {
  return Object.entries(state.socialHandles)
    .filter(([_, value]) => value && value.trim())
    .map(([id, value]) => ({ network: id, handle: value.trim() }));
}

function collectContacts(selector) {
  return Array.from(document.querySelectorAll(selector))
    .map((el) => el.value.trim())
    .filter(Boolean);
}

function primaryTarget() {
  const mode = state.currentMode;
  if (mode === "handle") {
    const socials = collectSocialHandles();
    return socials.length ? socials[0].handle : "";
  }
  if (mode === "contact") {
    const emails = collectContacts(".email-input");
    const pecs = collectContacts(".pec-input");
    const phones = collectContacts(".phone-input");
    return emails[0] || pecs[0] || phones[0] || "";
  }
  if (mode === "media") {
    const inline = $("mediaInlineResult");
    return (inline && inline.dataset.filename) || "";
  }
  // domain / crypto
  const g = $("genericTarget");
  return g ? g.value.trim() : "";
}

function buildCommand() {
  const target = primaryTarget();
  const known = ($("knownFacts") && $("knownFacts").value || "").trim();
  const seeds = ($("seedUrls") && $("seedUrls").value || "").trim();
  return [
    target ? t("auth.searchFor", { target }) : t("auth.searchGeneric"),
    seeds ? t("pl.seedPrefix", { v: seeds }) : "",
    known ? t("pl.knownPrefix", { v: known }) : "",
  ].filter(Boolean).join(". ");
}

function payload() {
  const target = primaryTarget();
  const caseId = ($("currentCase") && $("currentCase").value) || "";
  const socials = collectSocialHandles();
  const emails = collectContacts(".email-input");
  const pecs = collectContacts(".pec-input");
  const phones = collectContacts(".phone-input");
  return {
    command: buildCommand(),
    target,
    target_type: $("targetType").value,
    provider: $("provider").value,
    source_route: ($("sourceRoute") && $("sourceRoute").value) || "auto",
    intensity: $("intensity").value,
    modules: selectedModules(),
    socials,
    emails,
    pecs,
    phones,
    seed_urls: dedupeList([
      ...extractUrls(($("seedUrls") && $("seedUrls").value) || ""),
      ...extractUrls(($("knownFacts") && $("knownFacts").value) || ""),
    ]),
    max_pages: Number($("maxPages").value || 24),
    confirm_authorization: $("confirmAuth").checked,
    allow_network_scan: $("networkScan").checked,
    allow_darkweb: $("darkweb").checked,
    include_contact: true,  // contatti sempre in chiaro per scelta UX
    include_external_tools: true,
    case_id: caseId || undefined,
  };
}

async function health() {
  try {
    const data = await api("/api/health");
    $("healthDot").style.background = "#59c19c";
    $("healthText").textContent = data.status;
  } catch (error) {
    $("healthDot").style.background = "#e06c75";
    $("healthText").textContent = "offline";
  }
}

async function plan() {
  $("planStatus").textContent = "calcolo";
  try {
    const data = await api("/api/plan", { method: "POST", body: JSON.stringify(payload()) });
    renderPlan(data.profile);
    $("planStatus").textContent = "pronto";
  } catch (error) {
    $("planOutput").textContent = error.message;
    $("planStatus").textContent = t("st.error");
  }
}

async function runJob() {
  $("runBtn").disabled = true;
  try {
    const data = await api("/api/jobs", { method: "POST", body: JSON.stringify(payload()) });
    state.currentJob = data.id;
    renderPlan(data.profile);
    showJobsPanel();
    await loadJobs();
    pollJob(data.id);
  } catch (error) {
    $("planOutput").textContent = error.message;
  } finally {
    $("runBtn").disabled = false;
  }
}

// Etichette leggibili per ogni agente + flag "gated" (richiede autorizzazione).
// Agent labels are i18n keys, resolved at render time via t().
const AGENT_LABELS = {
  planner: "ag.planner",
  web: "ag.web",
  opsec: "ag.opsec",
  geo: "ag.geo",
  socmint: "ag.socmint",
  media: "ag.media",
  crypto: "ag.crypto",
  phone: "ag.phone",
  humint: "ag.humint",
  external: "ag.external",
  reverse_account: "ag.reverse_account",
  darkweb: "ag.darkweb",
  red_team: "ag.red_team",
};
const GATED_AGENTS = new Set(["darkweb", "red_team"]);

function agentChips(agents) {
  if (!agents || !agents.length) return "<span class=\"muted\">-</span>";
  return agents.map((a) => {
    const label = AGENT_LABELS[a] ? t(AGENT_LABELS[a]) : a;
    const gated = GATED_AGENTS.has(a);
    return `<span class="agentChip${gated ? " agentChip--gated" : ""}" title="${gated ? t("ag.gatedTip") : t("ag.alwaysTip")}">${gated ? "🔒 " : ""}${escapeHtml(label)}</span>`;
  }).join("");
}

function renderPlan(profile) {
  $("planOutput").innerHTML = "";
  const block = document.createElement("div");
  block.className = "planBlock";
  const agents = profile.agents || [];
  block.innerHTML = `
    <p><strong>Target</strong>: ${escapeHtml(profile.target || "-")}</p>
    <p><strong>${t("inv.type")}</strong>: ${escapeHtml(profile.target_type || "-")}</p>
    <p><strong>${t("pl.activeAgents")} (${agents.length})</strong></p>
    <div class="agentChips">${agentChips(agents)}</div>
    <p class="muted agentChipsNote">${t("pl.agentsNote")}</p>
    <p><strong>${t("pl.tools")}</strong>: ${escapeHtml((profile.external_tools || []).join(", ") || "-")}</p>
    <p><strong>Seed URL</strong>: ${escapeHtml((profile.seed_urls || []).join(", ") || "-")}</p>
    <p><strong>${t("pl.depth")}</strong>: ${profile.depth} · <strong>${t("pl.pages")}</strong>: ${profile.max_pages}</p>
    <hr>
    ${(profile.notes || []).map((note) => `<p>${escapeHtml(note)}</p>`).join("")}
  `;
  $("planOutput").appendChild(block);
}

async function loadCapabilities() {
  try {
    const data = await api("/api/capabilities");
    state.reportSealing = data.report_sealing || { always_on: true, tsa_configured: false };
    // Se non-admin: NON mostrare la lista, solo un placeholder col contatore
    // e un pulsante che apre il modal di sblocco (Ricerca aggressiva riusa lo stesso).
    if (!data.admin_unlocked) {
      const conns = (data.connectors && data.connectors[0]) || {};
      const nOk = conns.count_ok || 0, nTot = conns.count || 0;
      $("capabilities").innerHTML = `
        <div class="capability" style="grid-column:1/-1;text-align:center;padding:18px">
          <strong>${t("cap.hidden")}</strong>
          <div class="muted" style="margin:6px 0 12px">${t("cap.hiddenSub", { ok: nOk, tot: nTot })}</div>
          <button type="button" class="btn" id="capUnlockBtn">${t("inv.ah.unlock")}</button>
        </div>`;
      const b = document.getElementById("capUnlockBtn");
      if (b) b.addEventListener("click", () => { if (typeof openAdminUnlockModal === "function") openAdminUnlockModal(); });
      return;
    }
    const providers = (data.search_providers || []).map((provider) => {
      const cls = provider.configured ? "ok" : "ko";
      return `
        <div class="capability">
          <strong>${t("cap.searchPrefix")} ${escapeHtml(provider.name)}<span class="statusDot ${cls}" title="${cls === "ok" ? t("cap.configured") : t("cap.missingEnv")}"></span></strong>
          <span>${provider.configured ? t("cap.configured") : escapeHtml(provider.env_var)}</span>
        </div>
      `;
    }).join("");
    const tools = data.tools.map((tool) => {
      const cls = tool.available ? "ok" : "ko";
      const tip = tool.available ? t("cap.available") : (tool.health_reason || t("cap.unavailable"));
      return `
        <div class="capability">
          <strong>${escapeHtml(tool.name)}<span class="statusDot ${cls}" title="${escapeHtml(tip)}"></span></strong>
          <span>${tool.available ? t("cap.available") : escapeHtml(tool.env_var)}</span>
        </div>
      `;
    }).join("");
    // Connettori (registro connectors/): tutti visibili con stato.
    const connectors = (data.connectors || []).map((c) => {
      const ok = c.status === "ok";
      const cls = ok ? "ok" : "ko";
      const tip = ok ? t("cap.connActive")
        : (c.status === "needs_key" ? (t("cap.connNeedsKey") + (c.needs || "")) : t("cap.connNeedsTool"));
      const sub = ok ? (c.input_types || []).join(", ")
        : (c.status === "needs_key" ? ("API: " + (c.needs || "")) : t("cap.configMissing"));
      return `
        <div class="capability">
          <strong>${escapeHtml(c.label || c.name)}<span class="statusDot ${cls}" title="${escapeHtml(tip)}"></span></strong>
          <span>${escapeHtml(sub)}</span>
        </div>
      `;
    }).join("");
    const connHeader = (data.connectors && data.connectors.length)
      ? `<div class="capability" style="grid-column:1/-1;opacity:.7;font-size:12px;margin-top:6px">${t("cap.connectors")} (${data.connectors.length})</div>`
      : "";
    $("capabilities").innerHTML = providers + tools + connHeader + connectors;
  } catch (error) {
    $("capabilities").textContent = error.message;
  }
}

async function loadJobs() {
  try {
    const data = await api("/api/jobs");
    $("jobCount").textContent = String(data.jobs.length);
    $("jobsList").innerHTML = data.jobs.filter((job) => job.profile).map((job) => `
      <div class="job" data-id="${job.id}" data-status="${job.status}">
        <button class="jobDeleteBtn" data-del-id="${job.id}" title="${t("act.delReportTitle")}" aria-label="${t("act.delAria")}">🗑</button>
        <strong>${escapeHtml(job.profile.target)} · ${escapeHtml(job.profile.target_type)}</strong>
        <span>${escapeHtml(job.status)} · ${escapeHtml(jobStageLabel(job))} · ${escapeHtml(job.updated_at || job.created_at)}</span>
      </div>
    `).join("") || `<div class="empty">${t("jb.noReports")}</div>`;
    document.querySelectorAll(".job").forEach((item) => item.addEventListener("click", (e) => {
      // Evita di selezionare quando si clicca il cestino.
      if (e.target.closest(".jobDeleteBtn")) return;
      selectJob(item.dataset.id);
    }));
    document.querySelectorAll(".jobDeleteBtn").forEach((btn) => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteJob(btn.dataset.delId);
    }));
  } catch (error) {
    $("jobsList").textContent = error.message;
  }
}

// Fase 3 — Banner HighRiskResearchMode. Inserito dinamicamente sopra il viewer
// del report quando il job ha `high_risk.active=true`. Nessuna modifica a
// index.html: minimizza il rischio di conflitto con editing in parallelo.
function renderHighRiskBanner(job) {
  // Rimuovi sempre l'eventuale banner precedente (job diverso, switch tab).
  const old = document.getElementById("highRiskBanner");
  if (old && old.parentNode) old.parentNode.removeChild(old);

  const hr = job && job.high_risk;
  if (!hr || !hr.active) return;

  const anchor = document.getElementById("progressTimeline");
  if (!anchor || !anchor.parentNode) return;

  const wrap = document.createElement("div");
  wrap.id = "highRiskBanner";
  wrap.className = "highRiskBanner";
  const reasons = (hr.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const restrictions = (hr.restrictions || []).slice(0, 6)
    .map((r) => `<span class="srcChip">${escapeHtml(r.label || r.key || "")}</span>`).join("");
  wrap.innerHTML = `
    <div class="hrTitle">🛡️ ${escapeHtml(hr.banner || t("hrb.opsecActive"))}</div>
    ${reasons ? `<details class="hrDetails"><summary>${t("hrb.whyActive")} (${(hr.reasons || []).length})</summary><ul>${reasons}</ul></details>` : ""}
    ${restrictions ? `<div class="hrRestrictions">${restrictions}</div>` : ""}
  `;
  anchor.parentNode.insertBefore(wrap, anchor);
}

// Cancellazione granulare di un report (DELETE /api/jobs/<id>).
// Conferma esplicita obbligatoria perché' rimuove file da disco + record DB.
// L'audit log registra l'azione lato server (chain-of-custody preservata).
async function deleteJob(id) {
  if (!id) return;
  const reason = prompt(t("act.deletePrompt"), "");
  if (reason === null) return; // utente ha annullato
  try {
    await api(`/api/jobs/${id}`, {
      method: "DELETE",
      body: JSON.stringify({ reason: String(reason || "").slice(0, 500) }),
    });
    // Se il job aperto era questo, pulisci viewer e banner.
    if (state.currentJob === id) {
      state.currentJob = null;
      state.lastReport = null;
      const viewer = $("reportViewer");
      if (viewer) viewer.textContent = t("jb.reportDeleted");
      const banner = document.getElementById("highRiskBanner");
      if (banner && banner.parentNode) banner.parentNode.removeChild(banner);
    }
    await loadJobs();
    // Refresha anche dashboard recent-jobs se siamo lì.
    if (typeof loadDashboard === "function") loadDashboard();
  } catch (err) {
    alert(t("err.delete") + ((err && err.message) || err));
  }
}

// Cancellazione caso: conferma esplicita + scelta cascade (elimina anche i job
// del caso oppure li lascia come record orfani per audit).
async function deleteCase(id, title) {
  if (!id) return;
  const cascade = confirm(t("cs.delConfirm", { name: title || id }));
  if (!cascade && !confirm(t("cs.delOnlyCase"))) return;
  const reason = prompt(t("cs.delReason"), "") ?? "";
  try {
    const url = `/api/cases/${id}${cascade ? "?cascade=1" : ""}`;
    await api(url, { method: "DELETE", body: JSON.stringify({ reason: String(reason).slice(0, 500) }) });
    await loadCases();
    if (typeof loadDashboard === "function") loadDashboard();
  } catch (err) {
    alert(t("err.deleteCase") + ((err && err.message) || err));
  }
}

async function selectJobBase(id) {
  const job = await api(`/api/jobs/${id}`);
  state.currentJob = id;
  state.currentJobData = job;  // per messaggi contestuali (skip reasons, ecc.)
  updateAiNarrativeButtonVisibility();
  updateSealUI(id, job);
  renderHighRiskBanner(job);
  $("jsonLink").href = `/api/jobs/${id}/report.json`;
  $("mdLink").href = `/api/jobs/${id}/report.md`;
  $("pdfLink").href = `/api/jobs/${id}/report.pdf`;
  $("forensicMdLink").href = `/api/jobs/${id}/forensic.md`;
  $("forensicJsonLink").href = `/api/jobs/${id}/forensic.json`;
  if ($("redteamMdLink"))   $("redteamMdLink").href   = `/api/jobs/${id}/redteam.md`;
  if ($("redteamJsonLink")) $("redteamJsonLink").href = `/api/jobs/${id}/redteam.json`;
  if ($("stixLink")) $("stixLink").href = `/api/jobs/${id}/stix.json`;
  if ($("mispLink")) $("mispLink").href = `/api/jobs/${id}/misp.json`;
  renderProgress(job);
  if (job.status === "complete") {
    const markdownResponse = await fetch(`/api/jobs/${id}/report.md`);
    const jsonResponse = await fetch(`/api/jobs/${id}/report.json`);
    const markdown = await markdownResponse.text();
    const report = await jsonResponse.json();
    state.lastReport = report;
    $("reportViewer").textContent = markdown;
    renderEntityGraph(report);

    // Pre-load forensic + redteam JSON se disponibili.
    state.forensicReport = null;
    state.redteamReport = null;
    if (job.forensic_json_path) {
      try {
        const r = await fetch(`/api/jobs/${id}/forensic.json`);
        if (r.ok) state.forensicReport = await r.json();
      } catch (e) { console.warn("forensic load failed:", e); }
    }
    if (job.redteam_json_path) {
      try {
        const r = await fetch(`/api/jobs/${id}/redteam.json`);
        if (r.ok) state.redteamReport = await r.json();
      } catch (e) { console.warn("redteam load failed:", e); }
    }
    renderForensicViewer();
  } else {
    state.lastReport = null;
    state.forensicReport = null;
    state.redteamReport = null;
    clearEntityGraph();
    $("reportViewer").textContent = JSON.stringify(job, null, 2);
    renderForensicViewer();
  }
}

// --------- Report tabs (Classico | Forensico)

function setupReportTabs() {
  document.querySelectorAll(".reportTab").forEach((btn) => {
    btn.addEventListener("click", () => switchReportTab(btn.dataset.rtab));
  });
}

function switchReportTab(which) {
  document.querySelectorAll(".reportTab").forEach((b) => {
    b.classList.toggle("active", b.dataset.rtab === which);
  });
  state.currentReportTab = which;
  const classic = $("reportViewer");
  const forensic = $("forensicViewer");
  if (which === "classic") {
    if (classic) classic.classList.remove("hidden");
    if (forensic) forensic.classList.add("hidden");
  } else {
    // forensic | redteam → riusa lo stesso viewer con dati diversi.
    if (classic) classic.classList.add("hidden");
    if (forensic) forensic.classList.remove("hidden");
    renderForensicViewer();
  }
}

function renderForensicViewer() {
  const nav = $("forensicNav");
  const body = $("forensicBody");
  if (!nav || !body) return;
  const which = state.currentReportTab || "forensic";
  const report = which === "redteam" ? state.redteamReport : state.forensicReport;
  if (!report) {
    nav.innerHTML = "";
    if (which === "redteam") {
      // Cerco nella progress-timeline del job un evento redteam_report_skipped
      // che spiega perché' e' stato saltato.
      const skip = (state.currentJobData && state.currentJobData.progress || [])
        .find((p) => p.stage === "redteam_report_skipped");
      const skipReason = skip ? skip.message : "";
      body.innerHTML =
        '<div class="rtEmpty">' +
          '<div class="rtEmptyIcon">⚔</div>' +
          `<h3>${t("rt.unavailable")}</h3>` +
          (skipReason
            ? `<p class="rtWhy">${escapeHtml(skipReason)}</p>`
            : `<p class="muted">${t("rt.whenGenerated")}</p>`
          ) +
          '<div class="rtActions">' +
            `<button type="button" class="btnPrimary" onclick="document.querySelector(&quot;.nav[data-panel=cases]&quot;).click()">${t("rt.openCases")}</button>` +
            `<button type="button" class="btnGhost" onclick="document.querySelector(&quot;.nav[data-panel=investigate]&quot;).click()">${t("inv.title")}</button>` +
          '</div>' +
        '</div>';
    } else {
      body.innerHTML = `<p class="muted">${t("rt.noForensic")}</p>`;
    }
    return;
  }
  const sections = report.sections || [];
  // Index
  nav.innerHTML = sections.map((s) =>
    `<button type="button" class="forensicNavItem" data-section="${s.number}">${s.number}. ${escapeHtml(s.title)}</button>`
  ).join("");
  nav.querySelectorAll(".forensicNavItem").forEach((b) => {
    b.addEventListener("click", () => {
      const num = b.dataset.section;
      const el = body.querySelector(`[data-section="${num}"]`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      nav.querySelectorAll(".forensicNavItem").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
    });
  });
  // Body — render con markdown leggero (no eval, sanitization basilare)
  const meta = `
    <header class="forensicHeader">
      <h2>${escapeHtml(sections[0]?.body_markdown || report.target)}</h2>
      <p class="forensicMeta">
        ${t("rp.case")} <code>${escapeHtml(report.case_id)}</code> · target
        <code>${escapeHtml(report.target)}</code> (${escapeHtml(report.target_type)})
        · ${t("rp.generated")} ${escapeHtml(report.generated_at)}
      </p>
    </header>
  `;
  const sectionsHtml = sections.map((s) => `
    <section class="forensicSection" data-section="${s.number}">
      <h3>${s.number}. ${escapeHtml(s.title)}</h3>
      <div class="forensicSectionBody">${miniMarkdown(s.body_markdown || "—")}</div>
    </section>
  `).join("");
  body.innerHTML = meta + sectionsHtml;
}

// Minimal markdown renderer — no innerHTML user data, only structural transforms.
function miniMarkdown(md) {
  if (!md) return "";
  // Escape FIRST, then re-inject our own controlled markup.
  let s = escapeHtml(md);

  // Code fence ```json ... ```
  s = s.replace(/```(\w+)?\n([\s\S]*?)```/g, (m, lang, code) =>
    `<pre class="forensicCode" data-lang="${escapeHtml(lang || '')}">${code}</pre>`);

  // Tables (very simple — only the syntax our generator uses).
  s = s.replace(/(^|\n)(\|[^\n]+\|\n\|[\s\-:|]+\|\n(?:\|[^\n]+\|\n?)+)/g, (match, prefix, tbl) => {
    const lines = tbl.trim().split("\n");
    const header = lines[0].slice(1, -1).split("|").map((c) => c.trim());
    const rows = lines.slice(2).map((line) =>
      line.slice(1, -1).split("|").map((c) => c.trim())
    );
    let html = "<table class='forensicTable'><thead><tr>";
    html += header.map((c) => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
    html += rows.map((r) => "<tr>" + r.map((c) => `<td>${c}</td>`).join("") + "</tr>").join("");
    html += "</tbody></table>";
    return prefix + html;
  });

  // Headings handled by the section wrapper, but we still convert in-section h4/h5.
  s = s.replace(/(^|\n)#### ([^\n]+)/g, "$1<h4>$2</h4>");
  s = s.replace(/(^|\n)### ([^\n]+)/g, "$1<h4>$2</h4>");
  // Inline: bold, italic, code, links.
  s = s.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, "<em>$1</em>");
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  // Links [text](url) — sanitize URL.
  s = s.replace(/\[([^\]\n]+)\]\(([^)\n]+)\)/g, (m, text, url) => {
    const safe = /^https?:\/\//i.test(url) ? url : "#";
    return `<a href="${safe}" target="_blank" rel="noopener">${text}</a>`;
  });
  // Bullet lists (lines starting with "- ").
  const lines = s.split("\n");
  const out = [];
  let inList = false;
  for (const line of lines) {
    const li = line.match(/^- (.+)$/);
    if (li) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${li[1]}</li>`);
    } else {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push(line);
    }
  }
  if (inList) out.push("</ul>");
  s = out.join("\n");
  // Paragraphs: join newlines into <p>.
  s = s.split(/\n\n+/).map((block) => {
    block = block.trim();
    if (!block) return "";
    if (/^<(ul|ol|table|h\d|pre)/i.test(block)) return block;
    return `<p>${block.replace(/\n/g, "<br>")}</p>`;
  }).join("\n");
  return s;
}

function pollJob(id) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    const job = await api(`/api/jobs/${id}`);
    renderProgress(job);
    await loadJobs();
    if (job.status === "complete" || job.status === "error") {
      clearInterval(state.pollTimer);
      await selectJob(id);
    }
  }, 1800);
}

function renderProgress(job) {
  const progress = job.progress || [];
  if (!progress.length) {
    $("progressTimeline").innerHTML = "";
    return;
  }
  $("progressTimeline").innerHTML = progress.map((item, index) => `
    <div class="progressStep ${index === progress.length - 1 ? "active" : ""}" data-stage="${escapeHtml(item.stage)}">
      <span></span>
      <strong>${escapeHtml(progressLabel(item.stage))}</strong>
      <small>${escapeHtml(item.message || "")}</small>
    </div>
  `).join("");
}

function jobStageLabel(job) {
  const progress = job.progress || [];
  const last = progress[progress.length - 1];
  if (last) return progressLabel(last.stage);
  return progressLabel(job.status) || t("st.pending");
}

function progressLabel(stage) {
  const labels = {
    queued: "pr.queued",
    running: "pr.running",
    collecting: "pr.collecting",
    pdf: "pr.pdf",
    pdf_error: "pr.pdfError",
    complete: "pr.complete",
    error: "st.error",
  };
  return labels[stage] ? t(labels[stage]) : (stage || t("st.state"));
}

function renderEntityGraph(report) {
  const graph = $("entityGraph");
  const entities = Array.isArray(report.entities) ? report.entities : [];
  const relationships = Array.isArray(report.relationships) ? report.relationships : [];
  if (!entities.length) {
    clearEntityGraph();
    return;
  }

  const nodes = selectGraphEntities(entities, report.target || "");
  const nodeIds = new Set(nodes.map((node) => node.id));
  const links = relationships
    .filter((link) => nodeIds.has(link.source) && nodeIds.has(link.target))
    .slice(0, 70);
  const positioned = positionNodes(nodes, links, 900, 360);
  const byId = Object.fromEntries(positioned.map((node) => [node.id, node]));

  const linkMarkup = links.map((link) => {
    const source = byId[link.source];
    const target = byId[link.target];
    if (!source || !target) return "";
    return `<line class="graphLink" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" />`;
  }).join("");

  const nodeMarkup = positioned.map((node) => {
    const grade = `${node.source_reliability || "F"}${node.info_credibility || 6}`;
    const tier = gradeTier(node.source_reliability, node.info_credibility);
    return `
    <g class="graphNode grade-${tier}" data-entity-id="${escapeHtml(node.id)}" data-grade="${grade}" transform="translate(${node.x}, ${node.y})">
      <circle r="${node.radius + 4}" class="graphRing"></circle>
      <circle r="${node.radius}" class="type-${escapeHtml(node.type)}"></circle>
      <text y="${node.radius + 14}" text-anchor="middle">${escapeHtml(shortLabel(node.display_value || node.value, 24))}</text>
      <text y="${-(node.radius + 4)}" text-anchor="middle" class="graphGrade">${escapeHtml(grade)}</text>
    </g>
  `;
  }).join("");

  graph.classList.remove("hidden");
  graph.innerHTML = `
    <div class="graphHead">
      <div>
        <strong>${t("gr.title")}</strong>
        <span>${t("gr.nodesLinks", { n: nodes.length, r: links.length })}</span>
      </div>
      <span class="tag">pivot</span>
    </div>
    <svg viewBox="0 0 900 360" role="img" aria-label="${t("gr.ariaLabel")}">
      <rect class="graphCanvas" x="0" y="0" width="900" height="360" rx="8"></rect>
      ${linkMarkup}
      ${nodeMarkup}
    </svg>
    <div id="graphDetails" class="graphDetails">${t("gr.selectNode")}</div>
  `;
  graph.querySelectorAll(".graphNode").forEach((nodeEl) => {
    nodeEl.addEventListener("click", () => {
      const entity = nodes.find((item) => item.id === nodeEl.dataset.entityId);
      if (entity) renderGraphDetails(entity);
    });
  });
}

function clearEntityGraph() {
  $("entityGraph").classList.add("hidden");
  $("entityGraph").innerHTML = "";
}

function selectGraphEntities(entities, target) {
  return [...entities]
    .filter((entity) => !isUtilityEntity(entity, target))
    .sort((a, b) => graphRank(a) - graphRank(b))
    .slice(0, 34);
}

function isUtilityEntity(entity, target) {
  const utilityHosts = new Set([
    "bing.com",
    "crt.sh",
    "duckduckgo.com",
    "google.com",
    "hunter.io",
    "intelx.io",
    "search.censys.io",
    "shodan.io",
    "urlscan.io",
    "web.archive.org",
    "yandex.com",
  ]);
  const value = String(entity.value || "").toLowerCase();
  const cleanTarget = String(target || "").toLowerCase().replace(/^www\./, "");
  if (value.replace(/^www\./, "") === cleanTarget) return false;
  const host = entity.type === "url" ? urlHost(value) : value;
  return utilityHosts.has(host);
}

function urlHost(value) {
  try {
    return new URL(value).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return value;
  }
}

function graphRank(entity) {
  const priority = {
    domain: 0,
    organization: 1,
    email: 2,
    username: 3,
    phone: 4,
    ip: 5,
    wallet: 6,
    url: 7,
    media: 8,
    location: 9,
  };
  const roleBoost = entity.attributes && entity.attributes.role === "target" ? -10 : 0;
  return roleBoost + (priority[entity.type] ?? 20) - Number(entity.confidence || 0);
}

// Force-directed layout (Fruchterman-Reingold-style spring embedder), pure
// JS, no external library — keeps with the platform's zero-third-party-CDN
// design. Replaces the old fixed two-ring layout, which placed nodes purely
// by array index and completely ignored `links`: with up to 34 nodes and 70
// relationships that produced an unreadable "hairball" where connected
// nodes could land on opposite sides of the circle. This actually pulls
// linked nodes together and pushes everything else apart.
function positionNodes(nodes, links, width, height) {
  if (!nodes.length) return [];
  const n = nodes.length;
  const centerX = width / 2;
  const centerY = height / 2;
  const margin = 34;

  // Seed on a circle (not all-at-origin, which would give the repulsion
  // force a 0/0 direction to resolve on the first iteration).
  const seedR = Math.min(width, height) * 0.32;
  const pos = nodes.map((node, i) => ({
    ...node,
    x: centerX + Math.cos((i / n) * Math.PI * 2) * seedR,
    y: centerY + Math.sin((i / n) * Math.PI * 2) * seedR,
    vx: 0, vy: 0,
  }));
  const indexById = Object.fromEntries(pos.map((p, i) => [p.id, i]));
  const edges = links
    .map((l) => [indexById[l.source], indexById[l.target]])
    .filter(([a, b]) => a !== undefined && b !== undefined && a !== b);

  const REPULSION = 2600;
  const SPRING = 0.02;
  const SPRING_LEN = 92;
  const CENTER_PULL = 0.01;
  const TARGET_PULL = 0.05; // extra pull so the pivot entity (index 0) anchors near the middle
  const DAMPING = 0.85;
  const ITERATIONS = 220;

  for (let iter = 0; iter < ITERATIONS; iter++) {
    // Repulsion between every pair. n is capped at 34 (selectGraphEntities),
    // so O(n^2) is at most ~560 pair checks per iteration — cheap.
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = pos[i].x - pos[j].x;
        const dy = pos[i].y - pos[j].y;
        const distSq = Math.max(dx * dx + dy * dy, 0.01);
        const dist = Math.sqrt(distSq);
        const force = REPULSION / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        pos[i].vx += fx; pos[i].vy += fy;
        pos[j].vx -= fx; pos[j].vy -= fy;
      }
    }
    // Spring attraction along real relationships.
    for (const [a, b] of edges) {
      const dx = pos[b].x - pos[a].x;
      const dy = pos[b].y - pos[a].y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 0.01);
      const force = SPRING * (dist - SPRING_LEN);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      pos[a].vx += fx; pos[a].vy += fy;
      pos[b].vx -= fx; pos[b].vy -= fy;
    }
    // Weak centering (everyone) + integrate + damp + clamp to canvas.
    for (let i = 0; i < n; i++) {
      const pull = i === 0 ? TARGET_PULL : CENTER_PULL;
      pos[i].vx += (centerX - pos[i].x) * pull;
      pos[i].vy += (centerY - pos[i].y) * pull;
      pos[i].vx *= DAMPING; pos[i].vy *= DAMPING;
      pos[i].x += pos[i].vx; pos[i].y += pos[i].vy;
      pos[i].x = Math.max(margin, Math.min(width - margin, pos[i].x));
      pos[i].y = Math.max(margin, Math.min(height - margin, pos[i].y));
    }
  }

  return pos.map((p, i) => ({
    ...p, x: Math.round(p.x), y: Math.round(p.y), radius: i === 0 ? 24 : 16,
  }));
}

function renderGraphDetails(entity) {
  const details = $("graphDetails");
  details.innerHTML = `
    <div>
      <strong>${escapeHtml(entity.display_value || entity.value)}</strong>
      <span>${escapeHtml(entityTypeLabel(entity.type))} · ${t("gr.grade")} ${escapeHtml((entity.source_reliability || "F") + (entity.info_credibility || 6))} · ${t("gr.confidence")} ${Number(entity.confidence || 0).toFixed(2)}</span>
    </div>
    <button type="button" class="smallAction">${t("gr.preparePivot")}</button>
  `;
  details.querySelector("button").addEventListener("click", () => pivotFromEntity(entity));
}

function pivotFromEntity(entity) {
  document.querySelector('[data-panel="investigate"]').click();
  $("target").value = entity.value;
  $("targetType").value = targetTypeFromEntity(entity.type);
  setModules(modulesFromEntity(entity.type));
  $("modeHint").textContent = t("gr.pivotPrepared", { type: entityTypeLabel(entity.type) });
  if (["email", "phone", "username", "person"].includes(entity.type)) {
    $("confirmAuth").checked = false;
  }
  plan();
}

function targetTypeFromEntity(type) {
  const allowed = {
    domain: "domain",
    organization: "company",
    email: "email",
    username: "handle",
    phone: "phone",
    ip: "ip",
    wallet: "crypto",
    media: "media",
  };
  return allowed[type] || "auto";
}

function modulesFromEntity(type) {
  const map = {
    domain: ["company_domain", "opsec", "geo"],
    organization: ["company_domain", "opsec"],
    email: ["phone_email", "socmint"],
    username: ["socmint", "phone_email"],
    phone: ["phone_email", "socmint"],
    ip: ["company_domain", "opsec", "geo"],
    wallet: ["crypto", "opsec"],
    media: ["media", "geo"],
  };
  return map[type] || ["company_domain", "opsec"];
}

function entityTypeLabel(type) {
  const labels = {
    domain: "et.domain",
    organization: "et.organization",
    email: "et.email",
    username: "et.username",
    phone: "et.phone",
    ip: "et.ip",
    wallet: "et.wallet",
    url: "et.url",
    media: "et.media",
    location: "et.location",
  };
  return labels[type] ? t(labels[type]) : type;
}

function shortLabel(value, maxLength) {
  const clean = String(value || "");
  if (clean.length <= maxLength) return clean;
  return `${clean.slice(0, maxLength - 3)}...`;
}

async function uploadMedia() {
  const file = $("mediaFile").files[0];
  if (!file) {
    $("mediaOutput").textContent = t("md.selectFile");
    return;
  }
  $("mediaOutput").textContent = t("md.analyzing");
  const form = new FormData();
  form.append("file", file);
  try {
    const data = await api("/api/media", { method: "POST", body: form }, false);
    $("mediaOutput").textContent = JSON.stringify(data.metadata, null, 2);
  } catch (error) {
    $("mediaOutput").textContent = error.message;
  }
}

async function uploadMediaInline() {
  const file = $("mediaFileInline").files[0];
  const out = $("mediaInlineResult");
  if (!file) {
    out.classList.add("muted");
    out.textContent = t("inv.media.none");
    return;
  }
  out.classList.remove("muted");
  out.textContent = t("md.analyzingFile", { name: file.name });
  const form = new FormData();
  form.append("file", file);
  try {
    const data = await api("/api/media", { method: "POST", body: form }, false);
    out.dataset.filename = file.name;
    const m = data.metadata || {};
    out.innerHTML = `
      <div class="mediaSummary">
        <strong>${escapeHtml(file.name)}</strong>
        <span class="tag">${escapeHtml(m.mime || t("md.na"))}</span>
      </div>
      <pre>${escapeHtml(JSON.stringify(m, null, 2))}</pre>
    `;
  } catch (error) {
    out.textContent = t("err.generic") + error.message;
  }
}

async function api(path, options = {}, jsonContent = true, auth = true) {
  const headers = options.headers || {};
  if (jsonContent && options.body) headers["Content-Type"] = "application/json";
  if (auth && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const err = new Error(data.error || response.statusText);
    err.status = response.status;
    throw err;
  }
  return data;
}

function showJobsPanel() {
  document.querySelector('[data-panel="jobs"]').click();
}

function extractUrls(value) {
  return value.match(/https?:\/\/[^\s<>()]+/g) || [];
}

function dedupeList(values) {
  return Array.from(new Set(values.map((item) => item.trim()).filter(Boolean)));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function nomePiano(plan) {
  if (plan === "free") return t("opsec.free");
  if (plan === "pro") return "Pro";
  return plan || t("opsec.free");
}

function applyMode(mode) {
  const preset = modePresets[mode] || modePresets.handle;
  state.currentMode = mode;
  document.querySelectorAll(".quickMode").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === mode);
  });
  const usedMode = modePresets[mode] ? mode : "handle";
  $("targetType").value = preset.type;
  $("provider").value = preset.provider;
  if ($("modeHint")) $("modeHint").textContent = t(`mp.${usedMode}.hint`);
  $("confirmAuth").checked = preset.authorized;

  // Show/hide mode panels
  const panels = {
    handle:  $("socialPanel"),
    contact: $("contactPanel"),
    media:   $("mediaPanel"),
    domain:  $("genericPanel"),
    crypto:  $("genericPanel"),
  };
  Object.values(panels).forEach((el) => el && el.classList.add("hidden"));
  const active = panels[mode] || $("genericPanel");
  if (active) active.classList.remove("hidden");

  if (mode === "domain" || mode === "crypto") {
    const ph = mode === "domain" ? t("mp.domain.genph") : t("mp.crypto.genph");
    if ($("genericTarget")) $("genericTarget").placeholder = ph;
  }
  updatePrivacyBadge();
}

// Preset di ricerca aggressiva — MULTI-SELECT.
// Ogni preset e' un toggle: attivare piu' preset combina i loro moduli/tool
// e prende il massimo di intensity/pages. Non c'e' piu' "un solo attivo".
const AGGRESSIVE_PRESETS = {
  "username-full":   { mode: "handle",  type: "handle",  intensity: "deep",       pages: 60,
                       modules: ["socmint", "phone_email"] },
  "email-deep":      { mode: "contact", type: "email",   intensity: "deep",       pages: 40,
                       modules: ["phone_email", "socmint"] },
  "phone-osint":     { mode: "contact", type: "phone",   intensity: "deep",       pages: 40,
                       modules: ["phone_email"] },
  "person-alias":    { mode: "domain",  type: "person",  intensity: "meticulous", pages: 50,
                       modules: ["socmint", "humint"] },
  "domain-recon":    { mode: "domain",  type: "domain",  intensity: "meticulous", pages: 60,
                       modules: ["company_domain", "opsec"] },
  "wallet-tx":       { mode: "crypto",  type: "crypto",  intensity: "deep",       pages: 30,
                       modules: ["crypto"] },
};

// Set live dei preset attivi (memoria, non persistente).
state.activePresets = new Set();

const INTENSITY_RANK = { "quick": 1, "deep": 2, "meticulous": 3 };

function toggleAggressivePreset(key) {
  const p = AGGRESSIVE_PRESETS[key];
  if (!p) return;
  if (state.activePresets.has(key)) state.activePresets.delete(key);
  else state.activePresets.add(key);
  refreshAggressiveState();
}

function refreshAggressiveState() {
  const active = [...state.activePresets].map((k) => AGGRESSIVE_PRESETS[k]).filter(Boolean);
  document.querySelectorAll(".ahBtn").forEach((b) => {
    const on = state.activePresets.has(b.dataset.hunt);
    b.classList.toggle("ahActive", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
  });
  if (!active.length) return;  // niente attivo: lascio il form allo stato corrente
  // Prendi il MASSIMO di intensity e pages, unisci moduli (dedup)
  let intensity = "quick", pages = 0;
  const modules = new Set();
  for (const p of active) {
    if ((INTENSITY_RANK[p.intensity] || 0) > (INTENSITY_RANK[intensity] || 0)) intensity = p.intensity;
    if (p.pages > pages) pages = p.pages;
    (p.modules || []).forEach((m) => modules.add(m));
  }
  // Applica il "modo" del PRIMO preset attivato (senno' e' confondente)
  const first = active[0];
  applyMode(first.mode);
  if ($("targetType")) $("targetType").value = first.type;
  if ($("intensity"))  $("intensity").value  = intensity;
  if ($("maxPages"))   $("maxPages").value   = String(pages);
  if ($("provider"))   $("provider").value   = "all";
  // Rendi disponibili le opzioni avanzate (i moduli combinati verranno mandati dal payload)
  const adv = document.querySelector(".formAdvanced");
  if (adv) adv.setAttribute("open", "open");
  state.activeModules = [...modules];  // consumato in payload()
  // Contatore visivo
  const counter = document.getElementById("ahCounter");
  if (counter) counter.textContent = t("inv.ah.activeCount", { presets: active.length, modules: modules.size });
  // Focus sul primo input rilevante
  const focusMap = {
    handle:  ".socialBtn",
    contact: ".email-input, .phone-input",
    domain:  "#genericTarget",
    crypto:  "#genericTarget",
    media:   "#mediaFileInline",
  };
  const sel = focusMap[first.mode];
  if (sel) {
    const el = document.querySelector(sel);
    if (el && !el.matches(":focus")) el.scrollIntoView({behavior: "smooth", block: "center"});
  }
}

// Backwards-compat: alcuni handler chiamano il nome vecchio.
const applyAggressivePreset = toggleAggressivePreset;

// Delegation globale: click su qualsiasi .ahBtn TOGGLA il preset
document.addEventListener("click", (e) => {
  const btn = e.target && e.target.closest && e.target.closest(".ahBtn");
  if (btn && btn.dataset.hunt) toggleAggressivePreset(btn.dataset.hunt);
});

// --- Admin unlock (sblocca la sezione "Ricerca aggressiva") ---------------
// Nessuna persistenza: chiudendo la scheda la sezione torna bloccata.
// La password NON viene mai salvata in JS storage; e' verificata server-side.
function openAdminUnlockModal() {
  const m = $("adminUnlockModal");
  if (!m) return;
  m.classList.remove("hidden");
  const msg = $("adminUnlockMsg"); if (msg) msg.textContent = "";
  const u = $("adminUser"); if (u) u.value = "";
  const p = $("adminPass"); if (p) { p.value = ""; setTimeout(() => u && u.focus(), 60); }
}

function closeAdminUnlockModal() {
  const m = $("adminUnlockModal"); if (m) m.classList.add("hidden");
  const p = $("adminPass"); if (p) p.value = ""; // non lasciare la password nel DOM
}

async function submitAdminUnlock() {
  const u = ($("adminUser") && $("adminUser").value.trim()) || "";
  const p = ($("adminPass") && $("adminPass").value) || "";
  const msg = $("adminUnlockMsg");
  if (msg) msg.textContent = "";
  if (!u || !p) { if (msg) msg.textContent = "Compila username e password."; return; }
  try {
    await api("/api/admin/unlock", { method: "POST",
      body: JSON.stringify({ username: u, password: p }) });
    // Successo: rimuovo il gate + nascondo il teaser
    const box = $("aggressiveHunt");
    if (box) { box.removeAttribute("data-locked"); box.hidden = false; }
    const teaser = $("ahLockedTeaser"); if (teaser) teaser.hidden = true;
    closeAdminUnlockModal();
  } catch (err) {
    if (msg) msg.textContent = (err && err.message) || "Credenziali non valide.";
  }
}

if ($("ahUnlockBtn")) $("ahUnlockBtn").addEventListener("click", openAdminUnlockModal);
if ($("adminUnlockSubmit")) $("adminUnlockSubmit").addEventListener("click", submitAdminUnlock);
if ($("adminUnlockCancel")) $("adminUnlockCancel").addEventListener("click", closeAdminUnlockModal);
if ($("adminPass")) $("adminPass").addEventListener("keydown", (e) => {
  if (e.key === "Enter") submitAdminUnlock();
});
// Cliccando fuori dal box chiude
if ($("adminUnlockModal")) $("adminUnlockModal").addEventListener("click", (e) => {
  if (e.target && e.target.id === "adminUnlockModal") closeAdminUnlockModal();
});

// Mostra il badge "dato personale + base giuridica" quando rilevante
function updatePrivacyBadge() {
  const badge = $("privacyBadge"); const msg = $("privacyMsg");
  if (!badge || !msg) return;
  const mode = state.currentMode;
  const hasCase = !!($("currentCase") && $("currentCase").value);
  const personal = ["contact"].includes(mode) ||
    ["email","phone","person"].includes(($("targetType") && $("targetType").value) || "");
  if (!personal) { badge.classList.add("hidden"); return; }
  badge.classList.remove("hidden");
  if (hasCase) {
    badge.dataset.state = "ok";
    msg.textContent = t("pb.caseSelected");
  } else {
    badge.dataset.state = "warn";
    msg.textContent = t("pb.needCase");
  }
}

function buildSocialGrid() {
  const grid = $("socialGrid");
  if (!grid) return;
  grid.innerHTML = SOCIAL_NETWORKS.map((s) =>
    `<button type="button" class="socialBtn" data-social="${s.id}">${escapeHtml(s.label)}</button>`
  ).join("");
  grid.querySelectorAll(".socialBtn").forEach((btn) => {
    btn.addEventListener("click", () => toggleSocialInput(btn.dataset.social));
  });
}

function toggleSocialInput(socialId) {
  const network = SOCIAL_NETWORKS.find((s) => s.id === socialId);
  if (!network) return;
  const grid = $("socialGrid");
  const btn = grid.querySelector(`[data-social="${socialId}"]`);
  if (btn) btn.classList.add("active");
  const wrapper = $("socialInputs");
  let row = wrapper.querySelector(`[data-input-for="${socialId}"]`);
  if (row) {
    row.querySelector("input").focus();
    return;
  }
  row = document.createElement("div");
  row.className = "socialInputRow";
  row.dataset.inputFor = socialId;
  row.innerHTML = `
    <label>${escapeHtml(network.label)}
      <input type="text" placeholder="${network.prefix}handle">
    </label>
    <button type="button" class="iconButton socialRemove" title="Rimuovi">×</button>
  `;
  const input = row.querySelector("input");
  input.addEventListener("input", (e) => {
    state.socialHandles[socialId] = e.target.value;
  });
  row.querySelector(".socialRemove").addEventListener("click", () => {
    delete state.socialHandles[socialId];
    row.remove();
    if (btn) btn.classList.remove("active");
  });
  wrapper.appendChild(row);
  input.focus();
}

function gradeTier(reliability, credibility) {
  // Coarse buckets for visualisation: gold (A1-B2) → green ring,
  // solid (B3-C2) → cyan, candidate (C3-D4) → amber, weak (D5-F6) → grey.
  const code = `${reliability || "F"}${credibility || 6}`;
  if (["A1", "A2", "B1", "B2"].includes(code)) return "gold";
  if (["B3", "C1", "C2"].includes(code)) return "solid";
  if (["C3", "D1", "D2", "D3", "D4"].includes(code)) return "candidate";
  return "weak";
}

function setModules(values) {
  const selected = new Set(values);
  document.querySelectorAll(".module").forEach((item) => {
    item.checked = selected.has(item.value);
  });
}

// ----------------------------------------------------------------- API keys

async function loadApiKeys() {
  const catalog = $("keysCatalog");
  const status = $("keysStatus");
  const count = $("keysCount");
  if (!catalog) return;
  catalog.textContent = "Carico…";
  try {
    const data = await api("/api/keys", { method: "GET" });
    renderApiKeys(data.catalog || [], data.keys || []);
    count.textContent = t("ky.configured", { n: (data.keys || []).length });
    // Lo stato copertura usa la response di /api/capabilities che ora
    // contiene lo stato semantico (state, message, last4, ...) per provider.
    try {
      const caps = await api("/api/capabilities", { method: "GET" });
      renderApiKeyStatus(caps.search_providers || []);
      // Aggiorno anche il pannello capabilities (in tab Investigate).
      renderCapabilitiesPanel(caps);
    } catch (capsErr) {
      status.textContent = t("ky.coverageUnavail") + (capsErr.message || capsErr);
    }
  } catch (exc) {
    catalog.textContent = t("err.loading") + (exc.message || exc);
    if (status) status.textContent = "";
  }
}

function renderApiKeys(catalog, keys) {
  const byService = Object.fromEntries(keys.map((k) => [k.service, k]));
  const container = $("keysCatalog");
  container.innerHTML = "";
  const byCategory = {};
  for (const entry of catalog) {
    const cat = entry.category || t("ky.other");
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(entry);
  }
  for (const [category, items] of Object.entries(byCategory)) {
    const heading = document.createElement("h3");
    heading.textContent = category;
    heading.className = "keysCategory";
    container.appendChild(heading);
    for (const entry of items) {
      container.appendChild(buildKeyRow(entry, byService[entry.service]));
    }
  }
}

function buildKeyRow(entry, current) {
  const wrap = document.createElement("div");
  wrap.className = "keyRow";
  wrap.dataset.service = entry.service;
  if (current) wrap.dataset.configured = "1";

  const label = document.createElement("label");
  label.textContent = entry.label;
  wrap.appendChild(label);

  const input = document.createElement("input");
  input.type = "password";
  input.autocomplete = "off";
  input.placeholder = current ? current.masked : t("ky.pastePlaceholder", { label: entry.label });
  input.dataset.service = entry.service;
  wrap.appendChild(input);

  const actions = document.createElement("div");
  actions.className = "keyActions";

  const save = document.createElement("button");
  save.type = "button";
  save.className = "smallAction";
  save.textContent = t("ky.save");
  save.addEventListener("click", async () => {
    save.disabled = true;
    try { await saveApiKey(entry.service, input.value, { andTest: true }); }
    finally { save.disabled = false; }
  });
  actions.appendChild(save);

  const test = document.createElement("button");
  test.type = "button";
  test.className = "smallAction secondary";
  test.textContent = "Test";
  test.title = t("ky.testTip");
  test.addEventListener("click", async () => {
    test.disabled = true;
    try { await testApiKey(entry.service, input.value); }
    finally { test.disabled = false; }
  });
  actions.appendChild(test);

  if (current) {
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "smallAction danger";
    remove.textContent = t("ky.remove");
    remove.addEventListener("click", async () => {
      if (!confirm(t("ky.removeConfirm", { label: entry.label }))) return;
      remove.disabled = true;
      try { await saveApiKey(entry.service, ""); }
      finally { remove.disabled = false; }
    });
    actions.appendChild(remove);
  }

  const doc = document.createElement("a");
  doc.href = entry.doc;
  doc.target = "_blank";
  doc.rel = "noopener noreferrer";
  doc.className = "smallLink";
  doc.textContent = "Ottieni chiave";
  actions.appendChild(doc);

  wrap.appendChild(actions);

  // Slot per il risultato del test (popolato da testApiKey/saveApiKey).
  const result = document.createElement("div");
  result.className = "keyResult muted";
  result.dataset.role = "key-result";
  result.textContent = current
    ? t("ky.saved", { masked: current.masked, updated: current.updated_at || "?" })
    : t("ky.noneSaved");
  wrap.appendChild(result);

  return wrap;
}

// --------- Stato copertura provider (pannello "Stato copertura" + Investigate)

const PROVIDER_STATE_LABELS = {
  not_configured:  { key: "ps.not_configured", cls: "neutral" },
  untested:        { key: "ps.untested", cls: "warn" },
  ok:              { key: "ps.ok", cls: "ok" },
  auth_error:      { key: "ps.auth_error", cls: "ko" },
  quota_exceeded:  { key: "ps.quota_exceeded", cls: "warn" },
  network_error:   { key: "ps.network_error", cls: "ko" },
  unsupported:     { key: "ps.unsupported", cls: "neutral" },
};

function providerBadge(state) {
  const cfg = PROVIDER_STATE_LABELS[state];
  const span = document.createElement("span");
  span.className = `providerBadge ${cfg ? cfg.cls : "neutral"}`;
  span.textContent = cfg ? t(cfg.key) : (state || "—");
  return span;
}

function renderApiKeyStatus(providers) {
  const status = $("keysStatus");
  if (!status) return;
  status.innerHTML = "";
  // Salto "all" — è meta, non un provider reale.
  const real = providers.filter((p) => p.service && p.service !== "all");
  if (!real.length) {
    status.textContent = t("ky.noProviders");
    return;
  }
  for (const p of real) {
    const card = document.createElement("div");
    card.className = "capability providerCard";
    card.dataset.state = p.state || "not_configured";

    const head = document.createElement("div");
    head.className = "providerHead";
    const name = document.createElement("strong");
    name.textContent = p.label || p.name;
    head.appendChild(name);
    head.appendChild(providerBadge(p.state));
    card.appendChild(head);

    const meta = document.createElement("div");
    meta.className = "providerMeta";
    const last4 = p.last4 ? ` · ${"•".repeat(6)}${p.last4}` : "";
    const lat = (p.latency_ms != null) ? ` · ${p.latency_ms}ms` : "";
    const when = p.checked_at ? ` · check ${p.checked_at}` : "";
    meta.textContent = (p.message || "—") + last4 + lat + when;
    card.appendChild(meta);

    if (p.category) {
      const cat = document.createElement("span");
      cat.className = "tag muted";
      cat.textContent = p.category;
      card.appendChild(cat);
    }

    status.appendChild(card);
  }
}

function renderCapabilitiesPanel(caps) {
  const target = $("capabilities");
  if (!target) return;
  target.innerHTML = "";
  // Providers
  for (const p of (caps.search_providers || [])) {
    if (!p.service || p.service === "all") continue;
    const card = document.createElement("div");
    card.className = "capability";
    const name = document.createElement("strong");
    name.textContent = p.label || p.name;
    name.appendChild(document.createTextNode(" "));
    name.appendChild(providerBadge(p.state));
    card.appendChild(name);
    const span = document.createElement("span");
    span.textContent = p.message || "";
    card.appendChild(span);
    target.appendChild(card);
  }
  // Tools CLI (con pallini classici)
  for (const t of (caps.tools || [])) {
    const card = document.createElement("div");
    card.className = "capability";
    const cls = t.available ? "ok" : "ko";
    const tip = t.available ? "disponibile" : (t.health_reason || "non disponibile");
    card.innerHTML = `<strong>${escapeHtml(t.name)}<span class="statusDot ${cls}" title="${escapeHtml(tip)}"></span></strong>
                      <span>${t.available ? "disponibile" : escapeHtml(t.env_var)}</span>`;
    target.appendChild(card);
  }
}

// --------------------------------------------------------------------- cases

async function loadCases() {
  const list = $("casesList");
  if (!list) return;
  list.textContent = "Carico…";
  try {
    const data = await api("/api/cases", { method: "GET" });
    state.cases = data.cases || [];
    renderCasesList(state.cases);
    populateCaseSelector(state.cases);
  } catch (exc) {
    list.textContent = t("err.generic") + (exc.message || exc);
  }
}

function renderCasesList(cases) {
  const list = $("casesList");
  const count = $("casesCount");
  count.textContent = `${cases.length}`;
  list.innerHTML = "";
  if (!cases.length) {
    list.textContent = t("cs.noCases");
    return;
  }
  for (const c of cases) {
    const card = document.createElement("div");
    card.className = "job";
    card.dataset.status = c.status || "open";

    // Bottone cancella (in alto a destra, allineato al pattern .jobDeleteBtn)
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "jobDeleteBtn caseDelBtn";
    delBtn.title = t("cs.delTitle");
    delBtn.textContent = "🗑";
    delBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteCase(c.id, c.title);
    });
    card.appendChild(delBtn);

    const title = document.createElement("strong");
    title.textContent = c.title;
    card.appendChild(title);

    const meta = document.createElement("div");
    meta.style.color = "var(--muted)";
    meta.style.fontSize = "12px";
    const lb = (c.legal_basis && c.legal_basis.type) ? c.legal_basis.type : "—";
    const ref = (c.legal_basis && c.legal_basis.reference) ? ` · ${c.legal_basis.reference}` : "";
    const collab = (c.collaborators || []).length ? ` · ${t("cs.collabLabel")}: ${(c.collaborators || []).join(", ")}` : "";
    meta.textContent = `${c.status} · ${t("cs.basisLabel")}: ${lb}${ref}${collab}`;
    card.appendChild(meta);

    if (c.purpose) {
      const purpose = document.createElement("div");
      purpose.textContent = c.purpose;
      purpose.style.marginTop = "6px";
      card.appendChild(purpose);
    }

    // Scope editor inline (toggle expand)
    const scopeBtn = document.createElement("button");
    scopeBtn.type = "button";
    scopeBtn.className = "smallAction secondary";
    scopeBtn.textContent = (c.allowed_targets && c.allowed_targets.length)
      ? t("cs.scopeEdit", { n: c.allowed_targets.length })
      : t("cs.scopeEmpty");
    scopeBtn.style.marginTop = "10px";
    scopeBtn.style.marginRight = "8px";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "smallAction";
    useBtn.textContent = t("cs.useForSearch");
    useBtn.style.marginTop = "10px";
    useBtn.addEventListener("click", () => selectCaseAndGoToSearch(c.id));

    card.appendChild(scopeBtn);
    card.appendChild(useBtn);

    // Consenso IA per-caso (opt-in, indipendente dal kill-switch server —
    // vedi web.py:_require_ai_agents_enabled). Il toggle fallisce chiuso:
    // se il deployment ha OSINT_AI_AGENTS_ENABLED=0 la chiamata risponde
    // 404 e il checkbox torna allo stato precedente.
    const aiRow = document.createElement("label");
    aiRow.className = "caseAiToggle";
    const aiCheckbox = document.createElement("input");
    aiCheckbox.type = "checkbox";
    aiCheckbox.checked = !!c.ai_enrichment_enabled;
    aiRow.appendChild(aiCheckbox);
    const aiLabelSpan = document.createElement("span");
    aiLabelSpan.dataset.i18n = "ai.caseSettings.toggle";
    aiLabelSpan.textContent = t("ai.caseSettings.toggle");
    aiRow.appendChild(aiLabelSpan);
    const aiMsg = document.createElement("div");
    aiMsg.className = "caseAiToggleMsg muted";
    aiMsg.hidden = true;
    aiCheckbox.addEventListener("change", () => setCaseAiEnrichment(c.id, aiCheckbox.checked, aiCheckbox, aiMsg));
    card.appendChild(aiRow);
    card.appendChild(aiMsg);

    const scopeBox = document.createElement("div");
    scopeBox.className = "caseScopeBox hidden";
    const taId = `caseScope-${c.id}`;
    const msgId = `caseScopeMsg-${c.id}`;
    const current = (c.allowed_targets || []).join("\n");
    scopeBox.innerHTML = `
      <label class="wideLabel">${t("cases.scope")}
        <textarea id="${taId}" rows="5">${escapeHtml(current)}</textarea>
      </label>
      <p class="modeHint">${t("cs.formats")}</p>
      <div class="actions">
        <button type="button" class="smallAction" data-action="save-scope">${t("cs.saveScope")}</button>
      </div>
      <p id="${msgId}" class="authMessage"></p>
    `;
    card.appendChild(scopeBox);

    scopeBtn.addEventListener("click", () => {
      scopeBox.classList.toggle("hidden");
    });
    scopeBox.querySelector('[data-action="save-scope"]').addEventListener("click",
      () => updateCaseScope(c.id, taId, msgId));

    list.appendChild(card);
  }
}

async function setCaseAiEnrichment(caseId, enabled, checkboxEl, msgEl) {
  try {
    const updated = await api(`/api/cases/${caseId}/ai-settings`, {
      method: "POST",
      body: JSON.stringify({ ai_enrichment_enabled: enabled }),
    });
    const idx = state.cases.findIndex((c) => c.id === caseId);
    if (idx >= 0) state.cases[idx] = updated;
    updateAiNarrativeButtonVisibility();
    if (msgEl) { msgEl.hidden = true; msgEl.textContent = ""; }
  } catch (exc) {
    if (checkboxEl) checkboxEl.checked = !enabled;
    console.error("setCaseAiEnrichment failed:", exc.message || exc);
    // 404 qui è il kill-switch server-side (OSINT_AI_AGENTS_ENABLED=0), non un
    // errore generico: senza distinguerlo il checkbox tornava indietro in
    // silenzio (solo un tooltip invisibile) e sembrava "non fare nulla".
    const message = exc.status === 404 ? t("ai.caseSettings.serverDisabled") : t("err.generic") + (exc.message || exc);
    if (checkboxEl) checkboxEl.title = message;
    if (msgEl) {
      msgEl.hidden = false;
      msgEl.textContent = message;
      msgEl.style.color = "var(--danger)";
    }
  }
}

function updateAiNarrativeButtonVisibility() {
  const job = state.currentJobData;
  const caseObj = job && job.case_id ? (state.cases || []).find((c) => c.id === job.case_id) : null;
  const eligible = !!(job && job.status === "complete" && caseObj && caseObj.ai_enrichment_enabled);

  const narrativeBtn = $("aiNarrativeBtn");
  if (narrativeBtn) {
    narrativeBtn.classList.toggle("hidden", !eligible);
    if (!eligible) { const p = $("aiNarrativePanel"); if (p) p.classList.add("hidden"); }
  }
  const triageBtn = $("aiTriageBtn");
  if (triageBtn) {
    triageBtn.classList.toggle("hidden", !eligible);
    if (!eligible) { const p = $("aiTriagePanel"); if (p) p.classList.add("hidden"); }
  }
}

async function updateSealUI(jobId, job) {
  const badge = $("sealBadge");
  const tsaBtn = $("tsaTimestampBtn");
  const panel = $("sealPanel");
  if (!badge || !tsaBtn) return;
  state.currentSeal = null;
  if (!job || job.status !== "complete") {
    badge.classList.add("hidden");
    tsaBtn.classList.add("hidden");
    if (panel) panel.classList.add("hidden");
    return;
  }
  try {
    const seal = await api(`/api/jobs/${jobId}/seal`);
    state.currentSeal = seal;
    badge.classList.remove("hidden");
    const tsaConfigured = !!(state.reportSealing && state.reportSealing.tsa_configured);
    const alreadyTimestamped = !!seal.tsa_gen_time;
    tsaBtn.classList.toggle("hidden", !(tsaConfigured && !alreadyTimestamped));
  } catch (exc) {
    // Job appena completato: il sigillo automatico potrebbe non essere
    // ancora scritto, o essere fallito (report_seal_failed in audit) — non
    // e' un errore da mostrare all'analista, solo un badge assente.
    badge.classList.add("hidden");
    tsaBtn.classList.add("hidden");
    if (panel) panel.classList.add("hidden");
  }
}

function renderSealBody(seal) {
  const body = $("sealBody");
  if (!body) return;
  const rows = [
    [t("seal.field.sealedAt"), seal.sealed_at],
    [t("seal.field.fingerprint"), seal.signing_pubkey_fingerprint],
    [t("seal.field.manifestHash"), seal.manifest_hash],
    [t("seal.field.artifactCount"), String(seal.artifact_count)],
  ];
  if (seal.tsa_gen_time) {
    rows.push([t("seal.field.tsaHost"), seal.tsa_url_host]);
    rows.push([t("seal.field.tsaGenTime"), seal.tsa_gen_time]);
  }
  if (seal.tsa_status) {
    rows.push([t("seal.field.tsaStatus"), seal.tsa_status]);
  }
  const rowsHtml = rows.map(([label, value]) =>
    `<div class="sealRow"><span class="sealLabel">${escapeHtml(label)}</span><code class="sealValue">${escapeHtml(String(value || ""))}</code></div>`
  ).join("");
  body.innerHTML = rowsHtml + `<pre class="sealHint">${escapeHtml(seal.verify_hint || "")}</pre>`;
}

function toggleSealPanel() {
  const panel = $("sealPanel");
  if (!panel) return;
  panel.classList.toggle("hidden");
  if (!panel.classList.contains("hidden") && state.currentSeal) renderSealBody(state.currentSeal);
}

async function requestTsaTimestamp() {
  const job = state.currentJobData;
  if (!job) return;
  const btn = $("tsaTimestampBtn");
  const panel = $("sealPanel");
  const body = $("sealBody");
  if (!btn || !panel || !body) return;
  if (!window.confirm(t("seal.tsa.confirm"))) return;

  btn.disabled = true;
  panel.classList.remove("hidden");
  body.textContent = t("common.loading");
  try {
    const seal = await api(`/api/jobs/${job.id}/seal/tsa-timestamp`, { method: "POST" });
    state.currentSeal = seal;
    renderSealBody(seal);
    updateSealUI(job.id, job);
  } catch (exc) {
    body.textContent = t("seal.tsa.failed", { error: exc.message || String(exc) });
  } finally {
    btn.disabled = false;
  }
}

async function generateAiNarrative() {
  const job = state.currentJobData;
  if (!job || !job.case_id) return;
  const btn = $("aiNarrativeBtn");
  const panel = $("aiNarrativePanel");
  const body = $("aiNarrativeBody");
  if (!btn || !panel || !body) return;

  const providerLabel = window.prompt(t("ai.narrative.providerPrompt"), "anthropic");
  if (!providerLabel) return;
  const provider = providerLabel.trim().toLowerCase();
  if (!["anthropic", "openai", "local"].includes(provider)) {
    alert(t("ai.narrative.invalidProvider"));
    return;
  }
  if (!window.confirm(t("ai.narrative.confirmSend", { provider }))) return;

  btn.disabled = true;
  body.textContent = t("common.loading");
  panel.classList.remove("hidden");
  try {
    const result = await api("/api/ai/narrative", {
      method: "POST",
      body: JSON.stringify({
        case_id: job.case_id, job_id: job.id, provider,
        lang: (window.I18N && window.I18N.get()) || "it",
      }),
    });
    renderAiNarrative(result, body);
  } catch (exc) {
    body.textContent = t("ai.narrative.failed", { error: exc.message || String(exc) });
  } finally {
    btn.disabled = false;
  }
}

function renderAiNarrative(result, bodyEl) {
  const narrative = result.narrative || {};
  const parts = [];
  if (result.truncated) {
    parts.push(`<p class="modeHint">${escapeHtml(t("ai.narrative.truncatedNote", {
      sent: result.finding_count_sent, total: result.total_available,
    }))}</p>`);
  }
  if (narrative.summary_paragraph) {
    parts.push(`<p>${linkifyCitations(narrative.summary_paragraph)}</p>`);
  }
  for (const section of narrative.sections || []) {
    parts.push(`<h4>${escapeHtml(section.heading || "")}</h4>`);
    parts.push(`<p>${linkifyCitations(section.body || "")}</p>`);
  }
  if ((narrative.caveats || []).length) {
    parts.push(`<ul class="aiCaveats">${narrative.caveats.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>`);
  }
  bodyEl.innerHTML = parts.join("\n");
}

function linkifyCitations(text) {
  return escapeHtml(text).replace(/\[F#([\w.#-]+)\]/g, (match, fid) =>
    `<span class="aiCitation" title="${escapeHtml(fid)}">[F#${escapeHtml(fid)}]</span>`);
}

const AI_TRIAGE_BUCKET_ORDER = ["critical_now", "high", "medium", "low", "noise"];
const AI_TRIAGE_BUCKET_CLASS = {
  critical_now: "triageCritical", high: "triageHigh", medium: "triageMedium",
  low: "triageLow", noise: "triageNoise",
};

async function generateAiTriage() {
  const job = state.currentJobData;
  if (!job || !job.case_id) return;
  const btn = $("aiTriageBtn");
  const panel = $("aiTriagePanel");
  const body = $("aiTriageBody");
  if (!btn || !panel || !body) return;

  const providerLabel = window.prompt(t("ai.narrative.providerPrompt"), "anthropic");
  if (!providerLabel) return;
  const provider = providerLabel.trim().toLowerCase();
  if (!["anthropic", "openai", "local"].includes(provider)) {
    alert(t("ai.narrative.invalidProvider"));
    return;
  }
  if (!window.confirm(t("ai.triage.confirmSend", { provider }))) return;

  btn.disabled = true;
  body.textContent = t("common.loading");
  panel.classList.remove("hidden");
  try {
    const result = await api("/api/ai/triage", {
      method: "POST",
      body: JSON.stringify({
        case_id: job.case_id, job_id: job.id, provider,
        lang: (window.I18N && window.I18N.get()) || "it",
      }),
    });
    renderAiTriage(result, body, (state.lastReport && state.lastReport.findings) || []);
  } catch (exc) {
    body.textContent = t("ai.narrative.failed", { error: exc.message || String(exc) });
  } finally {
    btn.disabled = false;
  }
}

function renderAiTriage(result, bodyEl, findings) {
  const rankings = result.rankings || [];
  const coverage = result.coverage || {};
  if (!rankings.length) {
    bodyEl.innerHTML = `<p class="modeHint">${escapeHtml(t("ai.triage.noRankings"))}</p>`;
    return;
  }

  const byBucket = {};
  AI_TRIAGE_BUCKET_ORDER.forEach((b) => { byBucket[b] = []; });
  rankings.forEach((r) => { (byBucket[r.priority_bucket] || byBucket.noise).push(r); });

  const findingLabel = (findingId) => {
    const idx = Number(String(findingId).split("#").pop());
    const f = Number.isInteger(idx) ? findings[idx] : null;
    return f ? `${escapeHtml(f.kind)}: ${escapeHtml(String(f.value).slice(0, 100))}` : escapeHtml(findingId);
  };

  const renderRow = (r) => {
    const rationale = r.fallback ? t("ai.triage.fallbackRationale") : r.rationale;
    return `
      <div class="triageRow ${AI_TRIAGE_BUCKET_CLASS[r.priority_bucket] || "triageNoise"}" title="${escapeHtml(rationale)}">
        <span class="triageBadge">${escapeHtml(t("ai.triage.bucket." + r.priority_bucket))}</span>
        <span class="triageLabel">${findingLabel(r.finding_id)}</span>
      </div>`;
  };

  const sections = [];
  for (const bucket of AI_TRIAGE_BUCKET_ORDER) {
    const rows = byBucket[bucket];
    if (!rows.length) continue;
    if (bucket === "noise") {
      sections.push(`
        <details class="triageNoiseGroup">
          <summary>${escapeHtml(t("ai.triage.showMore", { n: rows.length }))}</summary>
          ${rows.map(renderRow).join("")}
        </details>`);
    } else {
      sections.push(rows.map(renderRow).join(""));
    }
  }

  const coverageNote = (coverage.fallback_ranked || coverage.dropped_hallucinated)
    ? `<p class="modeHint">${escapeHtml(t("ai.triage.coverageNote", {
        ai: coverage.ai_ranked || 0, total: coverage.total || 0,
      }))}</p>`
    : "";

  bodyEl.innerHTML = coverageNote + sections.join("");
}

function populateCaseSelector(cases) {
  const sel = $("currentCase");
  if (!sel) return;
  const previous = sel.value;
  sel.innerHTML = "";
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = t("cs.defaultCase");
  sel.appendChild(blank);
  for (const c of cases) {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.title;
    sel.appendChild(opt);
  }
  if (previous && cases.find((c) => c.id === previous)) sel.value = previous;
}

function selectCaseAndGoToSearch(caseId) {
  const sel = $("currentCase");
  if (sel) sel.value = caseId;
  const investigateNav = document.querySelector('.nav[data-panel="investigate"]');
  if (investigateNav) investigateNav.click();
}

async function createCase() {
  const msg = $("caseCreateMsg");
  msg.textContent = "";
  const title = $("caseTitle").value.trim();
  if (!title) { msg.textContent = t("cs.titleRequired"); return; }
  const collabs = $("caseCollabs").value.split(",").map((s) => s.trim()).filter(Boolean);
  const body = {
    title,
    purpose: $("casePurpose").value.trim(),
    legal_basis: {
      type: $("caseLegalType").value,
      reference: $("caseLegalRef").value.trim(),
    },
    collaborators: collabs,
    retention_until: $("caseRetention").value.trim() || null,
  };
  // Scope autorizzato (una voce per riga)
  const allowedRaw = ($("caseAllowedTargets") && $("caseAllowedTargets").value) || "";
  body.allowed_targets = allowedRaw.split("\n").map((s) => s.trim()).filter(Boolean);

  try {
    await api("/api/cases", { method: "POST", body: JSON.stringify(body) });
    $("caseTitle").value = "";
    $("casePurpose").value = "";
    $("caseLegalRef").value = "";
    $("caseCollabs").value = "";
    $("caseRetention").value = "";
    if ($("caseAllowedTargets")) $("caseAllowedTargets").value = "";
    msg.textContent = t("cs.created");
    msg.style.color = "var(--green)";
    await loadCases();
  } catch (exc) {
    msg.textContent = t("err.generic") + (exc.message || exc);
    msg.style.color = "var(--danger)";
  }
}

// ---- Scope editor inline per caso esistente ----

async function updateCaseScope(caseId, allowedTextareaId, msgId) {
  const ta = document.getElementById(allowedTextareaId);
  const msgEl = document.getElementById(msgId);
  if (!ta) return;
  const allowed_targets = ta.value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (msgEl) { msgEl.textContent = t("cs.saving"); msgEl.style.color = ""; }
  try {
    const updated = await api(`/api/cases/${encodeURIComponent(caseId)}/scope`,
      { method: "POST", body: JSON.stringify({ allowed_targets }) });
    if (msgEl) {
      msgEl.textContent = t("cs.scopeUpdated", { n: (updated.allowed_targets || []).length });
      msgEl.style.color = "#21d07a";
    }
    await loadCases();
  } catch (exc) {
    if (msgEl) {
      msgEl.textContent = t("err.generic") + (exc.message || exc);
      msgEl.style.color = "#ff7a8a";
    }
  }
}

async function saveApiKey(service, value, opts = {}) {
  const trimmed = (value || "").trim();
  try {
    const data = await api("/api/keys", {
      method: "POST",
      body: JSON.stringify({ service, value: trimmed }),
    });
    renderApiKeys(data.catalog || [], data.keys || []);
    $("keysCount").textContent = t("ky.configured", { n: (data.keys || []).length });
    // Aggiorno subito lo stato copertura (passa per /api/capabilities che
    // restituisce gli stati semantici dei provider).
    if (trimmed && opts.andTest !== false) {
      // Salva → poi test reale (in serie, così l'utente vede il risultato).
      await testApiKey(service);
    } else {
      await refreshProviderStatus();
    }
  } catch (exc) {
    setKeyResult(service, t("ky.saveError") + (exc.message || exc), "ko");
  }
}

async function testApiKey(service, value) {
  const body = { service };
  const v = (value || "").trim();
  if (v) body.value = v;  // se passato, testa quella stringa senza salvarla
  setKeyResult(service, t("ky.probing"), "neutral");
  try {
    const status = await api("/api/keys/test", { method: "POST", body: JSON.stringify(body) });
    const cfg = PROVIDER_STATE_LABELS[status.state];
    const label = cfg ? t(cfg.key) : status.state;
    const cls = cfg ? cfg.cls : "neutral";
    const lat = status.latency_ms != null ? ` · ${status.latency_ms}ms` : "";
    const http = status.http_status != null ? ` · HTTP ${status.http_status}` : "";
    const last4 = status.last4 ? ` · ${"•".repeat(6)}${status.last4}` : "";
    setKeyResult(service, `${label}: ${status.message}${http}${lat}${last4}`, cls);
    await refreshProviderStatus();
  } catch (exc) {
    setKeyResult(service, t("ky.testFailed") + (exc.message || exc), "ko");
  }
}

function setKeyResult(service, text, cls) {
  const row = document.querySelector(`.keyRow[data-service="${CSS.escape(service)}"]`);
  if (!row) return;
  const slot = row.querySelector('[data-role="key-result"]');
  if (!slot) return;
  slot.className = `keyResult ${cls || "muted"}`;
  slot.textContent = text;
}

async function refreshProviderStatus() {
  try {
    const caps = await api("/api/capabilities", { method: "GET" });
    renderApiKeyStatus(caps.search_providers || []);
    renderCapabilitiesPanel(caps);
  } catch (exc) {
    // non bloccante
    console.warn("refreshProviderStatus failed:", exc);
  }
}

// ================================================================
// DASHBOARD
// ================================================================

// Dashboard server-backed: tutte le statistiche globali arrivano da
// /api/dashboard. Nessuna dipendenza da cache client-side (state.jobs/cases/
// _lastCaps): la dashboard è coerente anche senza aver visitato altri pannelli.
async function loadDashboard() {
  let data;
  try {
    data = await api("/api/dashboard");
  } catch (err) {
    renderDashError((err && err.message) ? err.message : t("db.loadError"));
    return;
  }
  populateDashCaseSelector(data.cases_select || []);
  const totals = data.totals || {};
  renderDashStats(data.stats || {}, totals.jobs || 0);
  renderDashCoverage(data.coverage || {});
  renderDashWarnings(data.warnings || []);
  renderDashRecentCases(data.recent_cases || [], totals.cases || 0);
  renderDashRecentJobs(data.recent_jobs || [], totals.jobs || 0);
  // Metriche riservate all'admin: se non sbloccato → 403, mostro un CTA
  // che apre il modal di sblocco. Se sbloccato → mostro i numeri.
  loadAdminStats();
}

async function loadAdminStats() {
  const box = document.getElementById("adminStatsBox");
  if (!box) return;
  try {
    const s = await api("/api/admin/stats");
    const u = s.users || {}, j = s.jobs || {}, a = s.audit || {};
    box.innerHTML = `
      <div class="capability" style="grid-column:1/-1"><strong>📊 ${t("db.metrics")}</strong></div>
      <div class="capability"><strong>${t("db.usersTotal")}</strong><span>${u.total ?? 0}</span></div>
      <div class="capability"><strong>${t("db.usersVerified")}</strong><span>${u.verified ?? 0}</span></div>
      <div class="capability"><strong>${t("db.active24h")}</strong><span>${u.active_24h ?? 0}</span></div>
      <div class="capability"><strong>${t("db.active7d")}</strong><span>${u.active_7d ?? 0}</span></div>
      <div class="capability"><strong>${t("db.signups7d")}</strong><span>${u.signups_7d ?? 0}</span></div>
      <div class="capability"><strong>${t("db.jobsTotal")}</strong><span>${j.total ?? 0}</span></div>
      <div class="capability"><strong>${t("db.jobsByStatus")}</strong><span>${
        Object.entries(j.by_status || {}).map(([k,v])=>`${k}: ${v}`).join(" · ") || "—"
      }</span></div>
      <div class="capability"><strong>Audit chain</strong><span>${a.chain_valid ? t("db.chainValid") : t("db.chainBroken")} (${a.events_total ?? 0} ${t("db.events")})</span></div>
      <div style="grid-column:1/-1">${renderLoginHistoryTable(s.logins || [])}</div>
      <div id="pendingErasuresBox" style="display:contents"></div>
    `;
    box.hidden = false;
    loadPendingErasures();
  } catch (err) {
    // 403 = non-admin: mostro CTA discreta.
    box.innerHTML = `
      <div class="capability" style="grid-column:1/-1;text-align:center;padding:14px">
        <span class="muted">📊 ${t("db.metricsLocked")} </span>
        <button type="button" class="btn" id="statsUnlockBtn" style="margin-left:8px">${t("db.unlock")}</button>
      </div>`;
    const b = document.getElementById("statsUnlockBtn");
    if (b) b.addEventListener("click", () => { if (typeof openAdminUnlockModal === "function") openAdminUnlockModal(); });
    box.hidden = false;
  }
}

const _LOGIN_HISTORY_ROW_CAP = 100;

function renderLoginHistoryTable(logins) {
  if (!logins.length) return "";
  const shown = logins.slice(0, _LOGIN_HISTORY_ROW_CAP);
  const providerLabel = (p) => (p === "google" ? "Google" : t("db.providerPassword"));
  const roleLabel = (r) => (r === "admin" ? `⚑ ${t("db.roleAdmin")}` : t("db.roleAnalyst"));
  const rows = shown.map((row) => `
    <tr>
      <td>${escapeHtml(row.username)}</td>
      <td>${escapeHtml(row.email || "—")}</td>
      <td>${roleLabel(row.role)}</td>
      <td>${providerLabel(row.provider)}</td>
      <td style="text-align:right">${row.login_count}</td>
      <td>${row.last_login ? escapeHtml(row.last_login) : t("db.neverLoggedIn")}</td>
    </tr>`).join("");
  const truncNote = logins.length > _LOGIN_HISTORY_ROW_CAP
    ? `<p class="muted" style="margin-top:6px">${t("db.loginHistoryTruncated", { shown: shown.length, total: logins.length })}</p>`
    : "";
  return `
    <div class="capability" style="grid-column:1/-1;margin-top:6px"><strong>👤 ${t("db.loginHistory")}</strong></div>
    <div style="overflow-x:auto">
      <table class="entityTable">
        <thead><tr>
          <th>${t("db.colUser")}</th>
          <th>${t("db.colEmail")}</th>
          <th>${t("db.colRole")}</th>
          <th>${t("db.colProvider")}</th>
          <th style="text-align:right">${t("db.colLoginCount")}</th>
          <th>${t("db.colLastLogin")}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="muted" style="margin-top:6px">${t("db.roleManageHint")}</p>
    ${truncNote}
  `;
}

// --- Richieste di cancellazione profilo in attesa (solo admin) -------------
// Le richieste GDPR art.17 degli utenti non partono più da sole: restano in
// "pending" finché un admin non le approva (esegue) o rifiuta qui.
async function loadPendingErasures() {
  const box = document.getElementById("pendingErasuresBox");
  if (!box) return;
  try {
    const data = await api("/api/admin/privacy/pending");
    const pending = data.pending || [];
    if (!pending.length) {
      box.innerHTML = `
        <div class="capability" style="grid-column:1/-1;margin-top:6px">
          <strong>🗑️ ${t("db.pendingErasures")}</strong><span>${t("db.noPendingErasures")}</span>
        </div>`;
      return;
    }
    const rows = pending.map((r) => `
      <tr>
        <td>${escapeHtml(r.owner || "—")}</td>
        <td>${escapeHtml(r.created_at || "—")}</td>
        <td>${escapeHtml(r.reason || "")}</td>
        <td style="text-align:right;white-space:nowrap">
          <button type="button" class="btn eraseApproveBtn" data-id="${escapeHtml(r.id)}"
            data-owner="${escapeHtml(r.owner || "")}"
            style="border-color:var(--danger);color:var(--danger)">${t("db.approve")}</button>
          <button type="button" class="btn eraseRejectBtn" data-id="${escapeHtml(r.id)}"
            style="margin-left:6px">${t("db.reject")}</button>
        </td>
      </tr>`).join("");
    box.innerHTML = `
      <div class="capability" style="grid-column:1/-1;margin-top:6px"><strong>🗑️ ${t("db.pendingErasures")} (${pending.length})</strong></div>
      <div style="grid-column:1/-1;overflow-x:auto">
        <table class="entityTable">
          <thead><tr>
            <th>${t("db.colUser")}</th>
            <th>${t("db.colRequestedAt")}</th>
            <th>${t("db.colReason")}</th>
            <th style="text-align:right">${t("db.colActions")}</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="muted" style="grid-column:1/-1;margin-top:4px">${t("db.erasureHint")}</p>`;
    box.querySelectorAll(".eraseApproveBtn").forEach((b) => {
      b.addEventListener("click", () => approvePrivacyErase(b.dataset.id, b.dataset.owner));
    });
    box.querySelectorAll(".eraseRejectBtn").forEach((b) => {
      b.addEventListener("click", () => rejectPrivacyErase(b.dataset.id));
    });
  } catch (err) {
    // 403 (non-admin) o altro: lascio vuoto — il box statistiche mostra già la
    // CTA di sblocco admin, non serve un secondo errore.
    box.innerHTML = "";
  }
}

async function approvePrivacyErase(id, owner) {
  if (!confirm(t("db.approveConfirm", { owner: owner || "?" }))) return;
  try {
    const data = await api("/api/admin/privacy/approve", {
      method: "POST", body: JSON.stringify({ request_id: id }),
    });
    alert(data.message || t("db.approveDone"));
  } catch (err) {
    alert(t("err.generic") + (err.message || err));
  } finally {
    loadPendingErasures();
  }
}

async function rejectPrivacyErase(id) {
  const note = prompt(t("db.rejectPrompt"));
  if (note === null) return; // annullato
  try {
    const data = await api("/api/admin/privacy/reject", {
      method: "POST", body: JSON.stringify({ request_id: id, note }),
    });
    alert(data.message || t("db.rejectDone"));
  } catch (err) {
    alert(t("err.generic") + (err.message || err));
  } finally {
    loadPendingErasures();
  }
}

function renderDashError(message) {
  ["dashStats", "dashCoverage", "dashWarnings", "dashCases", "dashJobs"].forEach((id) => {
    const el = $(id);
    if (el) el.innerHTML = `<div class="warnItem">${escapeHtml(message)}</div>`;
  });
}

function populateDashCaseSelector(cases) {
  const sel = $("dashCase");
  if (!sel) return;
  const previous = sel.value;
  sel.innerHTML = `<option value="">${t("dash.caseAuto")}</option>`;
  (cases || []).forEach((c) => {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.title;
    sel.appendChild(opt);
  });
  if (previous && (cases || []).some((c) => c.id === previous)) sel.value = previous;
}

function renderDashStats(stats, totalJobs) {
  const el = $("dashStats");
  const total = $("dashJobTotal");
  if (!el) return;
  if (total) total.textContent = totalJobs;
  el.innerHTML = [
    { key: "complete", k: "db.complete", cls: "complete" },
    { key: "running",  k: "db.running",  cls: "running" },
    { key: "error",    k: "st.error",    cls: "error" },
  ].map((s) => `
    <div class="statTile ${s.cls}">
      <span class="statN">${Number(stats[s.key] || 0)}</span>
      <span class="statLabel">${t(s.k)}</span>
    </div>
  `).join("");
}

function renderDashCoverage(coverage) {
  const el = $("dashCoverage");
  const tag = $("dashCoverageTag");
  if (!el) return;
  const pOk = Number(coverage.providers_configured || 0);
  const pTot = Number(coverage.providers_total || 0);
  const tOk = Number(coverage.tools_available || 0);
  const tTot = Number(coverage.tools_total || 0);
  if (tag) tag.textContent = `${pOk}/${pTot} API`;
  el.innerHTML = `
    <div class="coverageRow"><span>${t("db.providersConfigured")}</span><strong>${pOk} / ${pTot}</strong></div>
    <div class="coverageRow"><span>${t("db.toolsAvailable")}</span><strong>${tOk} / ${tTot}</strong></div>
    <p class="modeHint">${t("db.byokNote")}</p>`;
}

function renderDashWarnings(warnings) {
  const el = $("dashWarnings");
  if (!el) return;
  warnings = warnings || [];
  if (!warnings.length) {
    el.innerHTML = `<div class="warnItem ok">${t("db.noWarnings")}</div>`;
    return;
  }
  el.innerHTML = warnings.map((w) =>
    `<div class="warnItem ${escapeHtml(w.level || "info")}">${escapeHtml(w.message || "")}</div>`).join("");
}

function renderDashRecentCases(cases, totalCases) {
  const el = $("dashCases");
  const tag = $("dashCasesTag");
  if (!el) return;
  if (tag) tag.textContent = totalCases;
  if (!cases.length) { el.innerHTML = `<div class="empty">${t("db.noCases")}</div>`; return; }
  el.innerHTML = cases.map((c) => `
    <div class="job" data-status="${escapeHtml(c.status || "open")}" style="cursor:pointer" onclick="selectCaseAndGoToSearch('${escapeHtml(c.id)}')">
      <strong>${escapeHtml(c.title)}</strong>
      <span>${escapeHtml(c.status || t("db.open"))} · ${escapeHtml(c.legal_basis || "—")}</span>
    </div>
  `).join("");
}

function renderDashRecentJobs(jobs, totalJobs) {
  const el = $("dashJobs");
  const tag = $("dashJobsTag");
  if (!el) return;
  if (tag) tag.textContent = totalJobs;
  if (!jobs.length) { el.innerHTML = `<div class="empty">${t("db.noJobs")}</div>`; return; }
  el.innerHTML = jobs.map((j) => `
    <div class="job" data-status="${escapeHtml(j.status)}" style="cursor:pointer" onclick="openJobFromDash('${escapeHtml(j.id)}')">
      <strong>${escapeHtml(j.target || "—")} · ${escapeHtml(j.target_type || "")}</strong>
      <span>${escapeHtml(j.status)} · ${escapeHtml(j.updated_at || "")}</span>
    </div>
  `).join("");
}

function openJobFromDash(id) {
  document.querySelector('.nav[data-panel="jobs"]').click();
  selectJob(id);
}

// ================================================================
// GLOBAL SEARCH (dashboard search bar)
// ================================================================

const TYPE_PATTERNS = [
  [/^https?:\/\//i,                           "dt.url"],
  [/@[a-z0-9._-]+/i,                          "dt.username"],
  [/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i, "dt.email"],
  [/^\+?[\d\s\-().]{7,}$/,                    "dt.phone"],
  [/^(bc1|[13])[a-z0-9]{25,}/i,              "dt.btc"],
  [/^0x[a-f0-9]{40}/i,                        "dt.eth"],
  [/[a-f0-9]{32,64}/i,                        "dt.hash"],
  [/^(\d{1,3}\.){3}\d{1,3}/,                 "dt.ip"],
  [/[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+/i, "dt.domain"],
];

function updateDetectedType(value) {
  const el = $("detectedType");
  if (!el) return;
  const v = (value || "").trim();
  if (!v) { el.textContent = t("dash.detectedType"); return; }
  for (const [re, key] of TYPE_PATTERNS) {
    if (re.test(v)) { el.textContent = `${t("dt.prefix")} ${t(key)}`; return; }
  }
  el.textContent = `${t("dt.prefix")} ${t("dt.nameCompany")}`;
}

function routeGlobalSearch(value) {
  const v = (value || "").trim();
  if (!v) return;
  const caseId = ($("dashCase") && $("dashCase").value) || "";
  // Pre-fill investigate panel and navigate to it
  document.querySelector('.nav[data-panel="investigate"]').click();
  // Set target based on detected type
  const isEmail = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(v);
  const isHandle = /^@[a-z0-9._-]+/i.test(v);
  const isDomain = /[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+/i.test(v) && !isEmail;
  const isCrypto = /^(bc1|[13]|0x)[a-z0-9]{25,}/i.test(v);
  if (isEmail) {
    applyMode("contact");
    const first = document.querySelector(".email-input");
    if (first) first.value = v;
  } else if (isHandle || /^@/.test(v)) {
    applyMode("handle");
  } else if (isCrypto) {
    applyMode("crypto");
    if ($("genericTarget")) $("genericTarget").value = v;
  } else {
    applyMode("domain");
    if ($("genericTarget")) $("genericTarget").value = v;
  }
  if (caseId && $("currentCase")) $("currentCase").value = caseId;
}

// ================================================================
// ENTITY PROFILE
// ================================================================

function showEntityProfile(report) {
  if (!report) return;
  const empty = $("entityProfileEmpty");
  const card = $("entityProfileCard");
  if (!empty || !card) return;
  empty.classList.add("hidden");
  card.classList.remove("hidden");

  // Header
  const entities = report.entities || [];
  const target = report.target || "—";
  const targetType = report.target_type || "—";

  $("entityName").textContent = target;
  $("entityAvatar").textContent = target.charAt(0).toUpperCase() || "?";

  const badges = $("entityTypeBadges");
  if (badges) {
    badges.innerHTML = `<span class="typeBadge">${escapeHtml(targetType)}</span>`;
    const types = [...new Set(entities.map((e) => e.type))].slice(0, 4);
    types.forEach((t) => {
      if (t !== targetType) badges.insertAdjacentHTML("beforeend", `<span class="typeBadge">${escapeHtml(entityTypeLabel(t))}</span>`);
    });
  }

  // Confidence
  const avgConf = entities.length
    ? entities.reduce((sum, e) => sum + Number(e.confidence || 0), 0) / entities.length
    : 0;
  const confEl = $("entityConfidence");
  if (confEl) {
    const cls = avgConf >= 0.7 ? "high" : avgConf >= 0.4 ? "medium" : "low";
    confEl.innerHTML = `
      <div class="confBar">
        <span>${t("en.confidence")}</span>
        <div class="confTrack"><div class="confFill ${cls}" style="width:${Math.round(avgConf * 100)}%"></div></div>
        <strong>${Math.round(avgConf * 100)}%</strong>
      </div>
      <span style="color:var(--muted);font-size:12px">${t("en.entitiesFindings", { n: entities.length, f: (report.findings || []).length })}</span>
    `;
  }

  // Tabs
  const tabs = document.querySelectorAll(".entityTab");
  tabs.forEach((tabEl) => {
    tabEl.addEventListener("click", () => {
      tabs.forEach((x) => x.classList.remove("active"));
      tabEl.classList.add("active");
      renderEntityTab(tabEl.dataset.etab, report);
    });
  });

  // Pivot + report buttons
  const pivotBtn = $("entityPivotBtn");
  if (pivotBtn) {
    pivotBtn.onclick = () => {
      document.querySelector('.nav[data-panel="investigate"]').click();
      if ($("genericTarget")) $("genericTarget").value = target;
    };
  }

  // Render default tab
  renderEntityTab("overview", report);
  renderSuggestedActions(target, targetType, report);
  updateEntityAiTabVisibility();

  // Navigate to entity panel
  document.querySelector('.nav[data-panel="entity"]').click();
}

function updateEntityAiTabVisibility() {
  const tabBtn = document.querySelector('.entityTab[data-etab="ai-suggestions"]');
  if (!tabBtn) return;
  const job = state.currentJobData;
  const caseObj = job && job.case_id ? (state.cases || []).find((c) => c.id === job.case_id) : null;
  tabBtn.classList.toggle("hidden", !(caseObj && caseObj.ai_enrichment_enabled));
}

function renderEntityTab(tab, report) {
  const body = $("entityTabBody");
  if (!body) return;
  const entities = report.entities || [];
  const findings = report.findings || [];

  switch (tab) {
    case "overview":
      body.innerHTML = renderEntityOverview(report, entities, findings);
      break;
    case "identifiers":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["email", "phone", "ip", "domain", "url"].includes(e.type)),
        ["th.type", "th.value", "th.confidence", "th.sources"]
      );
      break;
    case "social":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["username", "handle", "social"].includes(e.type)),
        ["th.type", "th.value", "th.confidence", "th.network"]
      );
      break;
    case "domains":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["domain", "organization", "company"].includes(e.type)),
        ["th.type", "th.value", "th.confidence", "th.source"]
      );
      break;
    case "contacts":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["email", "phone"].includes(e.type)),
        ["th.type", "th.contact", "th.confidence", "th.visibility"]
      );
      break;
    case "media":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["media", "location", "image"].includes(e.type)),
        ["th.type", "th.value", "th.geo", "th.source"]
      );
      break;
    case "crypto":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["wallet", "btc", "eth", "crypto"].includes(e.type)),
        ["th.network", "th.address", "th.confidence", "th.source"]
      );
      break;
    case "evidences":
      body.innerHTML = renderEvidencesTab(findings);
      break;
    case "timeline":
      body.innerHTML = renderTimelineTab(entities);
      break;
    case "audit":
      body.innerHTML = renderAuditTab(report);
      break;
    case "ai-suggestions":
      body.innerHTML = renderAiSuggestionsTabShell();
      wireAiSuggestionsTab(report);
      break;
    default:
      body.innerHTML = `<div class="entityTabEmpty">${t("en.tabUnavailable")}</div>`;
  }
}

function renderAiSuggestionsTabShell() {
  return `
    <div class="aiSuggestionsIntro">
      <p class="modeHint">${escapeHtml(t("ai.entity.intro"))}</p>
      <button type="button" id="aiEntitySuggestBtn" class="smallAction aiTrigger">${escapeHtml(t("ai.entity.generateBtn"))}</button>
    </div>
    <div id="aiEntitySuggestionsList" class="aiSuggestionsList"></div>
  `;
}

function wireAiSuggestionsTab(report) {
  const btn = $("aiEntitySuggestBtn");
  const list = $("aiEntitySuggestionsList");
  if (!btn || !list) return;
  btn.addEventListener("click", async () => {
    const job = state.currentJobData;
    if (!job || !job.case_id) return;
    const providerLabel = window.prompt(t("ai.narrative.providerPrompt"), "anthropic");
    if (!providerLabel) return;
    const provider = providerLabel.trim().toLowerCase();
    if (!["anthropic", "openai", "local"].includes(provider)) {
      alert(t("ai.narrative.invalidProvider"));
      return;
    }
    if (!window.confirm(t("ai.entity.confirmSend", { provider }))) return;
    btn.disabled = true;
    list.textContent = t("common.loading");
    try {
      const result = await api("/api/ai/entity-suggestions", {
        method: "POST",
        body: JSON.stringify({
          case_id: job.case_id, provider,
          lang: (window.I18N && window.I18N.get()) || "it",
        }),
      });
      renderAiSuggestionsList(result, list, report.entities || [], job.case_id);
    } catch (exc) {
      list.textContent = t("ai.narrative.failed", { error: exc.message || String(exc) });
    } finally {
      btn.disabled = false;
    }
  });
}

function renderAiSuggestionsList(result, listEl, entities, caseId) {
  const verdicts = result.verdicts || [];
  if (!verdicts.length) {
    const note = result.candidates_total === 0 ? t("ai.entity.noCandidates") : t("ai.entity.noSuggestions");
    listEl.innerHTML = `<p class="modeHint">${escapeHtml(note)}</p>`;
    return;
  }
  const byId = {};
  entities.forEach((e) => { byId[e.id] = e; });
  const labelFor = (id) => {
    const e = byId[id];
    return e ? `${escapeHtml(e.display_value || e.value)} (${escapeHtml(e.type)})` : escapeHtml(id.slice(0, 8));
  };

  listEl.innerHTML = verdicts.map((v, idx) => `
    <div class="aiSuggestionCard" data-idx="${idx}">
      <div class="aiSuggestionHead">
        <span>${labelFor(v.entity_id_a)}</span>
        <span aria-hidden="true">&harr;</span>
        <span>${labelFor(v.entity_id_b)}</span>
      </div>
      <div class="confTrack"><div class="confFill ${v.confidence >= 0.7 ? "high" : v.confidence >= 0.4 ? "medium" : "low"}" style="width:${Math.round(v.confidence * 100)}%"></div></div>
      <p>${escapeHtml(v.rationale || "")}</p>
      <div class="actions">
        <button type="button" class="smallAction" data-decision="confirmed">${escapeHtml(t("ai.entity.confirm"))}</button>
        <button type="button" class="smallAction secondary" data-decision="rejected">${escapeHtml(t("ai.entity.reject"))}</button>
      </div>
      <p class="aiDecisionMsg"></p>
    </div>
  `).join("");

  listEl.querySelectorAll(".aiSuggestionCard").forEach((card) => {
    const idx = Number(card.dataset.idx);
    const v = verdicts[idx];
    card.querySelectorAll("[data-decision]").forEach((decideBtn) => {
      decideBtn.addEventListener("click", async () => {
        const msg = card.querySelector(".aiDecisionMsg");
        try {
          await api("/api/ai/entity-suggestions/decide", {
            method: "POST",
            body: JSON.stringify({
              case_id: caseId, entity_id_a: v.entity_id_a, entity_id_b: v.entity_id_b,
              decision: decideBtn.dataset.decision, ai_run_id: result.run_id,
              ai_confidence: v.confidence, ai_rationale: v.rationale,
            }),
          });
          card.classList.add(decideBtn.dataset.decision === "confirmed" ? "aiConfirmed" : "aiRejected");
          if (msg) msg.textContent = decideBtn.dataset.decision === "confirmed"
            ? t("ai.entity.confirmedMsg") : t("ai.entity.rejectedMsg");
        } catch (exc) {
          if (msg) msg.textContent = t("err.generic") + (exc.message || exc);
        }
      });
    });
  });
}

function renderEntityOverview(report, entities, findings) {
  const n = entities.length;
  const byType = {};
  entities.forEach((e) => { byType[e.type] = (byType[e.type] || 0) + 1; });
  const typesSummary = Object.entries(byType)
    .map(([ty, c]) => `${c} ${entityTypeLabel(ty)}`)
    .join(" · ");
  const critHigh = findings.filter((f) => ["critical", "high"].includes(f.severity));

  // Avvertenze incertezza/omonimi (requisito spec): mai unire omonimi in automatico.
  const avgConf = entities.length
    ? entities.reduce((s, e) => s + Number(e.confidence || 0), 0) / entities.length : 0;
  const warns = [];
  if (!findings.length) warns.push(t("en.noEvidence"));
  if (entities.length && avgConf < 0.45) warns.push(t("en.lowConfidence"));
  const nameLike = entities.filter((e) => ["person", "username", "handle"].includes(e.type));
  const distinctNames = new Set(nameLike.map((e) => String(e.value || "").toLowerCase()));
  if (distinctNames.size > 1) warns.push(t("en.homonyms", { n: distinctNames.size }));
  const warnHtml = warns.length
    ? `<div class="entityWarns">${warns.map((w) => `<div class="warnItem">⚠️ ${escapeHtml(w)}</div>`).join("")}</div>` : "";

  // Fonti consultate: provider di ricerca + host delle evidenze.
  const providers = [...new Set((report.search_results || []).map((r) => r.provider).filter(Boolean))];
  const evidenceHosts = [...new Set(
    findings.flatMap((f) => (f.evidence || []).map((ev) => evidenceHostLabel(ev.url))).filter((h) => h && h !== "fonte")
  )];
  const srcChips = [...providers.map((p) => `provider:${p}`), ...evidenceHosts.slice(0, 20)];
  const srcHtml = `
    <div class="entitySources">
      <h4>${t("en.sourcesConsulted")} (${srcChips.length})</h4>
      ${srcChips.length
        ? `<div class="srcChips">${srcChips.map((s) => `<span class="srcChip">${escapeHtml(s)}</span>`).join("")}</div>`
        : `<p style="color:var(--muted);font-size:13px;margin:0">${t("en.noExternalSources")}</p>`}
    </div>`;

  return `
    ${warnHtml}
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
      <div class="statTile"><span class="statN">${n}</span><span class="statLabel">${t("en.entitiesFound")}</span></div>
      <div class="statTile"><span class="statN">${findings.length}</span><span class="statLabel">${t("en.findings")}</span></div>
      <div class="statTile ${critHigh.length ? "error" : ""}"><span class="statN">${critHigh.length}</span><span class="statLabel">Critical/High</span></div>
    </div>
    <p style="color:var(--muted);font-size:13px;margin:0 0 16px">${typesSummary || t("en.noEntitiesExtracted")}</p>
    ${n ? renderEntityTable(entities.slice(0, 8), ["th.type", "th.value", "th.confidence", "th.grade"]) : `<div class="entityTabEmpty">${t("en.noEntitiesInReport")}</div>`}
    ${srcHtml}
  `;
}

function renderEntityTable(items, headers) {
  if (!items.length) return `<div class="entityTabEmpty">${t("en.noDataCategory")}</div>`;
  const rows = items.map((e) => {
    const grade = `${e.source_reliability || "F"}${e.info_credibility || 6}`;
    const conf = Number(e.confidence || 0);
    const confCls = conf >= 0.7 ? "high" : conf >= 0.4 ? "medium" : "low";
    return `<tr>
      <td><span class="typeBadge">${escapeHtml(entityTypeLabel(e.type))}</span></td>
      <td style="font-family:var(--font-mono);font-size:12.5px">${escapeHtml(String(e.display_value || e.value || "—").slice(0, 80))}</td>
      <td><span class="confFill ${confCls}" style="display:inline-block;width:${Math.round(conf*100)}%;max-width:60px;height:6px;border-radius:3px;background:${confCls==="high"?"var(--green)":confCls==="medium"?"var(--amber)":"var(--danger)"}"></span> ${Math.round(conf*100)}%</td>
      <td style="color:var(--muted);font-size:12px">${escapeHtml(grade)}</td>
    </tr>`;
  }).join("");
  return `
    <table class="entityTable">
      <thead><tr>${headers.map((h) => `<th>${escapeHtml(t(h))}</th>`).join("")}</tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function evidenceHostLabel(url) {
  try { return new URL(url).host.replace(/^www\./, ""); } catch { return "fonte"; }
}

function renderEvidencesTab(findings) {
  if (!findings.length) return `<div class="entityTabEmpty">${t("en.noFindingsReport")}</div>`;
  return `
    <table class="entityTable">
      <thead><tr><th>Severity</th><th>${t("th.type")}</th><th>${t("th.value")}</th><th>${t("th.confidence")}</th><th>${t("th.source")}</th></tr></thead>
      <tbody>
        ${findings.slice(0, 50).map((f) => {
          const links = (f.evidence || [])
            .filter((ev) => ev && ev.url)
            .slice(0, 3)
            .map((ev) => `<a href="${escapeHtml(ev.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(ev.title || ev.url)}">${escapeHtml(evidenceHostLabel(ev.url))}</a>`)
            .join(", ");
          return `
          <tr>
            <td><span class="providerBadge ${f.severity === "critical" || f.severity === "high" ? "ko" : f.severity === "medium" ? "warn" : "neutral"}">${escapeHtml(f.severity || "info")}</span></td>
            <td style="font-size:12px">${escapeHtml(f.kind || "—")}</td>
            <td style="font-family:var(--font-mono);font-size:12px">${escapeHtml(String(f.value || "").slice(0, 80))}</td>
            <td>${Math.round(Number(f.confidence || 0) * 100)}%</td>
            <td style="font-size:12px">${links || '<span style="color:var(--muted)">—</span>'}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderTimelineTab(entities) {
  const dated = entities.filter((e) => e.first_seen || e.last_seen).sort(
    (a, b) => new Date(b.first_seen || 0) - new Date(a.first_seen || 0)
  );
  if (!dated.length) return `<div class="entityTabEmpty">${t("en.noTimestamps")}</div>`;
  return `
    <table class="entityTable">
      <thead><tr><th>${t("th.firstSeen")}</th><th>${t("th.lastSeen")}</th><th>${t("th.type")}</th><th>${t("th.value")}</th></tr></thead>
      <tbody>
        ${dated.slice(0, 30).map((e) => `
          <tr>
            <td style="font-size:12px;color:var(--muted)">${escapeHtml(e.first_seen || "—")}</td>
            <td style="font-size:12px;color:var(--muted)">${escapeHtml(e.last_seen || "—")}</td>
            <td><span class="typeBadge">${escapeHtml(entityTypeLabel(e.type))}</span></td>
            <td style="font-family:var(--font-mono);font-size:12px">${escapeHtml(String(e.value || "").slice(0, 60))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderAuditTab(report) {
  const queries = report.queries || [];
  const agents = report.agent_results || [];
  const rows = agents.map((a) =>
    `<tr><td>${escapeHtml(a.name || "—")}</td><td>${escapeHtml(a.status || "—")}</td>` +
    `<td style="font-size:12px;color:var(--muted)">${escapeHtml(String(a.summary || "").slice(0, 120))}</td></tr>`
  ).join("");
  return `
    <p style="color:var(--muted);font-size:13px;margin:0 0 12px">${t("au.intro")}</p>
    <div class="auditMeta">
      <div><strong>${t("au.generated")}</strong>: ${escapeHtml(report.generated_at || "—")}</div>
      <div><strong>Target</strong>: ${escapeHtml(report.target || "—")} (${escapeHtml(report.target_type || "—")})</div>
      <div><strong>${t("au.queriesRun")}</strong>: ${queries.length}</div>
    </div>
    ${agents.length ? `
      <h4 style="margin:16px 0 8px">${t("au.modulesRun")}</h4>
      <table class="entityTable">
        <thead><tr><th>${t("au.agent")}</th><th>${t("au.status")}</th><th>${t("au.summary")}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>` : ""}
    ${queries.length ? `
      <h4 style="margin:16px 0 8px">${t("au.verifiableQueries")}</h4>
      <ul class="auditQueries">${queries.slice(0, 20).map((q) => `<li>${escapeHtml(q)}</li>`).join("")}</ul>` : ""}
  `;
}

function renderSuggestedActions(target, type, report) {
  const list = $("suggestedList");
  if (!list) return;
  const actions = [];
  if (["domain", "company"].includes(type)) {
    actions.push({ labelKey: "sa.subdomains", mode: "domain" });
    actions.push({ labelKey: "sa.whois", mode: "domain" });
  }
  if (["email"].includes(type)) {
    actions.push({ labelKey: "sa.pivotUsername", mode: "handle" });
    actions.push({ labelKey: "sa.checkBreach", mode: "contact" });
  }
  if (["handle", "username"].includes(type)) {
    actions.push({ labelKey: "sa.findEmails", mode: "contact" });
    actions.push({ labelKey: "sa.otherSocial", mode: "handle" });
  }
  if (["ip"].includes(type)) {
    actions.push({ labelKey: "sa.ipReputation", mode: "domain" });
    actions.push({ labelKey: "sa.geolocation", mode: "domain" });
  }
  actions.push({ labelKey: "sa.forensicReport", action: "forensic" });
  list.innerHTML = actions.map((a) => `
    <button class="suggestedAction" type="button" data-mode="${a.mode || ""}" data-action="${a.action || ""}">${escapeHtml(t(a.labelKey))}</button>
  `).join("");
  list.querySelectorAll(".suggestedAction").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.action === "forensic") {
        document.querySelector('.nav[data-panel="jobs"]').click();
        return;
      }
      routeGlobalSearch(target);
    });
  });
}

// ================================================================
// HIGHRISKRESEARCHMODE modal
// ================================================================

let _highRiskResolve = null;
let _highRiskCheckbox = null;

function setupHighRiskModal() {
  if ($("hrCancel")) $("hrCancel").addEventListener("click", () => dismissHighRiskModal(false));
  if ($("hrProceed")) $("hrProceed").addEventListener("click", () => {
    if (!($("hrConfirm") && $("hrConfirm").checked)) {
      $("hrConfirm").style.outline = "2px solid var(--amber)";
      return;
    }
    const just = ($("hrJustification") && $("hrJustification").value.trim()) || "";
    if (!just) {
      $("hrJustification").style.borderColor = "var(--amber)";
      return;
    }
    dismissHighRiskModal(true);
  });
  if ($("hrConfirm")) $("hrConfirm").addEventListener("change", () => {
    $("hrConfirm").style.outline = "";
  });
  if ($("hrJustification")) $("hrJustification").addEventListener("input", () => {
    $("hrJustification").style.borderColor = "";
  });
  // Gate gated checkboxes
  if ($("darkweb")) $("darkweb").addEventListener("change", function() {
    if (this.checked) gateHighRisk("deep/dark web", this);
  });
  if ($("redTeamFlag")) $("redTeamFlag").addEventListener("change", function() {
    if (this.checked) gateHighRisk("red team", this);
  });
}

async function gateHighRisk(modeName, checkbox) {
  const modal = $("highRiskModal");
  if (!modal) return;
  $("hrModeName").textContent = modeName;
  if ($("hrJustification")) $("hrJustification").value = "";
  if ($("hrConfirm")) $("hrConfirm").checked = false;
  modal.classList.remove("hidden");
  return new Promise((resolve) => {
    _highRiskResolve = resolve;
    _highRiskCheckbox = checkbox;
  });
}

function dismissHighRiskModal(confirmed) {
  const modal = $("highRiskModal");
  if (modal) modal.classList.add("hidden");
  if (!confirmed && _highRiskCheckbox) {
    _highRiskCheckbox.checked = false;
  }
  if (_highRiskResolve) _highRiskResolve(confirmed);
  _highRiskResolve = null;
  _highRiskCheckbox = null;
}

// ================================================================
// PRIVACY CENTER
// ================================================================

async function loadPrivacyCenter() {
  await loadPrivacyLog();
}

async function loadPrivacyLog() {
  const el = $("privacyLog");
  if (!el) return;
  el.textContent = "Carico…";
  try {
    const data = await api("/api/privacy/log");
    const requests = data.requests || [];
    if (!requests.length) {
      el.innerHTML = `<div class="empty">${t("pv.noRequests")}</div>`;
      return;
    }
    el.innerHTML = requests.map((r) => `
      <div class="job" style="cursor:default">
        <strong>${escapeHtml(r.type || t("pv.requestFallback"))} · ${escapeHtml(r.status || "—")}</strong>
        <span>${escapeHtml(r.created_at || "—")} · ${escapeHtml(r.reason || "")}</span>
      </div>
    `).join("");
  } catch (exc) {
    el.textContent = t("pv.logUnavailable") + (exc.message || exc);
  }
}

function setupPrivacyCenter() {
  if ($("privacyExportBtn")) {
    $("privacyExportBtn").addEventListener("click", async () => {
      const btn = $("privacyExportBtn");
      const msg = $("privacyExportResult");
      btn.disabled = true;
      if (msg) { msg.textContent = t("pv.requesting"); msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/export", { method: "POST" });
        if (msg) {
          msg.style.color = "var(--green)";
          msg.textContent = data.message || t("pv.exportStarted");
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = t("err.generic") + exc.message; }
      } finally {
        btn.disabled = false;
        await loadPrivacyLog();
      }
    });
  }

  if ($("privacyEraseBtn")) {
    $("privacyEraseBtn").addEventListener("click", async () => {
      const reason = ($("privacyEraseReason") && $("privacyEraseReason").value.trim()) || "";
      if (!confirm(t("pv.eraseConfirm"))) return;
      const btn = $("privacyEraseBtn");
      const msg = $("privacyEraseResult");
      btn.disabled = true;
      if (msg) { msg.textContent = t("pv.requesting"); msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/erase", { method: "POST", body: JSON.stringify({ reason }) });
        if (msg) {
          msg.style.color = "var(--amber)";
          msg.textContent = data.message || t("pv.eraseRegistered");
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = t("err.generic") + exc.message; }
      } finally {
        btn.disabled = false;
        await loadPrivacyLog();
      }
    });
  }

  if ($("privacyDsarBtn")) {
    $("privacyDsarBtn").addEventListener("click", async () => {
      const btn = $("privacyDsarBtn");
      const msg = $("privacyDsarResult");
      btn.disabled = true;
      if (msg) { msg.textContent = t("pv.sending"); msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/dsar", { method: "POST" });
        if (msg) {
          msg.style.color = "var(--green)";
          msg.textContent = data.message || t("pv.dsarRegistered");
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = t("err.generic") + exc.message; }
      } finally {
        btn.disabled = false;
        await loadPrivacyLog();
      }
    });
  }
}

// Intercept selectJob to offer entity profile.
// NB: the impl is `selectJobBase`; this is the single `selectJob` declaration,
// so all callers get the entity-profile button without infinite recursion.
const _origSelectJob = selectJobBase;
async function selectJob(id) {
  await _origSelectJob(id);
  // After job loaded, add "Apri profilo entità" button if not present
  const reportSurface = document.querySelector(".reportSurface .surfaceHead");
  if (reportSurface && !reportSurface.querySelector("#openEntityBtn")) {
    const btn = document.createElement("button");
    btn.id = "openEntityBtn";
    btn.type = "button";
    btn.className = "smallAction secondary";
    btn.textContent = t("en.openProfile");
    btn.style.marginLeft = "auto";
    btn.addEventListener("click", () => {
      if (state.lastReport) showEntityProfile(state.lastReport);
    });
    reportSurface.appendChild(btn);
  }
  if ($("openEntityBtn")) {
    $("openEntityBtn").style.display = state.lastReport ? "" : "none";
  }
}

// Nav: add privacy panel handling
document.querySelectorAll('.nav[data-panel="privacy"]').forEach((btn) => {
  btn.addEventListener("click", () => loadPrivacyCenter());
});
document.querySelectorAll('.nav[data-panel="entity"]').forEach((btn) => {
  btn.addEventListener("click", () => {
    // entity panel is rendered by showEntityProfile, nothing to load
  });
});

// Setup modals and privacy center on load
setupHighRiskModal();
setupPrivacyCenter();
