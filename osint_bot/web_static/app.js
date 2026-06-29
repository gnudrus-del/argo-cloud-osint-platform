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
  handle: {
    type: "handle",
    modules: ["socmint", "phone_email"],
    provider: "all",
    placeholder: "esempio: username oppure @username",
    hint: "Username pubblico: Sherlock e Maigret cercano profili aperti; contatti solo se visibili pubblicamente nelle fonti.",
    authorized: true,
  },
  domain: {
    type: "domain",
    modules: ["company_domain", "opsec", "geo"],
    provider: "all",
    placeholder: "esempio: example.com oppure nome azienda",
    hint: "Dominio o azienda: il planner usa seed, archivi, sottodomini e fonti pubbliche.",
    authorized: false,
  },
  contact: {
    type: "email",
    modules: ["phone_email", "socmint"],
    provider: "all",
    placeholder: "esempio: nome@example.com oppure numero autorizzato",
    hint: "Email o telefono: verifica presenza pubblica e contatti citati; non recupera dati privati di registrazione.",
    authorized: true,
  },
  media: {
    type: "media",
    modules: ["media", "geo"],
    provider: "none",
    placeholder: "carica il file nella sezione Media oppure inserisci un URL pubblico",
    hint: "Media: analisi di file e riferimenti pubblici, con attenzione a metadati e contesto.",
    authorized: false,
  },
  crypto: {
    type: "crypto",
    modules: ["crypto", "opsec"],
    provider: "all",
    placeholder: "esempio: address BTC/ETH o wallet pubblico",
    hint: "Crypto: contestualizza address e fonti pubbliche senza attribuzioni automatiche.",
    authorized: false,
  },
};

const $ = (id) => document.getElementById(id);

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

const TOPBAR_COPY = {
  dashboard: ["Dashboard", "Cerca una entità o riprendi un caso. Le aree gated (deep/dark web, red team) restano opt-in."],
  cases: ["Casi e indagini", "Ogni ricerca vive dentro un caso con base giuridica e finalità documentate."],
  investigate: ["Nuova ricerca", "Compila i dati. Le aree sono tutte attive: spunta solo deep/dark web o red team se servono."],
  jobs: ["Report investigativi", "Apri un report completato per leggere evidenze, grafo entità e fonti."],
  media: ["Media", "Analisi automatica di immagini e video: EXIF, geo, hash, MIME."],
  keys: ["Chiavi API (BYOK)", "Le chiavi restano cifrate e non sono mai mostrate in chiaro."],
  opsec: ["OPSEC", "Routing e isolamento gestiti dal planner in base al caso e ai flag."],
};

function updateTopbar(panel) {
  const copy = TOPBAR_COPY[panel];
  if (!copy) return;
  const head = document.querySelector(".topbar h1");
  const sub = document.querySelector(".topbar p");
  if (head) head.textContent = copy[0];
  if (sub) sub.textContent = copy[1];
}

$("loginTab").addEventListener("click", () => setAuthMode("login"));
$("signupTab").addEventListener("click", () => setAuthMode("signup"));
$("authSubmit").addEventListener("click", submitAuth);
$("logoutBtn").addEventListener("click", logout);
$("themeSelect").addEventListener("change", () => setTheme($("themeSelect").value));
$("planBtn").addEventListener("click", plan);
$("runBtn").addEventListener("click", runJob);
$("refreshJobs").addEventListener("click", loadJobs);
if ($("mediaFile")) $("mediaFile").addEventListener("change", uploadMedia);
if ($("mediaFileInline")) $("mediaFileInline").addEventListener("change", uploadMediaInline);
if ($("caseCreateBtn")) $("caseCreateBtn").addEventListener("click", createCase);
document.querySelectorAll(".quickMode").forEach((button) => {
  button.addEventListener("click", () => applyMode(button.dataset.mode));
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
  setTheme(localStorage.getItem("argo-theme") || localStorage.getItem("gufo-theme") || "notte");
  applyMode(document.querySelector(".quickMode.active")?.dataset.mode || "handle");
  const status = await api("/api/auth/status", {}, true, false);
  if (!status.authenticated) {
    $("authScreen").classList.remove("hidden");
    $("appShell").classList.add("hidden");
    $("signupTab").disabled = !status.signup_enabled;
    if (!status.signup_enabled) setAuthMode("login");
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

function setTheme(theme) {
  document.body.dataset.theme = theme;
  localStorage.setItem("argo-theme", theme);
  if ($("themeSelect")) $("themeSelect").value = theme;
}

function setAuthMode(mode) {
  state.authMode = mode;
  $("loginTab").classList.toggle("active", mode === "login");
  $("signupTab").classList.toggle("active", mode === "signup");
  $("authSubmit").textContent = mode === "login" ? "Accedi" : "Crea account gratis";
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
        || `Email di verifica inviata a ${data.email}. Clicca il link per attivare l'account.`;
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
  const mods = [...DEFAULT_MODULES];
  if ($("darkweb") && $("darkweb").checked) mods.push("darkweb");
  if ($("redTeamFlag") && $("redTeamFlag").checked) mods.push("red_team");
  return mods;
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
    target ? `Analizza ${target}` : "Esegui una ricerca OSINT",
    seeds ? `fonti seed: ${seeds}` : "",
    known ? `informazioni note: ${known}` : "",
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
    $("planStatus").textContent = "errore";
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

function renderPlan(profile) {
  $("planOutput").innerHTML = "";
  const block = document.createElement("div");
  block.className = "planBlock";
  block.innerHTML = `
    <p><strong>Target</strong>: ${escapeHtml(profile.target || "-")}</p>
    <p><strong>Tipo</strong>: ${escapeHtml(profile.target_type || "-")}</p>
    <p><strong>Agenti</strong>: ${escapeHtml((profile.agents || []).join(", ") || "-")}</p>
    <p><strong>Strumenti</strong>: ${escapeHtml((profile.external_tools || []).join(", ") || "-")}</p>
    <p><strong>Seed URL</strong>: ${escapeHtml((profile.seed_urls || []).join(", ") || "-")}</p>
    <p><strong>Profondita</strong>: ${profile.depth} · <strong>Pagine</strong>: ${profile.max_pages}</p>
    <hr>
    ${(profile.notes || []).map((note) => `<p>${escapeHtml(note)}</p>`).join("")}
  `;
  $("planOutput").appendChild(block);
}

async function loadCapabilities() {
  try {
    const data = await api("/api/capabilities");
    const providers = (data.search_providers || []).map((provider) => {
      const cls = provider.configured ? "ok" : "ko";
      return `
        <div class="capability">
          <strong>Ricerca ${escapeHtml(provider.name)}<span class="statusDot ${cls}" title="${cls === "ok" ? "configurata" : "manca env"}"></span></strong>
          <span>${provider.configured ? "configurata" : escapeHtml(provider.env_var)}</span>
        </div>
      `;
    }).join("");
    const tools = data.tools.map((tool) => {
      const cls = tool.available ? "ok" : "ko";
      const tip = tool.available ? "disponibile" : (tool.health_reason || "non disponibile");
      return `
        <div class="capability">
          <strong>${escapeHtml(tool.name)}<span class="statusDot ${cls}" title="${escapeHtml(tip)}"></span></strong>
          <span>${tool.available ? "disponibile" : escapeHtml(tool.env_var)}</span>
        </div>
      `;
    }).join("");
    $("capabilities").innerHTML = providers + tools;
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
        <strong>${escapeHtml(job.profile.target)} · ${escapeHtml(job.profile.target_type)}</strong>
        <span>${escapeHtml(job.status)} · ${escapeHtml(jobStageLabel(job))} · ${escapeHtml(job.updated_at || job.created_at)}</span>
      </div>
    `).join("") || `<div class="empty">Nessun report.</div>`;
    document.querySelectorAll(".job").forEach((item) => item.addEventListener("click", () => selectJob(item.dataset.id)));
  } catch (error) {
    $("jobsList").textContent = error.message;
  }
}

async function selectJobBase(id) {
  const job = await api(`/api/jobs/${id}`);
  state.currentJob = id;
  $("jsonLink").href = `/api/jobs/${id}/report.json`;
  $("mdLink").href = `/api/jobs/${id}/report.md`;
  $("pdfLink").href = `/api/jobs/${id}/report.pdf`;
  $("forensicMdLink").href = `/api/jobs/${id}/forensic.md`;
  $("forensicJsonLink").href = `/api/jobs/${id}/forensic.json`;
  if ($("redteamMdLink"))   $("redteamMdLink").href   = `/api/jobs/${id}/redteam.md`;
  if ($("redteamJsonLink")) $("redteamJsonLink").href = `/api/jobs/${id}/redteam.json`;
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
    body.innerHTML = which === "redteam"
      ? '<p class="muted">Nessun report Red Team per questo job. ' +
        'Viene generato solo quando il modulo <code>red_team</code> è attivo ' +
        'e il caso ha uno scope autorizzato non vuoto.</p>'
      : '<p class="muted">Nessun report forensico per questo job. ' +
        'I report forensici a 19 sezioni vengono generati per i job avviati dopo l\'ultimo deploy.</p>';
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
        Caso <code>${escapeHtml(report.case_id)}</code> · target
        <code>${escapeHtml(report.target)}</code> (${escapeHtml(report.target_type)})
        · generato ${escapeHtml(report.generated_at)}
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
  return progressLabel(job.status) || "in attesa";
}

function progressLabel(stage) {
  const labels = {
    queued: "in coda",
    running: "pipeline",
    collecting: "raccolta",
    pdf: "PDF",
    pdf_error: "PDF non disponibile",
    complete: "completo",
    error: "errore",
  };
  return labels[stage] || stage || "stato";
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
  const positioned = positionNodes(nodes, 900, 360);
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
        <strong>Grafo entità</strong>
        <span>${nodes.length} nodi · ${links.length} relazioni visibili</span>
      </div>
      <span class="tag">pivot</span>
    </div>
    <svg viewBox="0 0 900 360" role="img" aria-label="Grafo entità del report">
      <rect class="graphCanvas" x="0" y="0" width="900" height="360" rx="8"></rect>
      ${linkMarkup}
      ${nodeMarkup}
    </svg>
    <div id="graphDetails" class="graphDetails">Seleziona un nodo per preparare un pivot investigativo.</div>
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

function positionNodes(nodes, width, height) {
  if (!nodes.length) return [];
  const centerX = width / 2;
  const centerY = height / 2;
  const radiusX = width * 0.38;
  const radiusY = height * 0.31;
  return nodes.map((node, index) => {
    if (index === 0) {
      return { ...node, x: centerX, y: centerY, radius: 24 };
    }
    const angle = ((index - 1) / Math.max(1, nodes.length - 1)) * Math.PI * 2 - Math.PI / 2;
    const ringOffset = index % 2 === 0 ? 1 : 0.78;
    return {
      ...node,
      x: Math.round(centerX + Math.cos(angle) * radiusX * ringOffset),
      y: Math.round(centerY + Math.sin(angle) * radiusY * ringOffset),
      radius: 16,
    };
  });
}

function renderGraphDetails(entity) {
  const details = $("graphDetails");
  details.innerHTML = `
    <div>
      <strong>${escapeHtml(entity.display_value || entity.value)}</strong>
      <span>${escapeHtml(entityTypeLabel(entity.type))} · grado ${escapeHtml((entity.source_reliability || "F") + (entity.info_credibility || 6))} · confidenza ${Number(entity.confidence || 0).toFixed(2)}</span>
    </div>
    <button type="button" class="smallAction">Prepara pivot</button>
  `;
  details.querySelector("button").addEventListener("click", () => pivotFromEntity(entity));
}

function pivotFromEntity(entity) {
  document.querySelector('[data-panel="investigate"]').click();
  $("target").value = entity.value;
  $("targetType").value = targetTypeFromEntity(entity.type);
  setModules(modulesFromEntity(entity.type));
  $("modeHint").textContent = `Pivot preparato da entità ${entityTypeLabel(entity.type)} del report selezionato.`;
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
    domain: "dominio",
    organization: "azienda",
    email: "email",
    username: "username",
    phone: "telefono",
    ip: "IP",
    wallet: "wallet",
    url: "URL",
    media: "media",
    location: "luogo",
  };
  return labels[type] || type;
}

function shortLabel(value, maxLength) {
  const clean = String(value || "");
  if (clean.length <= maxLength) return clean;
  return `${clean.slice(0, maxLength - 3)}...`;
}

async function uploadMedia() {
  const file = $("mediaFile").files[0];
  if (!file) {
    $("mediaOutput").textContent = "Seleziona un file.";
    return;
  }
  $("mediaOutput").textContent = "Analisi in corso…";
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
    out.textContent = "Nessun file caricato.";
    return;
  }
  out.classList.remove("muted");
  out.textContent = `Analisi in corso di ${file.name}…`;
  const form = new FormData();
  form.append("file", file);
  try {
    const data = await api("/api/media", { method: "POST", body: form }, false);
    out.dataset.filename = file.name;
    const m = data.metadata || {};
    out.innerHTML = `
      <div class="mediaSummary">
        <strong>${escapeHtml(file.name)}</strong>
        <span class="tag">${escapeHtml(m.mime || "n/d")}</span>
      </div>
      <pre>${escapeHtml(JSON.stringify(m, null, 2))}</pre>
    `;
  } catch (error) {
    out.textContent = `Errore: ${error.message}`;
  }
}

async function api(path, options = {}, jsonContent = true, auth = true) {
  const headers = options.headers || {};
  if (jsonContent && options.body) headers["Content-Type"] = "application/json";
  if (auth && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(data.error || response.statusText);
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
  if (plan === "free") return "Gratuito";
  if (plan === "pro") return "Pro";
  return plan || "Gratuito";
}

function applyMode(mode) {
  const preset = modePresets[mode] || modePresets.handle;
  state.currentMode = mode;
  document.querySelectorAll(".quickMode").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === mode);
  });
  $("targetType").value = preset.type;
  $("provider").value = preset.provider;
  if ($("modeHint")) $("modeHint").textContent = preset.hint;
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
    const ph = mode === "domain" ? "example.com / 192.0.2.1 / Acme Spa"
                                  : "address BTC/ETH o wallet pubblico";
    if ($("genericTarget")) $("genericTarget").placeholder = ph;
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
    count.textContent = `${(data.keys || []).length} configurate`;
    // Lo stato copertura usa la response di /api/capabilities che ora
    // contiene lo stato semantico (state, message, last4, ...) per provider.
    try {
      const caps = await api("/api/capabilities", { method: "GET" });
      renderApiKeyStatus(caps.search_providers || []);
      // Aggiorno anche il pannello capabilities (in tab Investigate).
      renderCapabilitiesPanel(caps);
    } catch (capsErr) {
      status.textContent = "Stato copertura non disponibile: " + (capsErr.message || capsErr);
    }
  } catch (exc) {
    catalog.textContent = "Errore nel caricamento: " + (exc.message || exc);
    if (status) status.textContent = "";
  }
}

function renderApiKeys(catalog, keys) {
  const byService = Object.fromEntries(keys.map((k) => [k.service, k]));
  const container = $("keysCatalog");
  container.innerHTML = "";
  const byCategory = {};
  for (const entry of catalog) {
    const cat = entry.category || "Altri";
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
  input.placeholder = current ? current.masked : `Incolla qui la chiave per ${entry.label}`;
  input.dataset.service = entry.service;
  wrap.appendChild(input);

  const actions = document.createElement("div");
  actions.className = "keyActions";

  const save = document.createElement("button");
  save.type = "button";
  save.className = "smallAction";
  save.textContent = "Salva";
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
  test.title = "Esegue una probe reale verso il provider per validare la chiave.";
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
    remove.textContent = "Rimuovi";
    remove.addEventListener("click", async () => {
      if (!confirm(`Rimuovere la chiave salvata per ${entry.label}?`)) return;
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
    ? `Chiave salvata · ${current.masked} · aggiornata ${current.updated_at || "?"}`
    : "Nessuna chiave salvata.";
  wrap.appendChild(result);

  return wrap;
}

// --------- Stato copertura provider (pannello "Stato copertura" + Investigate)

const PROVIDER_STATE_LABELS = {
  not_configured:  { label: "Non configurato", cls: "neutral" },
  untested:        { label: "Salvato, non testato", cls: "warn" },
  ok:              { label: "Attivo", cls: "ok" },
  auth_error:      { label: "Errore autenticazione", cls: "ko" },
  quota_exceeded:  { label: "Quota esaurita", cls: "warn" },
  network_error:   { label: "Errore rete", cls: "ko" },
  unsupported:     { label: "Provider non supportato", cls: "neutral" },
};

function providerBadge(state) {
  const cfg = PROVIDER_STATE_LABELS[state] || { label: state || "—", cls: "neutral" };
  const span = document.createElement("span");
  span.className = `providerBadge ${cfg.cls}`;
  span.textContent = cfg.label;
  return span;
}

function renderApiKeyStatus(providers) {
  const status = $("keysStatus");
  if (!status) return;
  status.innerHTML = "";
  // Salto "all" — è meta, non un provider reale.
  const real = providers.filter((p) => p.service && p.service !== "all");
  if (!real.length) {
    status.textContent = "Nessun provider nel catalogo.";
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
    list.textContent = "Errore: " + (exc.message || exc);
  }
}

function renderCasesList(cases) {
  const list = $("casesList");
  const count = $("casesCount");
  count.textContent = `${cases.length}`;
  list.innerHTML = "";
  if (!cases.length) {
    list.textContent = "Nessun caso ancora. Crea il primo a destra: titolo + base giuridica obbligatoria.";
    return;
  }
  for (const c of cases) {
    const card = document.createElement("div");
    card.className = "job";
    card.dataset.status = c.status || "open";
    const title = document.createElement("strong");
    title.textContent = c.title;
    card.appendChild(title);

    const meta = document.createElement("div");
    meta.style.color = "var(--muted)";
    meta.style.fontSize = "12px";
    const lb = (c.legal_basis && c.legal_basis.type) ? c.legal_basis.type : "—";
    const ref = (c.legal_basis && c.legal_basis.reference) ? ` · ${c.legal_basis.reference}` : "";
    const collab = (c.collaborators || []).length ? ` · collab: ${(c.collaborators || []).join(", ")}` : "";
    meta.textContent = `${c.status} · base: ${lb}${ref}${collab}`;
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
      ? `Scope (${c.allowed_targets.length}) · modifica`
      : "Scope vuoto · aggiungi";
    scopeBtn.style.marginTop = "10px";
    scopeBtn.style.marginRight = "8px";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "smallAction";
    useBtn.textContent = "Usa per la prossima ricerca";
    useBtn.style.marginTop = "10px";
    useBtn.addEventListener("click", () => selectCaseAndGoToSearch(c.id));

    card.appendChild(scopeBtn);
    card.appendChild(useBtn);

    const scopeBox = document.createElement("div");
    scopeBox.className = "caseScopeBox hidden";
    const taId = `caseScope-${c.id}`;
    const msgId = `caseScopeMsg-${c.id}`;
    const current = (c.allowed_targets || []).join("\n");
    scopeBox.innerHTML = `
      <label class="wideLabel">Scope autorizzato (una voce per riga)
        <textarea id="${taId}" rows="5">${escapeHtml(current)}</textarea>
      </label>
      <p class="modeHint">
        Formati: <code>dominio</code> · <code>*.dominio</code> · <code>IP</code> ·
        <code>CIDR</code> · <code>URL</code> · <code>@handle</code>.
      </p>
      <div class="actions">
        <button type="button" class="smallAction" data-action="save-scope">Salva scope</button>
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

function populateCaseSelector(cases) {
  const sel = $("currentCase");
  if (!sel) return;
  const previous = sel.value;
  sel.innerHTML = "";
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "— Caso default (auto) —";
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
  if (!title) { msg.textContent = "Titolo obbligatorio."; return; }
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
    msg.textContent = "Caso creato.";
    msg.style.color = "var(--green)";
    await loadCases();
  } catch (exc) {
    msg.textContent = "Errore: " + (exc.message || exc);
    msg.style.color = "var(--danger)";
  }
}

// ---- Scope editor inline per caso esistente ----

async function updateCaseScope(caseId, allowedTextareaId, msgId) {
  const ta = document.getElementById(allowedTextareaId);
  const msgEl = document.getElementById(msgId);
  if (!ta) return;
  const allowed_targets = ta.value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (msgEl) { msgEl.textContent = "Salvataggio…"; msgEl.style.color = ""; }
  try {
    const updated = await api(`/api/cases/${encodeURIComponent(caseId)}/scope`,
      { method: "POST", body: JSON.stringify({ allowed_targets }) });
    if (msgEl) {
      msgEl.textContent = `Scope aggiornato: ${(updated.allowed_targets || []).length} voci.`;
      msgEl.style.color = "#21d07a";
    }
    await loadCases();
  } catch (exc) {
    if (msgEl) {
      msgEl.textContent = "Errore: " + (exc.message || exc);
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
    $("keysCount").textContent = `${(data.keys || []).length} configurate`;
    // Aggiorno subito lo stato copertura (passa per /api/capabilities che
    // restituisce gli stati semantici dei provider).
    if (trimmed && opts.andTest !== false) {
      // Salva → poi test reale (in serie, così l'utente vede il risultato).
      await testApiKey(service);
    } else {
      await refreshProviderStatus();
    }
  } catch (exc) {
    setKeyResult(service, `Errore salvataggio: ${exc.message || exc}`, "ko");
  }
}

async function testApiKey(service, value) {
  const body = { service };
  const v = (value || "").trim();
  if (v) body.value = v;  // se passato, testa quella stringa senza salvarla
  setKeyResult(service, "Probe in corso…", "neutral");
  try {
    const status = await api("/api/keys/test", { method: "POST", body: JSON.stringify(body) });
    const label = (PROVIDER_STATE_LABELS[status.state] || { label: status.state }).label;
    const cls = (PROVIDER_STATE_LABELS[status.state] || { cls: "neutral" }).cls;
    const lat = status.latency_ms != null ? ` · ${status.latency_ms}ms` : "";
    const http = status.http_status != null ? ` · HTTP ${status.http_status}` : "";
    const last4 = status.last4 ? ` · ${"•".repeat(6)}${status.last4}` : "";
    setKeyResult(service, `${label}: ${status.message}${http}${lat}${last4}`, cls);
    await refreshProviderStatus();
  } catch (exc) {
    setKeyResult(service, `Test fallito: ${exc.message || exc}`, "ko");
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
    renderDashError((err && err.message) ? err.message : "Errore nel caricamento della dashboard.");
    return;
  }
  populateDashCaseSelector(data.cases_select || []);
  const totals = data.totals || {};
  renderDashStats(data.stats || {}, totals.jobs || 0);
  renderDashCoverage(data.coverage || {});
  renderDashWarnings(data.warnings || []);
  renderDashRecentCases(data.recent_cases || [], totals.cases || 0);
  renderDashRecentJobs(data.recent_jobs || [], totals.jobs || 0);
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
  sel.innerHTML = '<option value="">— Caso (auto) —</option>';
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
    { key: "complete", label: "Completi", cls: "complete" },
    { key: "running",  label: "In corso", cls: "running" },
    { key: "error",    label: "Errore",   cls: "error" },
  ].map((s) => `
    <div class="statTile ${s.cls}">
      <span class="statN">${Number(stats[s.key] || 0)}</span>
      <span class="statLabel">${s.label}</span>
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
    <div class="coverageRow"><span>Provider di ricerca configurati</span><strong>${pOk} / ${pTot}</strong></div>
    <div class="coverageRow"><span>Tool OSINT disponibili</span><strong>${tOk} / ${tTot}</strong></div>
    <p class="modeHint">Le fonti senza chiave restano disattivate con eleganza (BYOK). Configurale in <em>Chiavi API</em>.</p>`;
}

function renderDashWarnings(warnings) {
  const el = $("dashWarnings");
  if (!el) return;
  warnings = warnings || [];
  if (!warnings.length) {
    el.innerHTML = `<div class="warnItem ok">Nessun avviso di compliance attivo.</div>`;
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
  if (!cases.length) { el.innerHTML = '<div class="empty">Nessun caso. Vai in Casi per crearne uno.</div>'; return; }
  el.innerHTML = cases.map((c) => `
    <div class="job" data-status="${escapeHtml(c.status || "open")}" style="cursor:pointer" onclick="selectCaseAndGoToSearch('${escapeHtml(c.id)}')">
      <strong>${escapeHtml(c.title)}</strong>
      <span>${escapeHtml(c.status || "aperto")} · ${escapeHtml(c.legal_basis || "—")}</span>
    </div>
  `).join("");
}

function renderDashRecentJobs(jobs, totalJobs) {
  const el = $("dashJobs");
  const tag = $("dashJobsTag");
  if (!el) return;
  if (tag) tag.textContent = totalJobs;
  if (!jobs.length) { el.innerHTML = '<div class="empty">Nessun report. Vai in Ricerca per avviarne uno.</div>'; return; }
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
  [/^https?:\/\//i,                           "url"],
  [/@[a-z0-9._-]+/i,                          "username/handle"],
  [/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i, "email"],
  [/^\+?[\d\s\-().]{7,}$/,                    "telefono"],
  [/^(bc1|[13])[a-z0-9]{25,}/i,              "BTC"],
  [/^0x[a-f0-9]{40}/i,                        "ETH"],
  [/[a-f0-9]{32,64}/i,                        "file hash"],
  [/^(\d{1,3}\.){3}\d{1,3}/,                 "IP"],
  [/[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+/i, "dominio"],
];

function updateDetectedType(value) {
  const el = $("detectedType");
  if (!el) return;
  const v = (value || "").trim();
  if (!v) { el.textContent = "tipo: —"; return; }
  for (const [re, label] of TYPE_PATTERNS) {
    if (re.test(v)) { el.textContent = `tipo: ${label}`; return; }
  }
  el.textContent = "tipo: nome / azienda";
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
        <span>Confidenza</span>
        <div class="confTrack"><div class="confFill ${cls}" style="width:${Math.round(avgConf * 100)}%"></div></div>
        <strong>${Math.round(avgConf * 100)}%</strong>
      </div>
      <span style="color:var(--muted);font-size:12px">${entities.length} entità · ${(report.findings || []).length} finding</span>
    `;
  }

  // Tabs
  const tabs = document.querySelectorAll(".entityTab");
  tabs.forEach((t) => {
    t.addEventListener("click", () => {
      tabs.forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      renderEntityTab(t.dataset.etab, report);
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

  // Navigate to entity panel
  document.querySelector('.nav[data-panel="entity"]').click();
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
        ["Tipo", "Valore", "Confidenza", "Fonti"]
      );
      break;
    case "social":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["username", "handle", "social"].includes(e.type)),
        ["Tipo", "Valore", "Confidenza", "Network"]
      );
      break;
    case "domains":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["domain", "organization", "company"].includes(e.type)),
        ["Tipo", "Valore", "Confidenza", "Fonte"]
      );
      break;
    case "contacts":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["email", "phone"].includes(e.type)),
        ["Tipo", "Contatto", "Confidenza", "Visibilità"]
      );
      break;
    case "media":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["media", "location", "image"].includes(e.type)),
        ["Tipo", "Valore", "Geo", "Fonte"]
      );
      break;
    case "crypto":
      body.innerHTML = renderEntityTable(
        entities.filter((e) => ["wallet", "btc", "eth", "crypto"].includes(e.type)),
        ["Rete", "Address", "Confidenza", "Fonte"]
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
    default:
      body.innerHTML = `<div class="entityTabEmpty">Tab non disponibile.</div>`;
  }
}

function renderEntityOverview(report, entities, findings) {
  const n = entities.length;
  const byType = {};
  entities.forEach((e) => { byType[e.type] = (byType[e.type] || 0) + 1; });
  const typesSummary = Object.entries(byType)
    .map(([t, c]) => `${c} ${entityTypeLabel(t)}`)
    .join(" · ");
  const critHigh = findings.filter((f) => ["critical", "high"].includes(f.severity));

  // Avvertenze incertezza/omonimi (requisito spec): mai unire omonimi in automatico.
  const avgConf = entities.length
    ? entities.reduce((s, e) => s + Number(e.confidence || 0), 0) / entities.length : 0;
  const warns = [];
  if (!findings.length) warns.push("Nessuna evidenza raccolta: profilo basato solo sull'input.");
  if (entities.length && avgConf < 0.45) warns.push("Confidenza media bassa: verifica le fonti prima di trarre conclusioni.");
  const nameLike = entities.filter((e) => ["person", "username", "handle"].includes(e.type));
  const distinctNames = new Set(nameLike.map((e) => String(e.value || "").toLowerCase()));
  if (distinctNames.size > 1) warns.push(`Possibili omonimi: ${distinctNames.size} identità simili NON unite automaticamente.`);
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
      <h4>Fonti consultate (${srcChips.length})</h4>
      ${srcChips.length
        ? `<div class="srcChips">${srcChips.map((s) => `<span class="srcChip">${escapeHtml(s)}</span>`).join("")}</div>`
        : '<p style="color:var(--muted);font-size:13px;margin:0">Nessuna fonte esterna: solo dati inseriti.</p>'}
    </div>`;

  return `
    ${warnHtml}
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
      <div class="statTile"><span class="statN">${n}</span><span class="statLabel">Entità trovate</span></div>
      <div class="statTile"><span class="statN">${findings.length}</span><span class="statLabel">Finding</span></div>
      <div class="statTile ${critHigh.length ? "error" : ""}"><span class="statN">${critHigh.length}</span><span class="statLabel">Critical/High</span></div>
    </div>
    <p style="color:var(--muted);font-size:13px;margin:0 0 16px">${typesSummary || "Nessuna entità estratta."}</p>
    ${n ? renderEntityTable(entities.slice(0, 8), ["Tipo", "Valore", "Confidenza", "Grado"]) : '<div class="entityTabEmpty">Nessuna entità estratta in questo report.</div>'}
    ${srcHtml}
  `;
}

function renderEntityTable(items, headers) {
  if (!items.length) return '<div class="entityTabEmpty">Nessun dato per questa categoria.</div>';
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
      <thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function evidenceHostLabel(url) {
  try { return new URL(url).host.replace(/^www\./, ""); } catch { return "fonte"; }
}

function renderEvidencesTab(findings) {
  if (!findings.length) return '<div class="entityTabEmpty">Nessun finding in questo report.</div>';
  return `
    <table class="entityTable">
      <thead><tr><th>Severity</th><th>Tipo</th><th>Valore</th><th>Confidenza</th><th>Fonte</th></tr></thead>
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
  if (!dated.length) return '<div class="entityTabEmpty">Nessuna entità con timestamp disponibile.</div>';
  return `
    <table class="entityTable">
      <thead><tr><th>Prima vista</th><th>Ultima vista</th><th>Tipo</th><th>Valore</th></tr></thead>
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
    <p style="color:var(--muted);font-size:13px;margin:0 0 12px">
      Tracciabilità del report. La catena di audit firmata (hash-chain SHA-256) è
      mantenuta lato server ed esportabile dal Privacy Center.
    </p>
    <div class="auditMeta">
      <div><strong>Generato</strong>: ${escapeHtml(report.generated_at || "—")}</div>
      <div><strong>Target</strong>: ${escapeHtml(report.target || "—")} (${escapeHtml(report.target_type || "—")})</div>
      <div><strong>Query eseguite</strong>: ${queries.length}</div>
    </div>
    ${agents.length ? `
      <h4 style="margin:16px 0 8px">Moduli eseguiti</h4>
      <table class="entityTable">
        <thead><tr><th>Agente</th><th>Stato</th><th>Sintesi</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>` : ""}
    ${queries.length ? `
      <h4 style="margin:16px 0 8px">Query verificabili</h4>
      <ul class="auditQueries">${queries.slice(0, 20).map((q) => `<li>${escapeHtml(q)}</li>`).join("")}</ul>` : ""}
  `;
}

function renderSuggestedActions(target, type, report) {
  const list = $("suggestedList");
  if (!list) return;
  const actions = [];
  if (["domain", "company"].includes(type)) {
    actions.push({ label: "Cerca sottodomini", mode: "domain" });
    actions.push({ label: "Analisi WHOIS", mode: "domain" });
  }
  if (["email"].includes(type)) {
    actions.push({ label: "Pivot su username", mode: "handle" });
    actions.push({ label: "Verifica breach", mode: "contact" });
  }
  if (["handle", "username"].includes(type)) {
    actions.push({ label: "Cerca email associate", mode: "contact" });
    actions.push({ label: "Ricerca su altri social", mode: "handle" });
  }
  if (["ip"].includes(type)) {
    actions.push({ label: "Reputazione IP", mode: "domain" });
    actions.push({ label: "Geolocalizzazione", mode: "domain" });
  }
  actions.push({ label: "Genera report forensico", action: "forensic" });
  list.innerHTML = actions.map((a) => `
    <button class="suggestedAction" type="button" data-mode="${a.mode || ""}" data-action="${a.action || ""}">${escapeHtml(a.label)}</button>
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
      el.innerHTML = '<div class="empty">Nessuna richiesta privacy registrata.</div>';
      return;
    }
    el.innerHTML = requests.map((r) => `
      <div class="job" style="cursor:default">
        <strong>${escapeHtml(r.type || "richiesta")} · ${escapeHtml(r.status || "—")}</strong>
        <span>${escapeHtml(r.created_at || "—")} · ${escapeHtml(r.reason || "")}</span>
      </div>
    `).join("");
  } catch (exc) {
    el.textContent = "Log non disponibile: " + (exc.message || exc);
  }
}

function setupPrivacyCenter() {
  if ($("privacyExportBtn")) {
    $("privacyExportBtn").addEventListener("click", async () => {
      const btn = $("privacyExportBtn");
      const msg = $("privacyExportResult");
      btn.disabled = true;
      if (msg) { msg.textContent = "Richiesta in corso…"; msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/export", { method: "POST" });
        if (msg) {
          msg.style.color = "var(--green)";
          msg.textContent = data.message || "Esportazione avviata. Riceverai una email con il link.";
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = "Errore: " + exc.message; }
      } finally {
        btn.disabled = false;
        await loadPrivacyLog();
      }
    });
  }

  if ($("privacyEraseBtn")) {
    $("privacyEraseBtn").addEventListener("click", async () => {
      const reason = ($("privacyEraseReason") && $("privacyEraseReason").value.trim()) || "";
      if (!confirm("Sei sicuro di voler richiedere la cancellazione del tuo account? Questa azione è irreversibile.")) return;
      const btn = $("privacyEraseBtn");
      const msg = $("privacyEraseResult");
      btn.disabled = true;
      if (msg) { msg.textContent = "Richiesta in corso…"; msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/erase", { method: "POST", body: JSON.stringify({ reason }) });
        if (msg) {
          msg.style.color = "var(--amber)";
          msg.textContent = data.message || "Richiesta di cancellazione registrata.";
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = "Errore: " + exc.message; }
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
      if (msg) { msg.textContent = "Invio richiesta…"; msg.style.color = ""; }
      try {
        const data = await api("/api/privacy/dsar", { method: "POST" });
        if (msg) {
          msg.style.color = "var(--green)";
          msg.textContent = data.message || "DSAR registrata. Risposta entro 30 giorni.";
        }
      } catch (exc) {
        if (msg) { msg.style.color = "var(--danger)"; msg.textContent = "Errore: " + exc.message; }
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
    btn.textContent = "Apri profilo entità";
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
