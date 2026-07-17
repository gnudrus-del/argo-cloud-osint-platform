/* Argo Cloud — lightweight i18n engine (no dependencies).
 *
 * How it works
 * ------------
 * - Every translatable node in the HTML carries data-i18n="key".
 *   Its text is replaced from DICT[key][lang]. When the translation
 *   contains inline markup (<strong>, <code>, <span>…), the node also
 *   carries data-i18n-html and innerHTML is used instead of textContent.
 * - Attributes are translated with data-i18n-attr="attr:key;attr2:key2"
 *   (e.g. placeholder, aria-label, data-text for the hero animation).
 * - Dynamic strings produced by app.js go through window.I18N.t(key, params).
 *
 * Language resolution: localStorage('argo_lang') → navigator.language →
 * English fallback. English is the default for any non-Italian browser so
 * the platform reads as international out of the box.
 */
(function () {
  "use strict";

  var SUPPORTED = ["en", "it"];
  var STORE_KEY = "argo_lang";
  var DEFAULT = "en";

  // ---- dictionary -------------------------------------------------------
  // key: { en, it }. Keys marked with markup are rendered via innerHTML on
  // elements that also declare data-i18n-html.
  var DICT = {
    // meta
    "meta.title": { en: "Argo Cloud — Open Source Intelligence", it: "Argo Cloud — Open Source Intelligence" },

    // language selector (first-run overlay)
    "lang.choose": { en: "Choose your language", it: "Scegli la lingua" },
    "lang.hint": { en: "You can change it anytime from the top bar.", it: "Puoi cambiarla in qualsiasi momento dalla barra in alto." },
    "lang.switch.aria": { en: "Change language", it: "Cambia lingua" },

    // nav
    "nav.why": { en: "Why Argo", it: "Perché Argo" },
    "nav.how": { en: "How it works", it: "Come funziona" },
    "nav.stack": { en: "Engine", it: "Motore" },
    "nav.start": { en: "Get started", it: "Inizia" },

    // hero
    "hero.eyebrow": { en: "Open Source Intelligence · GDPR-oriented · tamper-evident", it: "Open Source Intelligence · GDPR-oriented · inviolabile" },
    "hero.w1": { en: "Trace", it: "Traccia" },
    "hero.w2": { en: "every", it: "ogni" },
    "hero.w3": { en: "lead.", it: "indizio." },
    "hero.w4": { en: "Leave", it: "Non" },
    "hero.w5": { en: "no", it: "lasci" },
    "hero.w6": { en: "trace.", it: "traccia." },
    "hero.lead": {
      en: "Argo is the privacy-by-design OSINT engine, built for GDPR from day one. 66 native connectors, all queried together on every search, audit-chained reports. Zero data sent to third-party cloud services by default.",
      it: "Argo è il motore OSINT italiano privacy-by-design. 66 connettori nativi, tutti insieme ad ogni ricerca, report con catena audit verificabile. Zero dati inviati a servizi cloud terzi di default."
    },
    "hero.cta.primary": { en: "Try it free", it: "Prova gratis" },
    "hero.cta.ghost": { en: "How it works", it: "Come funziona" },
    "hero.scroll": { en: "Scroll", it: "Scorri" },

    // marquee
    "mq.connectors": { en: "66 native connectors", it: "66 connettori nativi" },
    "mq.saas": { en: "No mandatory SaaS", it: "Zero SaaS obbligatori" },
    "mq.audit": { en: "SHA-256 audit chain", it: "Audit chain SHA-256" },
    "mq.report": { en: "STIX 2.1 · MISP reports", it: "Report STIX 2.1 · MISP" },
    "mq.gdpr": { en: "GDPR + RoE", it: "GDPR + RoE" },
    "mq.license": { en: "Apache 2.0 open source", it: "Codice open source Apache 2.0" },

    // why
    "why.kicker": { en: "Why Argo", it: "Perché Argo" },
    "why.title": { en: 'OSINT that does <span class="brand-gold">not</span> sell<br> your targets.', it: 'OSINT che <span class="brand-gold">non</span> vende<br> i tuoi target.' },
    "why.c1.h": { en: "Nothing leaves your VM.", it: "Nulla lascia la tua VM." },
    "why.c1.p": { en: "We aggregate public sources locally. No target, no case, no query ever passes through a third-party provider.", it: "Aggreghiamo fonti pubbliche in locale. Nessun target, nessun caso, nessuna query passa da un provider esterno." },
    "why.c2.h": { en: "Prove every claim.", it: "Prova ogni claim." },
    "why.c2.p": { en: "Every finding carries its provenance, SHA-256 hash, timestamp and a verifiable audit chain. Tamper-evident by design.", it: "Ogni finding porta con sé provenance, hash SHA-256, timestamp e catena audit verificabile. Inviolabile per design." },
    "why.c3.h": { en: "Compliance by design.", it: "Compliance nel design." },
    "why.c3.p": { en: "Rules of Engagement per case, documented legal basis, built-in DSAR, tombstoned erasure.", it: "Rules of Engagement per ogni caso, base giuridica documentata, DSAR built-in, cancellazione tombstonata." },

    // how
    "how.kicker": { en: "How it works", it: "Come funziona" },
    "how.title": { en: 'From an entity <span class="brand-gold">to a report</span> in 4 steps.', it: 'Da un\'entità <span class="brand-gold">a un report</span> in 4 mosse.' },
    "how.s1.h": { en: "Open a case", it: "Apri un caso" },
    "how.s1.p": { en: "Legal basis, authorized scope, collaborators. Nothing starts without a mandate.", it: "Base giuridica, scope autorizzato, collaboratori. Nulla parte senza mandato." },
    "how.s2.h": { en: "Search the entity", it: "Cerca l'entità" },
    "how.s2.p": { en: "Email, phone, username, domain, wallet, IP. Argo queries all 66 matching connectors together — no cherry-picking, no silent exclusions.", it: "Email, telefono, username, dominio, wallet, IP. Argo interroga insieme tutti i 66 connettori compatibili — nessuna cernita, nessuna esclusione silenziosa." },
    "how.s3.h": { en: "Verify the sources", it: "Verifica le fonti" },
    "how.s3.p": { en: "Entity-relationship graph, Admiralty scoring, cross-source corroboration, why_linked.", it: "Grafo entità-relazioni, scoring Admiralty, corroborazioni cross-source, why_linked." },
    "how.s4.h": { en: "Generate the report", it: "Genera il report" },
    "how.s4.p": { en: "19-section forensic PDF · JSON · Markdown · STIX 2.1 · MISP event. Signed audit chain.", it: "PDF forense a 19 sezioni · JSON · Markdown · STIX 2.1 · MISP event. Audit chain firmata." },

    // stack
    "stack.kicker": { en: "The engine", it: "Il motore" },
    "stack.title": { en: '<span class="brand-gold">63</span> connectors. One engine.', it: '<span class="brand-gold">63</span> connettori. Un solo motore.' },
    "stack.email": { en: "Email", it: "Email" },
    "stack.username": { en: "Username", it: "Username" },
    "stack.phone": { en: "Phone", it: "Telefono" },
    "stack.domain": { en: "Domain", it: "Dominio" },
    "stack.network": { en: "Network", it: "Rete" },
    "stack.threat": { en: "Threat intel", it: "Threat intel" },
    "stack.corporate": { en: "Corporate", it: "Corporate" },
    "stack.reverse": { en: "Reverse", it: "Reverse" },

    // demo
    "demo.kicker": { en: "Try it without signing up", it: "Prova senza registrarti" },
    "demo.title": { en: 'A preview. <span class="brand-gold">In 3 seconds.</span>', it: 'Un\'anteprima. <span class="brand-gold">In 3 secondi.</span>' },
    "demo.lead": { en: "Type a fake email, domain or @username. Argo simulates a real search with synthetic data. No network call to the target.", it: "Digita un'email, un dominio o un @username finto. Argo simula una ricerca reale con dati sintetici. Nessuna chiamata di rete verso il target." },
    "demo.input.ph": { en: "e.g. john.doe@example.com", it: "es. mario.rossi@example.com" },
    "demo.run": { en: "Analyze", it: "Analizza" },
    "demo.hint": { en: "Try it with:", it: "Provalo con:" },
    "demo.idle": { en: "Waiting for input", it: "In attesa di un input" },

    // voices
    "voices.kicker": { en: "Intended use cases", it: "Casi d'uso previsti" },
    "voices.title": { en: 'Who <span class="brand-gold">Argo</span> is for.', it: 'Per chi è pensato <span class="brand-gold">Argo.</span>' },
    "voices.lead": { en: 'The profiles below describe the <strong>use cases</strong> the product was designed for. If you recognize yourself in one of these contexts, Argo can probably help you — and to check, you can read the <a href="#stack" class="voicesInlineLink">code</a> directly.', it: 'I profili qui sotto descrivono i <strong>casi d\'uso</strong> per cui il prodotto è stato pensato. Se ti riconosci in uno di questi contesti, probabilmente Argo può aiutarti — e per verificarlo puoi leggere direttamente il <a href="#stack" class="voicesInlineLink">codice</a>.' },
    "voices.c1.q": { en: "Typical situation: an independent OSINT analyst who today uses three cloud services and fears leakage of investigation data. With Argo everything stays on their own VM, and the audit chain produces evidence that holds up in an expert report.", it: "Situazione tipica: analista OSINT indipendente che oggi usa tre servizi cloud e teme la fuoriuscita dei dati d'inchiesta. Con Argo tutto resta sulla propria VM, e la catena audit produce evidenze richiamabili in perizia." },
    "voices.c1.role": { en: "Independent OSINT analyst", it: "Analista OSINT indipendente" },
    "voices.c1.org": { en: "Authorized investigation firm", it: "Studio investigativo autorizzato" },
    "voices.c2.q": { en: "Typical situation: a SOC/CTI team that needs to correlate suspicious entities without sending IoCs to third parties. The entity-relationship graph speeds up attribution and the STIX report integrates with an existing TIP with no changes.", it: "Situazione tipica: SOC/CTI che deve correlare entità sospette senza mandare IoC a terzi. Il grafo entità-relazioni accelera l'attribuzione e il report STIX si integra con un TIP esistente senza modifiche." },
    "voices.c2.role": { en: "Threat Intelligence Analyst", it: "Threat Intelligence Analyst" },
    "voices.c2.org": { en: "In-house SOC of a regulated organization", it: "SOC interno di un'organizzazione regolamentata" },
    "voices.c3.q": { en: 'Typical situation: investigative journalism with evidentiary needs. The Rules of Engagement + audit chain combination lets you answer the "how do you know" question with hashes, timestamps and an immutable chain.', it: 'Situazione tipica: giornalismo d\'inchiesta con esigenza probatoria. La combinazione Rules of Engagement + catena audit permette di rispondere alla domanda "come lo sai" con hash, timestamp e catena immutabile.' },
    "voices.c3.role": { en: "Investigative journalist", it: "Giornalista d'inchiesta" },
    "voices.c3.org": { en: "Freelance or independent outlet", it: "Freelance o testata indipendente" },
    "voices.c4.q": { en: "Typical situation: a law firm bound to confidentiality over its clients' data. Local execution guarantees that nothing leaves the firm's perimeter, and the Apache 2.0 license removes any per-case cost.", it: "Situazione tipica: studio legale con obbligo di riservatezza sui dati degli assistiti. L'esecuzione locale garantisce che nulla esca dal perimetro dello studio, e la licenza Apache 2.0 rimuove il costo per numero di casi." },
    "voices.c4.role": { en: "Law firm (criminal / cybercrime)", it: "Studio legale (penale/cybercrime)" },
    "voices.c4.org": { en: "Criminal law, contractual confidentiality", it: "Diritto penale, riservatezza contrattuale" },

    // free
    "free.kicker": { en: "A tool, not a subscription.", it: "Uno strumento, non un abbonamento." },
    "free.title": { en: 'No <span class="brand-gold">paywall</span>, no expiry, no telemetry.', it: 'Nessun <span class="brand-gold">paywall</span>, nessuna scadenza, nessuna telemetria.' },
    "free.lead": { en: 'Argo is free software under the Apache 2.0 license: download it, install it on your own infrastructure, modify it and — if you want — redistribute it. We don\'t count your cases, your connectors or your searches. No trial, no "Pro" edition, no upselling. We ask for an email at sign-up to verify the account identity and to reach you if a critical vulnerability emerges: it\'s the only information we see, and it stays yours.', it: 'Argo è software libero sotto licenza Apache 2.0: lo scarichi, lo installi sulla tua infrastruttura, lo modifichi e — se vuoi — lo redistribuisci. Non contiamo i tuoi casi, i tuoi connettori, le tue ricerche. Nessun trial, nessuna versione "Pro", nessun upselling. Ti chiediamo un\'email al momento della registrazione per verificare l\'identità dell\'account e per poterti raggiungere se emerge una vulnerabilità critica: è l\'unica informazione che vediamo, e resta tua.' },
    "free.c1.h": { en: "Searches", it: "Ricerche" },
    "free.c1.s": { en: "No quota limit imposed by us.", it: "Nessun quota-limit imposto da noi." },
    "free.c2.h": { en: "Connectors", it: "Connettori" },
    "free.c2.s": { en: "All integrated ones, right away.", it: "Tutti quelli integrati, subito." },
    "free.c3.h": { en: "License", it: "Licenza" },
    "free.c3.s": { en: "Commercial use included.", it: "Uso commerciale incluso." },
    "free.c4.h": { en: "Inspectable code", it: "Codice ispezionabile" },
    "free.c4.s": { en: "Every line readable on GitHub.", it: "Ogni riga leggibile su GitHub." },
    "free.cta": { en: "Try it online now", it: "Prova subito online" },

    // faq
    "faq.kicker": { en: "Frequently asked questions", it: "Domande frequenti" },
    "faq.title": { en: 'The things you <span class="brand-gold">ask</span> most.', it: 'Le cose che <span class="brand-gold">chiedete</span> più spesso.' },
    "faq.q1": { en: "Is it really open source? Even for commercial use?", it: "È veramente open source? Anche per uso commerciale?" },
    "faq.a1": { en: 'Yes. <strong>Apache 2.0</strong> license: you can self-host, modify, distribute and use Argo commercially. The only thing we ask is that you keep the copyright notice in the files you redistribute. No "dual model", no "core+enterprise": <strong>one codebase, the same for everyone</strong>.', it: 'Sì. Licenza <strong>Apache 2.0</strong>: puoi self-hostare, modificare, distribuire e usare Argo commercialmente. L\'unica cosa che ti chiediamo è di mantenere il copyright notice nei file che redistribuisci. Nessun "modello dual", nessun "core+enterprise": <strong>un solo codice, uno solo per tutti</strong>.' },
    "faq.q2": { en: "How do you guarantee none of my targets' data ends up with you?", it: "Come garantite che nessun dato dei miei target finisca da voi?" },
    "faq.a2": { en: 'We don\'t ask you to install anything of ours as a runtime dependency. Argo runs <strong>entirely on your own VM or machine</strong>. There is no telemetry, no "phone home". You call the BYOK APIs (Shodan, VirusTotal, HIBP, etc.) directly with your own key — we never intermediate them. You can verify it with <code>strace</code> or from the source.', it: 'Non ti chiediamo di installare nulla di nostro come dipendenza runtime. Argo gira <strong>interamente sulla tua VM o macchina</strong>. Non c\'è telemetria, non c\'è "ping home". Le API BYOK (Shodan, VirusTotal, HIBP, ecc.) le chiami direttamente tu con la tua chiave — noi non le intermediamo. Puoi verificarlo con <code>strace</code> o dal codice.' },
    "faq.q3": { en: "How do you self-host it? Do you need an ops team?", it: "Come si self-hosta? Serve un ops team?" },
    "faq.a3": { en: 'Setup: <code>git clone</code>, <code>python -m venv</code>, <code>pip install</code>, a systemd unit, Caddy in front for HTTPS. The repo includes <code>deploy_artifacts/</code> with an installer, a ready Caddyfile and an optional docker-compose for Neo4j/Postgres/Redis. <strong>Real measurements from the demo instance</strong> (Ubuntu 24.04 on Oracle Cloud, 1 vCPU / 5.9 GB): the Argo process uses <strong>~57 MB RSS</strong>, the full system <strong>~700 MB</strong>, the <code>/opt/argo-osint</code> folder is <strong>109 MB</strong>, load average steady at 0.00. In theory far less than 4 GB is enough, but we haven\'t yet measured sustained use under real load. Our first deploy took <strong>~45 minutes</strong> including debugging the Oracle security list; on a clean Ubuntu with no network surprises it should be noticeably faster.', it: 'Setup: <code>git clone</code>, <code>python -m venv</code>, <code>pip install</code>, systemd unit, Caddy davanti per HTTPS. Il repo include <code>deploy_artifacts/</code> con installer, Caddyfile pronto, docker-compose opzionale per Neo4j/Postgres/Redis. <strong>Misure reali dall\'istanza demo</strong> (Ubuntu 24.04 su Oracle Cloud, 1 vCPU / 5.9 GB): il processo Argo occupa <strong>~57 MB RSS</strong>, il sistema completo <strong>~700 MB</strong>, la cartella <code>/opt/argo-osint</code> è <strong>109 MB</strong>, load average stabile a 0.00. In teoria basta molto meno di 4 GB, ma non abbiamo ancora misurato l\'uso continuativo sotto carico reale. Il nostro primo deploy ha richiesto <strong>~45 minuti</strong> includendo debug della security list Oracle; su una Ubuntu pulita senza sorprese di rete dovrebbe essere sensibilmente più rapido.' },
    "faq.q4": { en: 'What is the "court-ready audit chain" in practice?', it: 'Cos\'è la "catena audit court-ready" in pratica?' },
    "faq.a4": { en: 'Every event (login, search, finding, erasure) is appended to a list of records. Each record contains: <code>timestamp</code>, <code>actor</code>, <code>action</code>, <code>details</code>, <code>previous_hash</code>, <code>hash</code> (SHA-256 of the event + the previous one). Altering an event in the middle of the chain invalidates every subsequent hash — <strong>tampering is detectable with a single command</strong>. It\'s the same pattern used by Certificate Transparency and Git.', it: 'Ogni evento (login, ricerca, finding, cancellazione) viene appeso a una lista di record. Ogni record contiene: <code>timestamp</code>, <code>actor</code>, <code>action</code>, <code>details</code>, <code>previous_hash</code>, <code>hash</code> (SHA-256 dell\'evento + del precedente). Modificare un evento in mezzo alla catena invalida tutti gli hash successivi — <strong>la manomissione è rilevabile con una comando</strong>. È il pattern usato da Certificate Transparency e da Git.' },
    "faq.q5": { en: "Why is Argo built around EU compliance?", it: 'Perché "italiano"? Cosa cambia rispetto ad altri tool OSINT?' },
    "faq.a5": { en: "Argo starts from the idea that professional OSINT in the EU has specific requirements: <strong>GDPR</strong>, <strong>a documented legal basis for every case</strong>, <strong>signed Rules of Engagement</strong>, <strong>ready-to-serve DSARs</strong>, <strong>configurable retention</strong>. It isn't a US tool with a translation bolted on: it's designed for Italian and European compliance from day zero. UI, documentation, warnings and reports are available in both Italian and English.", it: "Argo nasce con l'idea che l'OSINT professionale in Italia (e in UE) ha requisiti specifici: <strong>GDPR</strong>, <strong>base giuridica documentata per ogni caso</strong>, <strong>Rules of Engagement firmate</strong>, <strong>DSAR pronti</strong>, <strong>retention configurabile</strong>. Non è un tool americano tradotto: è pensato per la compliance italiana ed europea dal giorno zero. UI, documentazione, warning e report escono in italiano e inglese." },
    "faq.q6": { en: "Which connectors can I use without paying anyone?", it: "Quali connettori posso usare senza pagare nessuno?" },
    "faq.a6": { en: 'Out of 66 connectors, <strong>49 are no-key</strong>: crt.sh, RDAP, DNS, TLS cert, Wayback, Gravatar, GDELT, Nominatim, PhishTank, OpenPhish, subdomain enumeration, port scan (active, gated), holehe, maigret, telegram checker, RIPEstat, HackerTarget, Wikipedia, and more. The 17 BYOK ones (Shodan, VirusTotal, HIBP, ContactOut, Lusha, etc.) become available the moment you paste your own key into the "API keys" tab.', it: 'Su 66 connettori totali, <strong>49 sono no-key</strong>: crt.sh, RDAP, DNS, TLS cert, Wayback, Gravatar, GDELT, Nominatim, PhishTank, OpenPhish, subdomain enumeration, port scan (attivo, gated), holehe, maigret, telegram checker, RIPEstat, HackerTarget, Wikipedia, ecc. I 17 BYOK (Shodan, VirusTotal, HIBP, ContactOut, Lusha, ecc.) diventano disponibili nel momento in cui incolli la tua chiave nel tab "Chiavi API".' },
    "faq.q7": { en: "Can I contribute? How do I add a connector?", it: "Posso contribuire? Come si aggiunge un connettore?" },
    "faq.a7": { en: "Yes, PRs welcome. A connector is a class that extends <code>BaseConnector</code>, declares a typed <code>spec</code> (input types, rate limit, cache TTL, legal note) and implements <code>_fetch()</code>, with an offline test that simulates its output. The pattern is documented in <code>CONTRIBUTING.md</code> with a minimal template. Golden rules: passive by default, graceful degradation when a key is missing, no mandatory SaaS service.", it: "Sì, PR benvenute. Un connettore è una classe che estende <code>BaseConnector</code>, dichiara uno <code>spec</code> tipizzato (input types, rate limit, cache TTL, legal note) e implementa <code>_fetch()</code>. Con un test offline che simula l'output. Il pattern è documentato in <code>CONTRIBUTING.md</code> con un template minimale. Regole d'oro: passivo di default, degradazione graceful se manca la chiave, nessun servizio SaaS obbligatorio." },
    "faq.q8": { en: "Is there commercial support? Training? On-premise deployment for companies?", it: "C'è supporto commerciale? Formazione? Deploy on-premise per aziende?" },
    "faq.a8": { en: "The project is maintained <strong>on a voluntary basis</strong> and does not yet have a commercial structure. There is no paid support channel, no team answering tickets, no SLA contracts. If you need assisted deployment or training, for now the realistic path is to do it in-house with the open code. <strong>The free-and-open code always remains fully usable.</strong>", it: "Il progetto è mantenuto <strong>volontariamente</strong> e non ha ancora una struttura commerciale. Non c'è un canale di supporto paid, non c'è un team che risponde a ticket, non ci sono contratti SLA. Se hai bisogno di deploy assistito o formazione, per ora la strada realistica è farlo internamente col codice open. <strong>Il codice free-and-open resta sempre completamente utilizzabile.</strong>" },

    // start / auth
    "start.kicker": { en: "Get started now", it: "Inizia adesso" },
    "start.title": { en: 'Create your account. <span class="brand-gold">Free.</span>', it: 'Crea il tuo account. <span class="brand-gold">Gratis.</span>' },
    "start.lead": { en: "No card. No telemetry. Inspectable code.", it: "Nessuna carta. Nessuna telemetria. Codice ispezionabile." },
    "auth.tag": { en: "Open Source Intelligence", it: "Open Source Intelligence" },
    "auth.login": { en: "Sign in", it: "Accedi" },
    "auth.signup": { en: "Sign up free", it: "Iscriviti gratis" },
    "auth.user": { en: "Username", it: "Username" },
    "auth.email": { en: "Email", it: "Email" },
    "auth.pass": { en: "Password", it: "Password" },
    "auth.email.ph": { en: "name@example.com", it: "nome@example.com" },
    "auth.pass.ph": { en: "minimum 12 characters", it: "minimo 12 caratteri" },
    "auth.submit": { en: "Sign in", it: "Accedi" },
    "auth.or": { en: "or", it: "oppure" },

    // footer
    "foot.tag": { en: "<strong>Argo OSINT</strong> — the investigation platform that stays yours.", it: "<strong>Argo OSINT</strong> — la piattaforma investigativa che rimane tua." },
    "foot.license": { en: "Apache 2.0 open source", it: "Open source Apache 2.0" },
    "foot.privacy": { en: "Privacy-first by design", it: "Progettata privacy-first" },
    "foot.eng": { en: "Italian engineering, international standards", it: "Ingegneria italiana, standard internazionali" },

    // app sidebar
    "side.dashboard": { en: "Dashboard", it: "Dashboard" },
    "side.cases": { en: "Cases", it: "Casi" },
    "side.investigate": { en: "Search", it: "Ricerca" },
    "side.jobs": { en: "Reports", it: "Report" },
    "side.media": { en: "Media", it: "Media" },
    "side.keys": { en: "API keys", it: "Chiavi API" },
    "side.entity": { en: "Profile", it: "Profilo" },
    "side.opsec": { en: "OPSEC", it: "OPSEC" },
    "side.methodology": { en: "Methodology", it: "Metodologia" },
    "side.privacy": { en: "Privacy", it: "Privacy" },
    "side.logout": { en: "Log out", it: "Esci" },

    // voices carousel aria-labels
    "voices.navAria": { en: "Navigate use cases", it: "Naviga tra i casi d'uso" },
    "voices.dotAria1": { en: "Use case 1", it: "Caso d'uso 1" },
    "voices.dotAria2": { en: "Use case 2", it: "Caso d'uso 2" },
    "voices.dotAria3": { en: "Use case 3", it: "Caso d'uso 3" },
    "voices.dotAria4": { en: "Use case 4", it: "Caso d'uso 4" },

    // investigate quick-modes aria-label
    "inv.modesAria": { en: "Search type", it: "Tipo di ricerca" },

    // demo simulator — progress stages
    "demo.stage.1": { en: "classifying target…", it: "classificazione target…" },
    "demo.stage.2": { en: "selecting connectors…", it: "selezione connettori…" },
    "demo.stage.3": { en: "cross-source collection…", it: "raccolta cross-source…" },
    "demo.stage.4": { en: "corroboration + scoring…", it: "corroborazione + scoring…" },
    "demo.stage.5": { en: "generating preview…", it: "generazione anteprima…" },

    // demo simulator — target line + disclaimer
    "demo.targetLine": {
      en: "Target: <strong>{value}</strong> · type: <strong>{type}</strong> · connectors consulted: {n}",
      it: "Target: <strong>{value}</strong> · tipo: <strong>{type}</strong> · connettori consultati: {n}"
    },
    "demo.disclaimer": {
      en: "☺ Simulation with synthetic data. No real call to the target. The live version actually runs the corresponding {n}+ connectors and produces evidence with SHA-256 provenance.",
      it: "☺ Simulazione con dati sintetici. Nessuna chiamata reale verso il target. La versione live esegue davvero i {n}+ connettori corrispondenti e produce evidenze con provenance SHA-256."
    },

    // demo simulator — fake findings (email)
    "demo.email.l1": { en: "Email domain valid", it: "Dominio email valido" },
    "demo.email.v1": { en: "gmail.com resolves (MX ok)", it: "gmail.com risolve (MX ok)" },
    "demo.email.l2": { en: "Gravatar", it: "Gravatar" },
    "demo.email.v2": { en: "public profile associated", it: "profilo pubblico associato" },
    "demo.email.l3": { en: "Registered on", it: "Registrata su" },
    "demo.email.v3": { en: "amazon.com · spotify.com · twitter.com", it: "amazon.com · spotify.com · twitter.com" },
    "demo.email.l4": { en: "Data breach", it: "Data breach" },
    "demo.email.v4": { en: "1 known breach (HIBP): Adobe 2013", it: "1 breach noto (HIBP): Adobe 2013" },
    "demo.email.l5": { en: "Legit score", it: "Legit score" },
    "demo.email.v5": { en: "82/100 · legitimate", it: "82/100 · legittima" },

    // demo simulator — fake findings (handle)
    "demo.handle.l1": { en: "Profiles found", it: "Profili trovati" },
    "demo.handle.v1": { en: "GitHub · GitLab · Reddit · Steam (10/12 with deterministic detection)", it: "GitHub · GitLab · Reddit · Steam (10/12 con detection deterministica)" },
    "demo.handle.l2": { en: "Maigret full", it: "Maigret full" },
    "demo.handle.v2": { en: "confirmed on 6 additional platforms", it: "confermato su 6 piattaforme aggiuntive" },
    "demo.handle.l3": { en: "socid-extractor", it: "socid-extractor" },
    "demo.handle.v3": { en: "numeric user_id + created_at extracted", it: "user_id numerico + created_at estratti" },
    "demo.handle.l4": { en: "Cross-corroboration", it: "Cross-corroboration" },
    "demo.handle.v4": { en: "email associated across 2 independent sources", it: "email associata su 2 fonti indipendenti" },

    // demo simulator — fake findings (domain)
    "demo.domain.l1": { en: "DNS", it: "DNS" },
    "demo.domain.v1": { en: "A · AAAA · MX · NS · TXT (9 records)", it: "A · AAAA · MX · NS · TXT (9 record)" },
    "demo.domain.l2": { en: "TLS cert", it: "TLS cert" },
    "demo.domain.v2": { en: "Let's Encrypt · SAN: 3 domains · SHA-256 fingerprint", it: "Let's Encrypt · SAN: 3 domini · SHA-256 fingerprint" },
    "demo.domain.l3": { en: "Subdomains", it: "Subdomains" },
    "demo.domain.v3": { en: "47 active hosts (CT logs + brute DNS + Common Crawl)", it: "47 host attivi (CT logs + brute DNS + Common Crawl)" },
    "demo.domain.l4": { en: "Wayback", it: "Wayback" },
    "demo.domain.v4": { en: "1247 historical URLs · 23 interesting (/admin, /api, .env)", it: "1247 URL storiche · 23 interessanti (/admin, /api, .env)" },
    "demo.domain.l5": { en: "Reputation", it: "Reputation" },
    "demo.domain.v5": { en: "clean (ThreatFox · VT via BYOK)", it: "clean (ThreatFox · VT via BYOK)" },

    // demo simulator — fake findings (phone)
    "demo.phone.l1": { en: "libphonenumber", it: "libphonenumber" },
    "demo.phone.v1": { en: "valid · mobile · Italy (+39) · TIM", it: "valido · mobile · Italia (+39) · TIM" },
    "demo.phone.l2": { en: "Ignorant", it: "Ignorant" },
    "demo.phone.v2": { en: "registered on Instagram · Amazon", it: "registrato su Instagram · Amazon" },
    "demo.phone.l3": { en: "Legit score", it: "Legit score" },
    "demo.phone.v3": { en: "76/100 · legitimate", it: "76/100 · legittima" },

    // demo simulator — fake findings (ip)
    "demo.ip.l1": { en: "ASN (Team Cymru)", it: "ASN (Team Cymru)" },
    "demo.ip.v1": { en: "AS15169 GOOGLE · US · 8.8.8.0/24", it: "AS15169 GOOGLE · US · 8.8.8.0/24" },
    "demo.ip.l2": { en: "Shodan InternetDB", it: "Shodan InternetDB" },
    "demo.ip.v2": { en: "port 53 · CPE: dnsmasq", it: "porte 53 · CPE: dnsmasq" },
    "demo.ip.l3": { en: "Reputation", it: "Reputation" },
    "demo.ip.v3": { en: "no threat intel", it: "no threat intel" },

    // demo simulator — fake findings (generic fallback)
    "demo.generic.l1": { en: "Unrecognized type", it: "Tipo non riconosciuto" },
    "demo.generic.v1": { en: "Argo still attempts a cross-connector aggregated search", it: "Argo prova comunque una ricerca aggregata cross-connettore" },

    // ---- app: common ----
    "common.loading": { en: "Loading…", it: "Carico…" },

    // app: topbar
    "topbar.title": { en: "New search", it: "Nuova ricerca" },
    "topbar.sub": { en: "Fill in the data. All areas are active: tick deep/dark web or red team only if needed.", it: "Compila i dati. Le aree sono tutte attive: spunta solo deep/dark web o red team se servono." },
    "topbar.refresh": { en: "Refresh reports", it: "Aggiorna report" },

    // app: dashboard
    "dash.heroTitle": { en: "OSINT engine for authorized investigations", it: "Motore OSINT per ricerche autorizzate" },
    "dash.heroSub": { en: "Search an entity — name, username, email, phone, domain, company, IP or wallet — and Argo aggregates public sources into a verifiable profile.", it: "Cerca una entità — nome, username, email, telefono, dominio, azienda, IP o wallet — e Argo aggrega le fonti pubbliche in un profilo verificabile." },
    "dash.search.ph": { en: "e.g. john.doe@example.com · @username · example.com · +1 555… · bc1q…", it: "es. mario.rossi@example.com · @username · example.com · +39 333… · bc1q…" },
    "dash.detectedType": { en: "type: —", it: "tipo: —" },
    "dash.caseAuto": { en: "— Case (auto) —", it: "— Caso (auto) —" },
    "dash.caseSelectTitle": { en: "Case to link the search to", it: "Caso a cui collegare la ricerca" },
    "dash.searchBtn": { en: "Search", it: "Cerca" },
    "dash.heroLegal": { en: "⚖️ Use only for lawful, authorized activities or with a documented legal basis. Email, phone and personal data require a case with a legal basis.", it: "⚖️ Usare solo per attività lecite, autorizzate o con base giuridica documentata. Per email, telefoni e dati personali serve un caso con base giuridica." },
    "dash.onboarding": { en: "How it works", it: "Come funziona" },
    "dash.ob1": { en: "Create case", it: "Crea caso" },
    "dash.ob2": { en: "Legal basis", it: "Base giuridica" },
    "dash.ob3": { en: "Search entity", it: "Cerca entità" },
    "dash.ob4": { en: "Verify sources", it: "Verifica fonti" },
    "dash.ob5": { en: "Generate report", it: "Genera report" },
    "dash.jobStatus": { en: "Job status", it: "Stato job" },
    "dash.coverage": { en: "Source coverage", it: "Copertura fonti" },
    "dash.warnings": { en: "Privacy / compliance alerts", it: "Avvisi privacy / compliance" },
    "dash.recentCases": { en: "Recent cases", it: "Casi recenti" },
    "dash.recentReports": { en: "Recent reports", it: "Report recenti" },

    // app: cases
    "cases.yours": { en: "Your cases", it: "I tuoi casi" },
    "cases.hint": { en: "Each investigation is a <strong>case</strong>. Specify title, legal basis and purpose. The jobs you launch in Search go into the case selected here.", it: "Ogni indagine e un <strong>caso</strong>. Specifica titolo, base giuridica e finalità. I job che lanci in Ricerca finiscono dentro il caso selezionato qui." },
    "cases.new": { en: "New case", it: "Nuovo caso" },
    "cases.title": { en: "Title", it: "Titolo" },
    "cases.title.ph": { en: "Example: Perimeter recon example.com — engagement 2026/03", it: "Esempio: Recon perimetro example.com — ingaggio 2026/03" },
    "cases.purpose": { en: "Purpose", it: "Finalità" },
    "cases.purpose.ph": { en: "Why are you carrying out this investigation? (for the GDPR purpose and the exportable RoPA)", it: "Perché stai facendo questa indagine? (per la finalità GDPR e per il RoPA esportabile)" },
    "cases.legalType": { en: "Legal basis — type", it: "Base giuridica — tipo" },
    "cases.legal.consent": { en: "Consent", it: "Consenso" },
    "cases.legal.contract": { en: "Contract / signed engagement", it: "Contratto / ingaggio firmato" },
    "cases.legal.li": { en: "Legitimate interest", it: "Interesse legittimo" },
    "cases.legal.obligation": { en: "Legal obligation", it: "Obbligo di legge" },
    "cases.legal.public": { en: "Public-interest task", it: "Compito di interesse pubblico" },
    "cases.legal.vital": { en: "Vital interest", it: "Interesse vitale" },
    "cases.legal.unspecified": { en: "Unspecified (not recommended)", it: "Non specificata (sconsigliato)" },
    "cases.legalRef": { en: "Mandate / contract reference", it: "Riferimento mandato / contratto" },
    "cases.legalRef.ph": { en: "Example: SOW-2026-018", it: "Esempio: SOW-2026-018" },
    "cases.collabs": { en: "Collaborators (comma-separated usernames)", it: "Collaboratori (username separati da virgola)" },
    "cases.retention": { en: "Retention until (optional, ISO date)", it: "Retention fino al (opzionale, ISO date)" },
    "cases.scope": { en: "Authorized scope (one entry per line)", it: "Scope autorizzato (una voce per riga)" },
    "cases.scopeHint": { en: "Allowed formats: <code>domain</code>, <code>*.domain</code>, <code>IP</code>, <code>CIDR</code>, <code>URL</code>, <code>@handle</code>. Only targets in this list can be targeted by Red Team / active recon modules. Empty = no invasive module enabled.", it: "Formati ammessi: <code>dominio</code>, <code>*.dominio</code>, <code>IP</code>, <code>CIDR</code>, <code>URL</code>, <code>@handle</code>. Solo i target in questa lista possono essere bersaglio di moduli Red Team / active recon. Vuoto = nessun modulo invasivo abilitato." },
    "cases.create": { en: "Create case", it: "Crea caso" },

    // app: investigate
    "inv.title": { en: "New search", it: "Nuova ricerca" },
    "inv.lead": { en: "Pick the type, enter the value. Argo decides the rest.", it: "Scegli il tipo, inserisci il valore. Il resto lo decide Argo." },
    "inv.caseLabel": { en: "Investigation case", it: "Caso di indagine" },
    "inv.caseSelect": { en: "— select a case —", it: "— seleziona un caso —" },
    "inv.caseHelp": { en: "For personal data (email, phone, person) a case with a legal basis is mandatory.", it: "Per dati personali (email, telefono, persona) il caso con base giuridica è obbligatorio." },
    "inv.mode.username": { en: "Username", it: "Username" },
    "inv.mode.domain": { en: "Domain / Company", it: "Dominio / Azienda" },
    "inv.mode.contact": { en: "Email / Phone", it: "Email / Telefono" },
    "inv.mode.media": { en: "Image / Video", it: "Immagine / Video" },
    "inv.mode.crypto": { en: "Crypto wallet", it: "Wallet crypto" },
    "inv.modeHint": { en: "Public username: open profiles via Sherlock and Maigret.", it: "Username pubblico: profili aperti via Sherlock e Maigret." },
    "inv.legend.phone": { en: "Phone", it: "Telefono" },
    "inv.media.drop": { en: "📤 Drag here or click to upload", it: "📤 Trascina qui o clicca per caricare" },
    "inv.media.dropSub": { en: "EXIF + geo + reverse analysis starts automatically", it: "Analisi EXIF + geo + reverse parte automaticamente" },
    "inv.media.none": { en: "No file uploaded.", it: "Nessun file caricato." },
    "inv.ah.unlock": { en: "🔐 Unlock advanced features", it: "🔐 Sblocca funzioni avanzate" },
    "inv.ah.title": { en: "🎯 Aggressive search", it: "🎯 Ricerca aggressiva" },
    "inv.ah.lead": { en: "Click <b>multiple presets together</b> to combine tools: intensity and max pages take the highest value, modules add up.", it: "Clicca <b>più preset insieme</b> per combinare i tool: intensity e pagine massime prendono il valore più alto, i moduli si sommano." },
    "inv.ah.counter": { en: "No preset active — select one or more.", it: "Nessun preset attivo — seleziona uno o più." },
    "inv.ah.username": { en: "Username — full scan", it: "Username — full scan" },
    "inv.ah.email": { en: "Email — deep breach + accounts", it: "Email — deep breach + accounts" },
    "inv.ah.phone": { en: "Phone — phone OSINT", it: "Telefono — phone OSINT" },
    "inv.ah.person": { en: "Person — alias & news", it: "Persona — alias & news" },
    "inv.ah.domain": { en: "Domain — attack surface", it: "Dominio — attack surface" },
    "inv.ah.wallet": { en: "Wallet — chain analysis", it: "Wallet — chain analysis" },
    "inv.privacyMsg": { en: "Personal data: a case with a legal basis is required.", it: "Dato personale: richiesto caso con base giuridica." },
    "inv.adv": { en: "⚙ Advanced options", it: "⚙ Opzioni avanzate" },
    "inv.type": { en: "Type", it: "Tipo" },
    "inv.type.auto": { en: "Auto-detect", it: "Auto-rilevamento" },
    "inv.type.domain": { en: "Domain", it: "Dominio" },
    "inv.type.company": { en: "Company", it: "Azienda" },
    "inv.type.person": { en: "Person", it: "Persona" },
    "inv.type.handle": { en: "Username", it: "Username" },
    "inv.type.email": { en: "Email", it: "Email" },
    "inv.type.phone": { en: "Phone", it: "Telefono" },
    "inv.type.crypto": { en: "Crypto wallet", it: "Wallet crypto" },
    "inv.type.ip": { en: "IP", it: "IP" },
    "inv.type.media": { en: "Media", it: "Media" },
    "inv.provider": { en: "Search provider", it: "Provider di ricerca" },
    "inv.provider.all": { en: "All available", it: "Tutti i disponibili" },
    "inv.provider.auto": { en: "Auto API", it: "Auto API" },
    "inv.provider.none": { en: "Only entered data", it: "Solo dati inseriti" },
    "inv.intensity": { en: "Intensity", it: "Intensità" },
    "inv.intensity.meticulous": { en: "Meticulous", it: "Meticolosa" },
    "inv.intensity.deep": { en: "Maximum authorized", it: "Massima autorizzata" },
    "inv.intensity.quick": { en: "Quick", it: "Rapida" },
    "inv.maxPages": { en: "Max pages", it: "Pagine max" },
    "inv.seed": { en: "Seed URLs (optional)", it: "URL seed (opzionale)" },
    "inv.seed.ph": { en: "Verifiable public links, one per line", it: "Link pubblici verificabili, uno per riga" },
    "inv.known": { en: "Known information (optional)", it: "Informazioni note (opzionale)" },
    "inv.known.ph": { en: "Aliases, context, extra sources…", it: "Alias, contesto, fonti aggiuntive…" },
    "inv.gate.dark": { en: "Deep / Dark web", it: "Deep / Dark web" },
    "inv.gate.darkSub": { en: "Opt-in with documented authorization", it: "Opt-in con autorizzazione documentata" },
    "inv.gate.red": { en: "Red team", it: "Red team" },
    "inv.gate.redSub": { en: "Requires explicit scope in the case", it: "Richiede scope esplicito nel caso" },
    "inv.gate.net": { en: "Active network scan", it: "Network scan attivo" },
    "inv.gate.netSub": { en: "Only on authorized target", it: "Solo su target autorizzato" },
    "inv.run": { en: "🚀 Start search", it: "🚀 Avvia ricerca" },
    "inv.planOnly": { en: "Plan preview only", it: "Solo anteprima del piano" },
    "inv.plan": { en: "Automatic plan", it: "Piano automatico" },
    "inv.plan.pending": { en: "pending", it: "in attesa" },
    "inv.plan.empty": { en: "Fill in the fields and generate the preview.", it: "Compila i campi e genera l'anteprima." },

    // app: jobs / reports
    "jobs.title": { en: "Investigation reports", it: "Report investigativi" },
    "jobs.viewer": { en: "Viewer", it: "Viewer" },
    "jobs.stixTitle": { en: "STIX 2.1 bundle for TIP/SIEM", it: "STIX 2.1 bundle per TIP/SIEM" },
    "jobs.mispTitle": { en: "MISP core-format event", it: "MISP core-format event" },
    "jobs.tab.classic": { en: "Classic", it: "Classico" },
    "jobs.tab.forensic": { en: "Forensic (19 sections)", it: "Forensico (19 sezioni)" },
    "jobs.tab.aria": { en: "Report type", it: "Tipo report" },
    "jobs.viewer.empty": { en: "Select a completed report.", it: "Seleziona un report completato." },
    "jobs.forensicNav": { en: "Section index", it: "Indice sezioni" },

    // app: media
    "media.title": { en: "Images and video", it: "Immagini e video" },
    "media.tag": { en: "automatic analysis", it: "analisi automatica" },
    "media.hint": { en: "Analysis starts as soon as you select the file: EXIF, geolocation, SHA-256 hash, dimensions, MIME. If reverse tools are available, they run automatically.", it: "L'analisi parte appena selezioni il file: EXIF, geolocalizzazione, hash SHA-256, dimensioni, MIME. Se disponibili tool reverse, vengono lanciati automaticamente." },
    "media.result": { en: "Result", it: "Risultato" },
    "media.none": { en: "No file analyzed.", it: "Nessun file analizzato." },

    // app: keys
    "keys.title": { en: "API keys for your tools", it: "Chiavi API per i tuoi tool" },
    "keys.count": { en: "0 configured", it: "0 configurate" },
    "keys.hint": { en: "Keys entered here are used only by the jobs you launch, and are never shown in clear text in server responses: you'll only see the <code>••••••</code> preview + last 4 characters. Leave blank and save to remove.", it: "Le chiavi inserite qui sono usate solo dai job che lanci tu, non sono mai mostrate in chiaro nelle risposte del server: vedrai solo il preview <code>••••••</code>+ ultimi 4 caratteri. Lascia vuoto e salva per rimuovere." },
    "keys.coverage": { en: "Coverage status", it: "Stato copertura" },
    "keys.perService": { en: "per service", it: "per servizio" },

    // app: entity profile
    "entity.empty": { en: "Select a completed report in the <strong>Reports</strong> section, then click <em>Open entity profile</em> to view the aggregated profile here.", it: "Seleziona un report completato nella sezione <strong>Report</strong>, poi clicca <em>Apri profilo entità</em> per visualizzare il profilo aggregato qui." },
    "entity.pivot": { en: "Pivot search", it: "Pivot ricerca" },
    "entity.report": { en: "Generate report", it: "Genera report" },
    "entity.tab.identifiers": { en: "Identifiers", it: "Identificatori" },
    "entity.tab.domains": { en: "Domains / Companies", it: "Domini / Aziende" },
    "entity.tab.contacts": { en: "Contacts", it: "Contatti" },
    "entity.tab.evidences": { en: "Evidence", it: "Evidenze" },
    "entity.suggested": { en: "Suggested actions", it: "Azioni suggerite" },

    // app: opsec
    "opsec.routing": { en: "OPSEC routing", it: "Routing OPSEC" },
    "opsec.byPlan": { en: "controlled by the plan", it: "controllato dal piano" },
    "opsec.hint": { en: "OPSEC routing is managed automatically by the planner based on the case, target type and authorization flags.", it: "L'OPSEC routing e gestito automaticamente dal planner in base al caso, al tipo di target e ai flag di autorizzazione." },
    "meth.confidence": { en: "Finding confidence", it: "Confidenza dei findings" },
    "meth.tag": { en: "analytical discipline", it: "disciplina analitica" },
    "meth.intro": { en: "Every finding carries a confidence score (0.0–1.0) set by the connector that produced it. There is no single formula — just three qualitative anchor tiers.", it: "Ogni finding porta una confidenza (0.0–1.0) assegnata dal connettore che l'ha prodotto. Nessuna formula unica — solo tre livelli qualitativi di ancoraggio." },
    "meth.c1": { en: "<strong>Tentative (&lt; 0.5):</strong> plausible from indirect evidence, unverified — a single passive source, an inferred pattern, a snippet-only match.", it: "<strong>Tentative (&lt; 0.5):</strong> plausibile da evidenza indiretta, non verificata — una sola fonte passiva, un pattern inferito, un frammento di testo." },
    "meth.c2": { en: "<strong>Firm (0.5–0.85):</strong> directly observed, not yet independently corroborated — a DNS record that resolves, an API that returns a positive match.", it: "<strong>Firm (0.5–0.85):</strong> osservato direttamente, non ancora corroborato in modo indipendente — un record DNS che risolve, una API che risponde positivamente." },
    "meth.c3": { en: "<strong>Confirmed (&gt; 0.85):</strong> corroborated by ≥2 independent sources, or verified through direct, unambiguous interaction.", it: "<strong>Confirmed (&gt; 0.85):</strong> corroborato da ≥2 fonti indipendenti, o verificato con interazione diretta e inequivocabile." },
    "meth.ruleOfThree": { en: "<strong>Rule of three:</strong> don't assert an identity link from a single weak signal. Two independent weak signals, or one strong + one weak, before treating a link as Firm rather than Tentative.", it: "<strong>Regola del tre:</strong> non attribuire un legame d'identità da un solo segnale debole. Servono due segnali deboli indipendenti, o uno forte + uno debole, prima di trattare un collegamento come Firm invece che Tentative." },
    "meth.admiralty": { en: "Admiralty/NATO grade (STANAG 2511)", it: "Grado Admiralty/NATO (STANAG 2511)" },
    "meth.tag2": { en: "source reliability", it: "affidabilità della fonte" },
    "meth.admiraltyIntro": { en: "Every finding also carries a letter (reliability A–F) and a number (credibility 1–6), shown together in reports (e.g. \"B2\").", it: "Ogni finding porta anche una lettera (affidabilità A–F) e un numero (credibilità 1–6), mostrati insieme nei report (es. \"B2\")." },
    "meth.a1": { en: "<strong>Reliability (the source):</strong> A completely reliable → F cannot be judged.", it: "<strong>Affidabilità (la fonte):</strong> A completamente affidabile → F non giudicabile." },
    "meth.a2": { en: "<strong>Credibility (this piece of information):</strong> 1 confirmed by other sources → 6 cannot be judged.", it: "<strong>Credibilità (questa informazione):</strong> 1 confermata da altre fonti → 6 non giudicabile." },
    "meth.severity": { en: "Severity", it: "Severità" },
    "meth.s1": { en: "<strong>Critical/High:</strong> exposure with direct, verified impact (valid credentials, a listable bucket, pre-auth RCE).", it: "<strong>Critical/High:</strong> esposizione con impatto diretto e verificato (credenziali valide, bucket listabile, RCE pre-auth)." },
    "meth.s2": { en: "<strong>Medium/Low:</strong> information disclosure, hardening gaps, marginal exposure.", it: "<strong>Medium/Low:</strong> disclosure di informazioni, gap di hardening, esposizione marginale." },
    "meth.s3": { en: "<strong>Info:</strong> worth noting, no immediate action required.", it: "<strong>Info:</strong> degno di nota, nessuna azione immediata richiesta." },
    "meth.footer": { en: "Full methodology, with examples and guidance for new connector authors: docs/METHODOLOGY.md in the repository.", it: "Metodologia completa, con esempi ed estensioni per nuovi connettori: docs/METHODOLOGY.md nel repository." },

    "opsec.li1": { en: "<strong>Protected standard:</strong> default for authorized targets that don't need isolation.", it: "<strong>Standard protetto:</strong> default per target autorizzati senza necessità di isolamento." },
    "opsec.li2": { en: "<strong>Dedicated Mozilla/Firefox:</strong> enabled when the source requires a separate profile.", it: "<strong>Mozilla/Firefox dedicato:</strong> attivato se la sorgente richiede un profilo separato." },
    "opsec.li3": { en: "<strong>Isolated Tor:</strong> mandatory for flagged dark/deep web.", it: "<strong>Tor isolato:</strong> obbligatorio per dark/deep web flaggato." },
    "opsec.li4": { en: "<strong>Multi-provider:</strong> used when APIs are configured for multiple engines.", it: "<strong>Multi-provider:</strong> usato quando esistono API configurate per più motori." },
    "opsec.override": { en: "OPSEC route override (optional)", it: "Override percorso OPSEC (opzionale)" },
    "opsec.route.auto": { en: "Automatic (recommended)", it: "Automatico (consigliato)" },
    "opsec.route.multi": { en: "Controlled multi-provider", it: "Multi-provider controllato" },
    "opsec.route.standard": { en: "Protected standard", it: "Standard protetto" },
    "opsec.route.firefox": { en: "Dedicated Mozilla/Firefox", it: "Mozilla/Firefox dedicato" },
    "opsec.route.tor": { en: "Isolated Tor", it: "Tor isolato" },
    "opsec.audit": { en: "Audit and logging", it: "Audit e logging" },
    "opsec.free": { en: "Free", it: "Gratuito" },
    "opsec.au1": { en: "Audit log with SHA-256 hash chain — every event is traceable.", it: "Audit log con hash chain SHA-256 — ogni evento e tracciabile." },
    "opsec.au2": { en: "Login with logged IP for accountability.", it: "Login con IP loggato per accountability." },
    "opsec.au3": { en: "Mandatory verification email on first sign-up.", it: "Email di verifica obbligatoria al primo signup." },
    "opsec.au4": { en: "HttpOnly sessions, CSRF, Secure cookie.", it: "Sessioni HttpOnly, CSRF, Secure cookie." },
    "opsec.au5": { en: "GDPR by-design: DSAR export/erase, tombstone, RoPA.", it: "GDPR by-design: DSAR export/erase, tombstone, RoPA." },

    // app: privacy
    "privacy.center": { en: "Privacy Center", it: "Privacy Center" },
    "privacy.hint": { en: "You have the right to access, export or delete the data associated with your account. Requests are processed within 72 hours and recorded in the audit log.", it: "Hai il diritto di accedere, esportare o cancellare i dati associati al tuo account. Le richieste vengono processate entro 72 ore e registrate nel log di audit." },
    "privacy.export.h": { en: "Export your data", it: "Esporta i tuoi dati" },
    "privacy.export.p": { en: "Generate a JSON archive with all your cases, jobs, evidence and audit logs.", it: "Genera un archivio JSON con tutti i tuoi casi, job, evidenze e log di audit." },
    "privacy.export.btn": { en: "Request export", it: "Richiedi esportazione" },
    "privacy.erase.h": { en: "Delete account", it: "Cancella account" },
    "privacy.erase.p": { en: "Marks your account for deletion. Data is tombstoned and removed within the retention terms.", it: "Marca il tuo account per la cancellazione. I dati vengono tombstonati e rimossi nei termini di retention." },
    "privacy.erase.reason": { en: "Reason (optional)", it: "Motivo (opzionale)" },
    "privacy.erase.reason.ph": { en: "e.g. end of investigation, role change…", it: "es. fine indagine, cambio ruolo…" },
    "privacy.erase.btn": { en: "Request deletion", it: "Richiedi cancellazione" },
    "privacy.dsar.h": { en: "Get information (DSAR)", it: "Ottieni informazioni (DSAR)" },
    "privacy.dsar.p": { en: "Formal request under Art. 15 GDPR: data categories, purposes, recipients, retention.", it: "Richiesta formale ex Art. 15 GDPR: categorie di dati, finalità, destinatari, retention." },
    "privacy.dsar.btn": { en: "Send DSAR", it: "Invia DSAR" },
    "privacy.log": { en: "Privacy request log", it: "Log richieste privacy" },

    // app: modals
    "admin.title": { en: "🔐 Unlock advanced features", it: "🔐 Sblocco funzioni avanzate" },
    "admin.hint": { en: "Aggressive search features require administrator credentials. The unlock session applies only to this page (no persistence).", it: "Le funzioni di ricerca aggressiva richiedono credenziali amministratore. La sessione di sblocco vale solo per questa pagina (nessuna persistenza)." },
    "admin.user.ph": { en: "admin username", it: "admin username" },
    "admin.pass.ph": { en: "admin password", it: "password admin" },
    "admin.cancel": { en: "Cancel", it: "Annulla" },
    "admin.unlock": { en: "Unlock", it: "Sblocca" },
    "hr.title": { en: "⚠ High-risk mode", it: "⚠ Modalità ad alto rischio" },
    "hr.intro1": { en: "You are about to enable ", it: "Stai per abilitare " },
    "hr.intro2": { en: ". This mode accesses sensitive sources and requires:", it: ". Questa modalità accede a fonti sensibili e richiede:" },
    "hr.li1": { en: "Documented legal basis in the current case", it: "Base giuridica documentata nel caso corrente" },
    "hr.li2": { en: "Explicit authorization from the investigation lead", it: "Autorizzazione esplicita del responsabile dell'indagine" },
    "hr.li3": { en: "Automatic OPSEC isolation (Tor routing)", it: "Isolamento OPSEC automatico (routing Tor)" },
    "hr.justif": { en: "Mandatory justification", it: "Giustificazione obbligatoria" },
    "hr.justif.ph": { en: "Describe why this mode is necessary for this specific investigation…", it: "Descrivi perché questa modalità è necessaria per questa specifica indagine…" },
    "hr.confirm": { en: "I confirm I have written authorization and a valid legal basis for this search.", it: "Confermo di avere l'autorizzazione scritta e base giuridica valida per questa ricerca." },
    "hr.cancel": { en: "Cancel", it: "Annulla" },
    "hr.proceed": { en: "Enable and proceed", it: "Abilita e procedi" },

    // ---- app.js: dynamic (panel topbars) ----
    "pt.dashboard.h": { en: "Dashboard", it: "Dashboard" },
    "pt.dashboard.p": { en: "Search an entity or resume a case. Gated areas (deep/dark web, red team) stay opt-in.", it: "Cerca una entità o riprendi un caso. Le aree gated (deep/dark web, red team) restano opt-in." },
    "pt.cases.h": { en: "Cases and investigations", it: "Casi e indagini" },
    "pt.cases.p": { en: "Every search lives inside a case with a documented legal basis and purpose.", it: "Ogni ricerca vive dentro un caso con base giuridica e finalità documentate." },
    "pt.jobs.p": { en: "Open a completed report to read evidence, the entity graph and sources.", it: "Apri un report completato per leggere evidenze, grafo entità e fonti." },
    "pt.media.p": { en: "Automatic analysis of images and video: EXIF, geo, hash, MIME.", it: "Analisi automatica di immagini e video: EXIF, geo, hash, MIME." },
    "pt.keys.h": { en: "API keys (BYOK)", it: "Chiavi API (BYOK)" },
    "pt.keys.p": { en: "Keys stay encrypted and are never shown in clear text.", it: "Le chiavi restano cifrate e non sono mai mostrate in chiaro." },
    "pt.opsec.p": { en: "Routing and isolation managed by the planner based on the case and flags.", it: "Routing e isolamento gestiti dal planner in base al caso e ai flag." },

    // app.js: mode presets (search form placeholder + hint)
    "mp.handle.ph": { en: "e.g. username or @username", it: "esempio: username oppure @username" },
    "mp.handle.hint": { en: "Public username: Sherlock and Maigret look for open profiles; contacts only if publicly visible in the sources.", it: "Username pubblico: Sherlock e Maigret cercano profili aperti; contatti solo se visibili pubblicamente nelle fonti." },
    "mp.domain.ph": { en: "e.g. example.com or a company name", it: "esempio: example.com oppure nome azienda" },
    "mp.domain.hint": { en: "Domain or company: the planner uses seeds, archives, subdomains and public sources.", it: "Dominio o azienda: il planner usa seed, archivi, sottodomini e fonti pubbliche." },
    "mp.contact.ph": { en: "e.g. name@example.com or an authorized number", it: "esempio: nome@example.com oppure numero autorizzato" },
    "mp.contact.hint": { en: "Email or phone: checks public presence and mentioned contacts; does not retrieve private registration data.", it: "Email o telefono: verifica presenza pubblica e contatti citati; non recupera dati privati di registrazione." },
    "mp.media.ph": { en: "upload the file in the Media section or enter a public URL", it: "carica il file nella sezione Media oppure inserisci un URL pubblico" },
    "mp.media.hint": { en: "Media: analysis of files and public references, with attention to metadata and context.", it: "Media: analisi di file e riferimenti pubblici, con attenzione a metadati e contesto." },
    "mp.crypto.ph": { en: "e.g. BTC/ETH address or public wallet", it: "esempio: address BTC/ETH o wallet pubblico" },
    "mp.crypto.hint": { en: "Crypto: contextualizes addresses and public sources without automatic attribution.", it: "Crypto: contestualizza address e fonti pubbliche senza attribuzioni automatiche." },
    "mp.domain.genph": { en: "example.com · 192.0.2.1 · Acme Inc", it: "example.com · 192.0.2.1 · Acme Spa" },
    "mp.crypto.genph": { en: "BTC / ETH address (bc1q… / 0x…)", it: "address BTC / ETH (bc1q… / 0x…)" },

    // app.js: auth
    "auth.submit.signup": { en: "Create free account", it: "Crea account gratis" },
    "auth.verifySent": { en: "Verification email sent to {email}. Click the link to activate your account.", it: "Email di verifica inviata a {email}. Clicca il link per attivare l'account." },
    "auth.searchFor": { en: "Analyze {target}", it: "Analizza {target}" },
    "auth.searchGeneric": { en: "Run an OSINT search", it: "Esegui una ricerca OSINT" },

    // app.js: common status / actions
    "st.error": { en: "error", it: "errore" },
    "st.pending": { en: "pending", it: "in attesa" },
    "st.running": { en: "running", it: "in corso" },
    "st.done": { en: "done", it: "completato" },
    "act.delReportTitle": { en: "Delete report and wipe traces", it: "Elimina report e cancella tracce" },
    "act.delAria": { en: "Delete", it: "Elimina" },
    "act.deletePrompt": {
      en: "Delete this report?\n\nThe files (markdown/json/pdf/forensic/redteam) and the DB record are removed.\nThe event stays tracked in the audit log.\n\nOptional reason (max 500 chars):",
      it: "Elimina questo report?\n\nI file (markdown/json/pdf/forensic/redteam) e il record DB vengono rimossi.\nL'evento resta tracciato nell'audit log.\n\nMotivo opzionale (max 500 char):"
    },
    "pl.seedPrefix": { en: "seed sources: {v}", it: "fonti seed: {v}" },
    "pl.knownPrefix": { en: "known information: {v}", it: "informazioni note: {v}" },

    // ---- app.js coda: agenti / piano ----
    "ag.planner": { en: "Planner", it: "Pianificatore" },
    "ag.web": { en: "Web coverage", it: "Copertura web" },
    "ag.opsec": { en: "OPSEC / exposed secrets", it: "OPSEC / segreti esposti" },
    "ag.geo": { en: "Geolocation", it: "Geolocalizzazione" },
    "ag.socmint": { en: "SOCMINT (public profiles)", it: "SOCMINT (profili pubblici)" },
    "ag.media": { en: "Media & metadata", it: "Media & metadati" },
    "ag.crypto": { en: "Crypto wallet", it: "Wallet crypto" },
    "ag.phone": { en: "Phone analysis", it: "Analisi telefono" },
    "ag.humint": { en: "HUMINT (ethical plan)", it: "HUMINT (piano etico)" },
    "ag.external": { en: "External tools", it: "Tool esterni" },
    "ag.reverse_account": { en: "Reverse account (email/phone)", it: "Reverse account (email/tel)" },
    "ag.darkweb": { en: "Deep / dark web", it: "Deep / dark web" },
    "ag.red_team": { en: "Red team", it: "Red team" },
    "ag.gatedTip": { en: "Active: requires authorization/flag", it: "Attivo: richiede autorizzazione/flag" },
    "ag.alwaysTip": { en: "Always active", it: "Sempre attivo" },
    "pl.activeAgents": { en: "Active agents", it: "Agenti attivi" },
    "pl.agentsNote": { en: "Every search runs all applicable agents: those not relevant to the target auto-exclude. 🔒 = requires flag/authorization.", it: "Ogni ricerca esegue tutti gli agenti applicabili: quelli non pertinenti al target si auto-escludono. 🔒 = richiede flag/autorizzazione." },
    "pl.tools": { en: "Tools", it: "Strumenti" },
    "pl.depth": { en: "Depth", it: "Profondità" },
    "pl.pages": { en: "Pages", it: "Pagine" },

    // app.js coda: capabilities
    "cap.hidden": { en: "🔒 Hidden tools and connectors", it: "🔒 Tool e connettori nascosti" },
    "cap.hiddenSub": { en: "{ok} active of {tot}. Unlock with the administrator password to view them.", it: "{ok} attivi su {tot}. Sblocca con la password amministratore per visualizzarli." },
    "cap.searchPrefix": { en: "Search", it: "Ricerca" },
    "cap.configured": { en: "configured", it: "configurata" },
    "cap.missingEnv": { en: "env missing", it: "manca env" },
    "cap.available": { en: "available", it: "disponibile" },
    "cap.unavailable": { en: "unavailable", it: "non disponibile" },
    "cap.connActive": { en: "active", it: "attivo" },
    "cap.connNeedsKey": { en: "requires API key: ", it: "richiede API key: " },
    "cap.connNeedsTool": { en: "requires tool/credential (env)", it: "richiede tool/credenziale (env)" },
    "cap.configMissing": { en: "config missing", it: "config mancante" },
    "cap.connectors": { en: "Connectors", it: "Connettori" },

    // app.js coda: jobs / reports
    "jb.noReports": { en: "No reports.", it: "Nessun report." },
    "jb.reportDeleted": { en: "Report deleted.", it: "Report eliminato." },
    "rt.unavailable": { en: "Red Team report unavailable", it: "Report Red Team non disponibile" },
    "rt.whenGenerated": { en: "The report is generated when: (1) the <b>red_team</b> module is active and (2) the case has at least one target in the <b>authorized scope</b>.", it: "Il report viene generato quando: (1) il modulo <b>red_team</b> è attivo e (2) il caso ha almeno un target nello <b>scope autorizzato</b>." },
    "rt.openCases": { en: "Open Cases", it: "Apri i Casi" },
    "rt.noForensic": { en: "No forensic report for this job. The 19-section forensic reports are generated for jobs started after the latest deploy.", it: "Nessun report forensico per questo job. I report forensici a 19 sezioni vengono generati per i job avviati dopo l'ultimo deploy." },
    "rp.case": { en: "Case", it: "Caso" },
    "rp.generated": { en: "generated", it: "generato" },
    "hrb.opsecActive": { en: "OPSEC mode active.", it: "Modalità OPSEC attiva." },
    "hrb.whyActive": { en: "Why it's active", it: "Perché è attiva" },

    // app.js coda: progress / status
    "pr.queued": { en: "queued", it: "in coda" },
    "pr.running": { en: "pipeline", it: "pipeline" },
    "pr.collecting": { en: "collecting", it: "raccolta" },
    "pr.pdf": { en: "PDF", it: "PDF" },
    "pr.pdfError": { en: "PDF unavailable", it: "PDF non disponibile" },
    "pr.complete": { en: "complete", it: "completo" },
    "st.state": { en: "status", it: "stato" },

    // app.js coda: entity graph
    "gr.title": { en: "Entity graph", it: "Grafo entità" },
    "gr.nodesLinks": { en: "{n} nodes · {r} visible relationships", it: "{n} nodi · {r} relazioni visibili" },
    "gr.ariaLabel": { en: "Report entity graph", it: "Grafo entità del report" },
    "gr.selectNode": { en: "Select a node to prepare an investigative pivot.", it: "Seleziona un nodo per preparare un pivot investigativo." },
    "gr.grade": { en: "grade", it: "grado" },
    "gr.confidence": { en: "confidence", it: "confidenza" },
    "gr.preparePivot": { en: "Prepare pivot", it: "Prepara pivot" },
    "gr.pivotPrepared": { en: "Pivot prepared from {type} entity of the selected report.", it: "Pivot preparato da entità {type} del report selezionato." },

    // app.js coda: entity type labels (inline, lowercase)
    "et.domain": { en: "domain", it: "dominio" },
    "et.organization": { en: "company", it: "azienda" },
    "et.email": { en: "email", it: "email" },
    "et.username": { en: "username", it: "username" },
    "et.phone": { en: "phone", it: "telefono" },
    "et.ip": { en: "IP", it: "IP" },
    "et.wallet": { en: "wallet", it: "wallet" },
    "et.url": { en: "URL", it: "URL" },
    "et.media": { en: "media", it: "media" },
    "et.location": { en: "place", it: "luogo" },

    // app.js coda: media
    "md.selectFile": { en: "Select a file.", it: "Seleziona un file." },
    "md.analyzing": { en: "Analyzing…", it: "Analisi in corso…" },
    "md.analyzingFile": { en: "Analyzing {name}…", it: "Analisi in corso di {name}…" },
    "md.na": { en: "n/a", it: "n/d" },

    // app.js coda: aggressive-hunt counter, privacy badge
    "inv.ah.activeCount": { en: "{presets} active presets · {modules} modules", it: "{presets} preset attivi · {modules} moduli" },
    "pb.caseSelected": { en: "Personal data: case selected. Make sure the legal basis is documented.", it: "Dato personale: caso selezionato. Verifica la base giuridica sia documentata." },
    "pb.needCase": { en: "⚠ Personal data: select a case with a legal basis first.", it: "⚠ Dato personale: seleziona prima un caso con base giuridica." },

    // app.js coda: API keys
    "ky.configured": { en: "{n} configured", it: "{n} configurate" },
    "ky.coverageUnavail": { en: "Coverage status unavailable: ", it: "Stato copertura non disponibile: " },
    "ky.other": { en: "Other", it: "Altri" },
    "ky.pastePlaceholder": { en: "Paste the key for {label} here", it: "Incolla qui la chiave per {label}" },
    "ky.save": { en: "Save", it: "Salva" },
    "ky.testTip": { en: "Runs a real probe against the provider to validate the key.", it: "Esegue una probe reale verso il provider per validare la chiave." },
    "ky.remove": { en: "Remove", it: "Rimuovi" },
    "ky.removeConfirm": { en: "Remove the saved key for {label}?", it: "Rimuovere la chiave salvata per {label}?" },
    "ky.noProviders": { en: "No provider in the catalog.", it: "Nessun provider nel catalogo." },
    "ky.saveError": { en: "Save error: ", it: "Errore salvataggio: " },
    "ky.probing": { en: "Probing…", it: "Probe in corso…" },
    "ky.testFailed": { en: "Test failed: ", it: "Test fallito: " },
    "ky.saved": { en: "Key saved · {masked} · updated {updated}", it: "Chiave salvata · {masked} · aggiornata {updated}" },
    "ky.noneSaved": { en: "No key saved.", it: "Nessuna chiave salvata." },
    "ps.not_configured": { en: "Not configured", it: "Non configurato" },
    "ps.untested": { en: "Saved, not tested", it: "Salvato, non testato" },
    "ps.ok": { en: "Active", it: "Attivo" },
    "ps.auth_error": { en: "Authentication error", it: "Errore autenticazione" },
    "ps.quota_exceeded": { en: "Quota exceeded", it: "Quota esaurita" },
    "ps.network_error": { en: "Network error", it: "Errore rete" },
    "ps.unsupported": { en: "Unsupported provider", it: "Provider non supportato" },

    // app.js coda: dashboard
    "db.loadError": { en: "Error loading the dashboard.", it: "Errore nel caricamento della dashboard." },
    "db.metrics": { en: "Platform metrics", it: "Metriche piattaforma" },
    "db.usersTotal": { en: "Total users", it: "Utenti totali" },
    "db.usersVerified": { en: "Verified users", it: "Utenti verificati" },
    "db.active24h": { en: "Active last 24h", it: "Attivi ultime 24h" },
    "db.active7d": { en: "Active last 7d", it: "Attivi ultimi 7gg" },
    "db.signups7d": { en: "New signups (7d)", it: "Nuove iscrizioni (7gg)" },
    "db.jobsTotal": { en: "Total jobs", it: "Job totali" },
    "db.jobsByStatus": { en: "Jobs by status", it: "Job per stato" },
    "db.chainValid": { en: "✓ intact", it: "✓ integra" },
    "db.chainBroken": { en: "⚠ compromised", it: "⚠ compromessa" },
    "db.events": { en: "events", it: "eventi" },
    "db.metricsLocked": { en: "📊 Platform metrics reserved for the administrator.", it: "📊 Metriche piattaforma riservate all'amministratore." },
    "db.unlock": { en: "🔐 Unlock", it: "🔐 Sblocca" },
    "db.loginHistory": { en: "Login history", it: "Storico accessi" },
    "db.colUser": { en: "User", it: "Utente" },
    "db.colEmail": { en: "Email", it: "Email" },
    "db.colProvider": { en: "Login method", it: "Metodo di accesso" },
    "db.colRole": { en: "Role", it: "Ruolo" },
    "db.roleAdmin": { en: "Admin", it: "Admin" },
    "db.roleAnalyst": { en: "Analyst", it: "Analista" },
    "db.roleManageHint": {
      en: "Roles are assigned from the server via \"argo-set-role &lt;user&gt; admin|analyst\" — not from this UI, by design.",
      it: "I ruoli si assegnano dal server con \"argo-set-role &lt;utente&gt; admin|analyst\" — non da questa UI, per scelta.",
    },
    "db.colLoginCount": { en: "Logins", it: "Accessi" },
    "db.colLastLogin": { en: "Last login", it: "Ultimo accesso" },
    "db.providerPassword": { en: "Password", it: "Password" },
    "db.neverLoggedIn": { en: "never", it: "mai" },
    "db.loginHistoryTruncated": { en: "Showing {shown} of {total} users.", it: "Mostrati {shown} di {total} utenti." },
    "db.pendingErasures": { en: "Pending profile deletions", it: "Cancellazioni profilo in attesa" },
    "db.noPendingErasures": { en: "No deletion requests awaiting approval.", it: "Nessuna richiesta di cancellazione da approvare." },
    "db.approve": { en: "Approve", it: "Approva" },
    "db.reject": { en: "Reject", it: "Rifiuta" },
    "db.colRequestedAt": { en: "Requested", it: "Richiesta il" },
    "db.colReason": { en: "Reason", it: "Motivo" },
    "db.colActions": { en: "Actions", it: "Azioni" },
    "db.erasureHint": {
      en: "Approving permanently erases that user's account and linked data (GDPR art. 17). Irreversible on the active datastore.",
      it: "Approvare cancella in modo permanente l'account dell'utente e i dati collegati (GDPR art. 17). Irreversibile sul datastore attivo.",
    },
    "db.approveConfirm": {
      en: "Permanently delete the account \"{owner}\" and all its data? This cannot be undone.",
      it: "Cancellare in modo permanente l'account \"{owner}\" e tutti i suoi dati? L'operazione è irreversibile.",
    },
    "db.approveDone": { en: "Deletion approved and executed.", it: "Cancellazione approvata ed eseguita." },
    "db.rejectPrompt": { en: "Reason for rejecting this deletion request (optional):", it: "Motivo del rifiuto della richiesta (facoltativo):" },
    "db.rejectDone": { en: "Deletion request rejected.", it: "Richiesta di cancellazione rifiutata." },
    "db.complete": { en: "Complete", it: "Completi" },
    "db.running": { en: "Running", it: "In corso" },
    "db.providersConfigured": { en: "Search providers configured", it: "Provider di ricerca configurati" },
    "db.toolsAvailable": { en: "OSINT tools available", it: "Tool OSINT disponibili" },
    "db.byokNote": { en: "Sources without a key stay gracefully disabled (BYOK). Configure them under <em>API keys</em>.", it: "Le fonti senza chiave restano disattivate con eleganza (BYOK). Configurale in <em>Chiavi API</em>." },
    "db.noWarnings": { en: "No active compliance alerts.", it: "Nessun avviso di compliance attivo." },
    "db.noCases": { en: "No cases. Go to Cases to create one.", it: "Nessun caso. Vai in Casi per crearne uno." },
    "db.open": { en: "open", it: "aperto" },
    "db.noJobs": { en: "No reports. Go to Search to start one.", it: "Nessun report. Vai in Ricerca per avviarne uno." },

    // app.js coda: detected-type badge (global search)
    "dt.prefix": { en: "type:", it: "tipo:" },
    "dt.url": { en: "url", it: "url" },
    "dt.username": { en: "username/handle", it: "username/handle" },
    "dt.email": { en: "email", it: "email" },
    "dt.phone": { en: "phone", it: "telefono" },
    "dt.btc": { en: "BTC", it: "BTC" },
    "dt.eth": { en: "ETH", it: "ETH" },
    "dt.hash": { en: "file hash", it: "file hash" },
    "dt.ip": { en: "IP", it: "IP" },
    "dt.domain": { en: "domain", it: "dominio" },
    "dt.nameCompany": { en: "name / company", it: "nome / azienda" },

    // app.js coda: entity profile
    "en.confidence": { en: "Confidence", it: "Confidenza" },
    "en.entitiesFindings": { en: "{n} entities · {f} findings", it: "{n} entità · {f} finding" },
    "en.tabUnavailable": { en: "Tab unavailable.", it: "Tab non disponibile." },
    "en.noEvidence": { en: "No evidence collected: profile based only on input.", it: "Nessuna evidenza raccolta: profilo basato solo sull'input." },
    "en.lowConfidence": { en: "Low average confidence: verify the sources before drawing conclusions.", it: "Confidenza media bassa: verifica le fonti prima di trarre conclusioni." },
    "en.homonyms": { en: "Possible homonyms: {n} similar identities NOT merged automatically.", it: "Possibili omonimi: {n} identità simili NON unite automaticamente." },
    "en.sourcesConsulted": { en: "Sources consulted", it: "Fonti consultate" },
    "en.noExternalSources": { en: "No external source: entered data only.", it: "Nessuna fonte esterna: solo dati inseriti." },
    "en.entitiesFound": { en: "Entities found", it: "Entità trovate" },
    "en.findings": { en: "Findings", it: "Finding" },
    "en.noEntitiesExtracted": { en: "No entity extracted.", it: "Nessuna entità estratta." },
    "en.noEntitiesInReport": { en: "No entity extracted in this report.", it: "Nessuna entità estratta in questo report." },
    "en.noDataCategory": { en: "No data for this category.", it: "Nessun dato per questa categoria." },
    "en.noFindingsReport": { en: "No finding in this report.", it: "Nessun finding in questo report." },
    "en.noTimestamps": { en: "No entity with an available timestamp.", it: "Nessuna entità con timestamp disponibile." },
    "en.openProfile": { en: "Open entity profile", it: "Apri profilo entità" },

    // app.js coda: table headers
    "th.type": { en: "Type", it: "Tipo" },
    "th.value": { en: "Value", it: "Valore" },
    "th.confidence": { en: "Confidence", it: "Confidenza" },
    "th.sources": { en: "Sources", it: "Fonti" },
    "th.source": { en: "Source", it: "Fonte" },
    "th.network": { en: "Network", it: "Rete" },
    "th.contact": { en: "Contact", it: "Contatto" },
    "th.visibility": { en: "Visibility", it: "Visibilità" },
    "th.geo": { en: "Geo", it: "Geo" },
    "th.address": { en: "Address", it: "Address" },
    "th.grade": { en: "Grade", it: "Grado" },
    "th.firstSeen": { en: "First seen", it: "Prima vista" },
    "th.lastSeen": { en: "Last seen", it: "Ultima vista" },

    // app.js coda: audit tab
    "au.intro": { en: "Report traceability. The signed audit chain (SHA-256 hash-chain) is kept server-side and exportable from the Privacy Center.", it: "Tracciabilità del report. La catena di audit firmata (hash-chain SHA-256) è mantenuta lato server ed esportabile dal Privacy Center." },
    "au.generated": { en: "Generated", it: "Generato" },
    "au.queriesRun": { en: "Queries run", it: "Query eseguite" },
    "au.modulesRun": { en: "Modules run", it: "Moduli eseguiti" },
    "au.agent": { en: "Agent", it: "Agente" },
    "au.status": { en: "Status", it: "Stato" },
    "au.summary": { en: "Summary", it: "Sintesi" },
    "au.verifiableQueries": { en: "Verifiable queries", it: "Query verificabili" },

    // app.js coda: suggested actions
    "sa.subdomains": { en: "Search subdomains", it: "Cerca sottodomini" },
    "sa.whois": { en: "WHOIS analysis", it: "Analisi WHOIS" },
    "sa.pivotUsername": { en: "Pivot to username", it: "Pivot su username" },
    "sa.checkBreach": { en: "Check breaches", it: "Verifica breach" },
    "sa.findEmails": { en: "Find associated emails", it: "Cerca email associate" },
    "sa.otherSocial": { en: "Search other social networks", it: "Ricerca su altri social" },
    "sa.ipReputation": { en: "IP reputation", it: "Reputazione IP" },
    "sa.geolocation": { en: "Geolocation", it: "Geolocalizzazione" },
    "sa.forensicReport": { en: "Generate forensic report", it: "Genera report forensico" },

    // app.js coda: privacy center
    "pv.noRequests": { en: "No privacy request recorded.", it: "Nessuna richiesta privacy registrata." },
    "pv.requestFallback": { en: "request", it: "richiesta" },
    "pv.logUnavailable": { en: "Log unavailable: ", it: "Log non disponibile: " },
    "pv.requesting": { en: "Request in progress…", it: "Richiesta in corso…" },
    "pv.exportStarted": { en: "Export started. You'll receive an email with the link.", it: "Esportazione avviata. Riceverai una email con il link." },
    "pv.eraseConfirm": { en: "Are you sure you want to request deletion of your account? This action is irreversible.", it: "Sei sicuro di voler richiedere la cancellazione del tuo account? Questa azione è irreversibile." },
    "pv.eraseRegistered": { en: "Deletion request recorded.", it: "Richiesta di cancellazione registrata." },
    "pv.sending": { en: "Sending request…", it: "Invio richiesta…" },
    "pv.dsarRegistered": { en: "DSAR recorded. Response within 30 days.", it: "DSAR registrata. Risposta entro 30 giorni." },

    // app.js coda: errors / cases
    "err.generic": { en: "Error: ", it: "Errore: " },
    "err.delete": { en: "Deletion error: ", it: "Errore cancellazione: " },
    "err.deleteCase": { en: "Case deletion error: ", it: "Errore cancellazione caso: " },
    "err.loading": { en: "Loading error: ", it: "Errore nel caricamento: " },
    "cs.delConfirm": { en: "Delete the case \"{name}\"?\n\nOK = also delete ALL the case's jobs (files + records).\nCancel now if you don't want to proceed.\n\n(The next step will ask for the reason.)", it: "Elimina il caso \"{name}\"?\n\nOK = elimina anche TUTTI i job del caso (file + record).\nAnnulla ora se non vuoi procedere.\n\n(Il prossimo passo chiederà la motivazione.)" },
    "cs.delOnlyCase": { en: "Delete ONLY the case, leaving the jobs as orphan records (for audit)?", it: "Vuoi eliminare SOLO il caso, lasciando i job come record orfani (per audit)?" },
    "cs.delReason": { en: "Reason (optional, max 500 chars) for the audit log:", it: "Motivo (opzionale, max 500 char) per l'audit log:" },
    "cs.noCases": { en: "No cases yet. Create the first one on the right: title + legal basis required.", it: "Nessun caso ancora. Crea il primo a destra: titolo + base giuridica obbligatoria." },
    "cs.delTitle": { en: "Delete case and its traces", it: "Elimina caso e le sue tracce" },
    "cs.basisLabel": { en: "basis", it: "base" },
    "cs.collabLabel": { en: "collab", it: "collab" },
    "cs.scopeEdit": { en: "Scope ({n}) · edit", it: "Scope ({n}) · modifica" },
    "cs.scopeEmpty": { en: "Empty scope · add", it: "Scope vuoto · aggiungi" },
    "cs.useForSearch": { en: "Use for the next search", it: "Usa per la prossima ricerca" },
    "cs.formats": { en: "Formats: <code>domain</code> · <code>*.domain</code> · <code>IP</code> · <code>CIDR</code> · <code>URL</code> · <code>@handle</code>.", it: "Formati: <code>dominio</code> · <code>*.dominio</code> · <code>IP</code> · <code>CIDR</code> · <code>URL</code> · <code>@handle</code>." },
    "cs.saveScope": { en: "Save scope", it: "Salva scope" },
    "cs.defaultCase": { en: "— Default case (auto) —", it: "— Caso default (auto) —" },
    "cs.created": { en: "Case created.", it: "Caso creato." },
    "cs.saving": { en: "Saving…", it: "Salvataggio…" },
    "cs.scopeUpdated": { en: "Scope updated: {n} entries.", it: "Scope aggiornato: {n} voci." },
    "cs.titleRequired": { en: "Title required.", it: "Titolo obbligatorio." },

    "ai.caseSettings.toggle": { en: "Enable AI enrichment for this case (opt-in, sends data to your chosen provider)", it: "Abilita arricchimento AI per questo caso (opt-in, invia dati al provider scelto)" },
    "ai.caseSettings.serverDisabled": {
      en: "AI features are turned off on this server (OSINT_AI_AGENTS_ENABLED is not set to 1). An administrator must enable it in the server's .env and configure a provider key under \"API Keys\" before this can work.",
      it: "Le funzioni IA sono disattivate su questo server (OSINT_AI_AGENTS_ENABLED non è impostata a 1). Un amministratore deve abilitarla nel file .env del server e configurare una chiave provider in \"Chiavi API\" prima che funzioni.",
    },
    "ai.narrative.button": { en: "Generate AI narrative", it: "Genera narrativa AI" },
    "ai.narrative.disclaimer": { en: "AI-generated — unverified. Verify every citation against the evidence table.", it: "Generato da AI — non verificato. Verifica ogni citazione contro la tabella evidenze." },
    "ai.narrative.providerPrompt": { en: "Provider (anthropic / openai / local):", it: "Provider (anthropic / openai / local):" },
    "ai.narrative.invalidProvider": { en: "Invalid provider. Use anthropic, openai or local.", it: "Provider non valido. Usa anthropic, openai o local." },
    "ai.narrative.confirmSend": { en: "This sends this case's findings to the {provider} provider you configured. Continue?", it: "Questo invia i finding di questo caso al provider {provider} che hai configurato. Continuare?" },
    "ai.narrative.failed": { en: "Narrative generation failed: {error}", it: "Generazione narrativa fallita: {error}" },
    "ai.narrative.truncatedNote": { en: "Note: {sent} of {total} findings sent (truncated for size).", it: "Nota: {sent} finding su {total} inviati (troncato per dimensione)." },

    "ai.entity.tab": { en: "AI suggestions", it: "Suggerimenti IA" },
    "ai.entity.intro": { en: "The AI compares similar entities and suggests possible matches. Nothing is merged automatically — you confirm or reject each suggestion.", it: "L'IA confronta entità simili e suggerisce possibili corrispondenze. Nulla viene unito automaticamente — confermi o rifiuti ogni suggerimento." },
    "ai.entity.generateBtn": { en: "Generate suggestions", it: "Genera suggerimenti" },
    "ai.entity.confirmSend": { en: "This sends candidate entity pairs from this case to the {provider} provider you configured. Continue?", it: "Questo invia le coppie di entità candidate di questo caso al provider {provider} che hai configurato. Continuare?" },
    "ai.entity.noCandidates": { en: "No ambiguous entity pairs found in this case.", it: "Nessuna coppia di entità ambigua trovata in questo caso." },
    "ai.entity.noSuggestions": { en: "The AI returned no valid suggestions.", it: "L'IA non ha restituito suggerimenti validi." },
    "ai.entity.confirm": { en: "Same entity", it: "Stessa entità" },
    "ai.entity.reject": { en: "Not the same", it: "Non la stessa" },
    "ai.entity.confirmedMsg": { en: "Marked as the same entity.", it: "Segnato come stessa entità." },
    "ai.entity.rejectedMsg": { en: "Marked as not the same.", it: "Segnato come non la stessa." },

    "ai.triage.button": { en: "AI priority", it: "Priorità AI" },
    "ai.triage.disclaimer": { en: "AI-generated advisory priority — no finding is filtered or hidden.", it: "Priorità consultiva generata da AI — nessun finding è filtrato o nascosto." },
    "ai.triage.confirmSend": { en: "This sends this job's findings to the {provider} provider you configured. Continue?", it: "Questo invia i finding di questo job al provider {provider} che hai configurato. Continuare?" },
    "ai.triage.noRankings": { en: "The AI returned no rankings.", it: "L'IA non ha restituito nessuna priorità." },
    "ai.triage.bucket.critical_now": { en: "Critical now", it: "Critico ora" },
    "ai.triage.bucket.high": { en: "High", it: "Alta" },
    "ai.triage.bucket.medium": { en: "Medium", it: "Media" },
    "ai.triage.bucket.low": { en: "Low", it: "Bassa" },
    "ai.triage.bucket.noise": { en: "Noise", it: "Rumore" },
    "ai.triage.showMore": { en: "Show {n} low-priority findings", it: "Mostra {n} finding a bassa priorità" },
    "ai.triage.fallbackRationale": { en: "(fallback: no AI assessment received)", it: "(fallback: nessuna valutazione AI ricevuta)" },
    "ai.triage.coverageNote": { en: "Note: {ai} of {total} findings ranked by AI, the rest use the deterministic fallback.", it: "Nota: {ai} finding su {total} valutati dall'AI, gli altri usano il fallback deterministico." },

    // -- report sealing (Ed25519 + RFC3161 opt-in) --
    "seal.badge": { en: "🔒 Sealed", it: "🔒 Sigillo" },
    "seal.disclaimer": {
      en: "Local Ed25519 signature, computed automatically when the report completes. The RFC3161 timestamp (if requested) is issued by a third party outside Argo — verify it with your own tools.",
      it: "Firma Ed25519 locale, calcolata automaticamente al completamento del report. Il timestamp RFC3161 (se richiesto) è emesso da una terza parte esterna a Argo — verificalo con i tuoi strumenti."
    },
    "seal.field.sealedAt": { en: "Sealed at", it: "Sigillato il" },
    "seal.field.fingerprint": { en: "Signing key fingerprint", it: "Fingerprint chiave di firma" },
    "seal.field.manifestHash": { en: "Manifest hash (SHA-256)", it: "Hash manifest (SHA-256)" },
    "seal.field.artifactCount": { en: "Artifacts covered", it: "Artifact coperti" },
    "seal.field.tsaHost": { en: "TSA", it: "TSA" },
    "seal.field.tsaGenTime": { en: "TSA timestamp", it: "Timestamp TSA" },
    "seal.field.tsaStatus": { en: "TSA status", it: "Stato TSA" },
    "seal.tsa.button": { en: "Request RFC3161 timestamp", it: "Richiedi timestamp RFC3161" },
    "seal.tsa.confirm": {
      en: "This sends only a SHA-256 digest (32 bytes) of the report manifest to the TSA configured by your operator — never case content. Continue?",
      it: "Questo invia solo un digest SHA-256 (32 byte) del manifest del report alla TSA configurata dal tuo operatore — mai il contenuto del caso. Continuare?"
    },
    "seal.tsa.failed": { en: "Timestamp request failed: {error}", it: "Richiesta di timestamp fallita: {error}" }
  };

  // ---- engine -----------------------------------------------------------
  function detect() {
    try {
      var saved = localStorage.getItem(STORE_KEY);
      if (saved && SUPPORTED.indexOf(saved) !== -1) return saved;
    } catch (e) { /* storage unavailable */ }
    var nav = (navigator.language || navigator.userLanguage || DEFAULT).slice(0, 2).toLowerCase();
    return nav === "it" ? "it" : DEFAULT;
  }

  var current = detect();
  var hadSaved = false;
  try { hadSaved = !!localStorage.getItem(STORE_KEY); } catch (e) {}

  function translate(key) {
    var entry = DICT[key];
    if (!entry) return null;
    return entry[current] != null ? entry[current] : (entry.en != null ? entry.en : null);
  }

  function t(key, params) {
    var s = translate(key);
    if (s == null) return key;
    if (params) {
      Object.keys(params).forEach(function (k) {
        s = s.split("{" + k + "}").join(params[k]);
      });
    }
    return s;
  }

  function apply(root) {
    root = root || document;
    var nodes = root.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var val = translate(el.getAttribute("data-i18n"));
      if (val == null) continue;
      if (el.hasAttribute("data-i18n-html")) el.innerHTML = val;
      else el.textContent = val;
    }
    var attrNodes = root.querySelectorAll("[data-i18n-attr]");
    for (var j = 0; j < attrNodes.length; j++) {
      var node = attrNodes[j];
      var spec = node.getAttribute("data-i18n-attr").split(";");
      for (var s = 0; s < spec.length; s++) {
        var pair = spec[s].split(":");
        if (pair.length !== 2) continue;
        var av = translate(pair[1].trim());
        if (av != null) node.setAttribute(pair[0].trim(), av);
      }
    }
    document.documentElement.lang = current;
    updateSwitchers();
  }

  function updateSwitchers() {
    var other = current === "it" ? "EN" : "IT";
    var switches = document.querySelectorAll(".langSwitch");
    for (var i = 0; i < switches.length; i++) {
      switches[i].textContent = other;
      switches[i].setAttribute("aria-label", t("lang.switch.aria"));
      switches[i].setAttribute("title", t("lang.switch.aria"));
    }
  }

  function set(lang) {
    if (SUPPORTED.indexOf(lang) === -1) return;
    current = lang;
    try { localStorage.setItem(STORE_KEY, lang); } catch (e) {}
    hadSaved = true;
    apply();
    document.dispatchEvent(new CustomEvent("i18n:changed", { detail: { lang: lang } }));
  }

  function toggle() { set(current === "it" ? "en" : "it"); }

  window.I18N = {
    t: t, apply: apply, set: set, toggle: toggle,
    get: function () { return current; },
    supported: SUPPORTED
  };

  // ---- first-run selector + switcher wiring -----------------------------
  function buildFirstRun() {
    if (hadSaved) return;
    var overlay = document.createElement("div");
    overlay.className = "langPickOverlay";
    overlay.innerHTML =
      '<div class="langPickCard" role="dialog" aria-modal="true" aria-label="Language">' +
      '<img src="/argo-logo.svg" alt="" class="langPickLogo">' +
      '<h2 data-i18n="lang.choose">' + t("lang.choose") + '</h2>' +
      '<div class="langPickBtns">' +
      '<button type="button" data-pick="en"><span>English</span><small>Default</small></button>' +
      '<button type="button" data-pick="it"><span>Italiano</span><small>&nbsp;</small></button>' +
      '</div>' +
      '<p class="langPickHint" data-i18n="lang.hint">' + t("lang.hint") + '</p>' +
      '</div>';
    // pre-highlight the detected language
    document.body.appendChild(overlay);
    overlay.querySelectorAll("button[data-pick]").forEach(function (b) {
      if (b.getAttribute("data-pick") === current) b.classList.add("is-detected");
      b.addEventListener("click", function () {
        set(b.getAttribute("data-pick"));
        overlay.classList.add("is-leaving");
        setTimeout(function () { overlay.remove(); }, 260);
      });
    });
  }

  function wireSwitchers() {
    document.addEventListener("click", function (ev) {
      var t2 = ev.target.closest ? ev.target.closest(".langSwitch") : null;
      if (t2) { ev.preventDefault(); toggle(); }
    });
  }

  function init() {
    apply();
    wireSwitchers();
    buildFirstRun();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
