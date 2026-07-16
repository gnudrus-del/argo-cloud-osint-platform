> 🇬🇧 [Read in English](../SECURITY.md)

# Security Policy

## Modello di minaccia

Argo OSINT è una piattaforma **investigativa**: gestisce dati personali di
terzi (target dell'indagine) e credenziali dell'analista (API key, cookie di
sessione dei tool). Le due superfici di attacco più rilevanti sono:

1. **Compromissione delle credenziali dell'analista** memorizzate nel DB
   (chiavi API, cookie sessione tool). Un attaccante che ottiene una copia del
   DB deve trovare le credenziali cifrate o inutilizzabili.
2. **Esfiltrazione o alterazione della catena audit** (integrità forense):
   modificare/inserire eventi audit invaliderebbe il valore probatorio dei
   report.

## Baseline hardening implementato

- **Auth**: sessioni server-side con cookie `HttpOnly + SameSite=Strict`.
  `Secure` cookie via `OSINT_SECURE_COOKIE=1`. HSTS via `OSINT_HSTS=1`.
- **CSRF**: token per-sessione richiesto su tutte le POST/DELETE.
- **CSP**: `default-src 'self'`, `frame-ancestors 'none'`, no inline script.
- **Header extra**: `X-Frame-Options DENY`, `X-Content-Type-Options nosniff`,
  `Referrer-Policy no-referrer`, `Permissions-Policy` restrittiva,
  `Cross-Origin-Opener-Policy same-origin`.
- **Password admin**: PBKDF2-SHA256 con salt 16 byte e 200k iterazioni;
  confronto in tempo costante (`hmac.compare_digest`); nessuna password mai in
  codice o repo.
- **Rate limiting** in-process (`InMemoryRateLimiter`) + delay costante sui
  fallimenti admin per prevenire enumerazione.
- **Audit chain SHA-256** (hash del precedente evento concatenato).
- **Offuscamento tool/connettori** per utenti non-admin (Fase 22): la lista
  degli strumenti di ricerca è visibile solo dopo sblocco con password admin.

## Cosa NON viene fatto (limiti dichiarati)

- Le API key sono cifrate a riposo con envelope encryption applicativa
  (`osint_bot/secrets_crypto.py`: AES-256-GCM, master key dell'istanza
  separata dal DB — env var, file credential systemd, o file locale
  autogenerato, mai una riga di tabella). Protegge da una fuga del solo
  database (file SQLite rubato, dump Postgres); non protegge da una
  compromissione della macchina che ospita la master key — in quel caso
  restano rilevanti chmod 600 sul file chiave, filesystem-level encryption
  della VM, controllo accessi sistema. Rotazione via `argo-rotate-master-key`.
- Le sessioni tool esterni (GHunt, Toutatis) sono memorizzate in env/dir sulla
  VM: proteggerle è responsabilità dell'analista.
- Argo NON è un WAF: dietro un reverse proxy pubblico usare Caddy/nginx con
  TLS moderno e fail2ban (unit incluse in `deploy_artifacts/`).

## Modello di minaccia completo e materiali per un audit esterno

Questo file è un riassunto. Il modello di minaccia completo (cosa è in
scope, cosa è dichiaratamente fuori scope, limiti noti) è in
[`docs/THREAT_MODEL.md`](THREAT_MODEL.md). Chi sta valutando di
commissionare una revisione di sicurezza esterna a pagamento trova materiali
preparatori (scope suggerito, dipendenze, gate CI già attivi) in
[`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md) — **non** un'attestazione
che Argo sia già stato controllato: non lo è stato, ad oggi.

## Segnalazione vulnerabilità

- **Non aprire una issue pubblica.**
- Usa il flusso GitHub **Security Advisories**: `Security → Report a vulnerability`.
- Nel report includi: passaggi di riproduzione, versione (git SHA), impatto
  potenziale, e — se hai una POC — un esempio minimo.

Rispondiamo entro **7 giorni lavorativi** e concordiamo una disclosure timeline
coordinata (di norma 90 giorni). Contribuenti che segnalano vulnerabilità
verificate sono citati nel CHANGELOG (se lo desiderano) e nei rilasci fix.

## Uso responsabile

Argo è distribuito per: (1) indagini **autorizzate**, (2) audit di sicurezza
su asset propri, (3) ricerca giornalistica documentata, (4) training/CTF.
**Non è consentito** usarlo per stalking, doxxing, spionaggio non autorizzato,
o violazione dei ToS delle piattaforme target. Il layer Rules of Engagement
(RoE) + scope autorizzato è pensato esattamente per tracciare cosa è stato
autorizzato caso per caso.
