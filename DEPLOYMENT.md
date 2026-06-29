# Deployment

Questa piattaforma ha due parti:

- `osint_bot.web`: backend + UI locale, esegue agenti, job e tool installati sulla macchina.
- Cloudflare Tunnel o un VPS: rende il backend raggiungibile da internet.

Cloudflare Pages e Workers sono ottimi per frontend statici e funzioni edge, ma non sono adatti a eseguire binari locali come `nmap`, `sherlock`, `maigret`, `holehe`, `phoneinfoga`, `exiftool` o `ffprobe`. Per questi serve una macchina runner: PC locale, server, VM o container.

## Avvio locale

```powershell
cd C:\Users\gnudr\Documents\Codex\2026-06-24\cffe\outputs\osint-bot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

$env:OSINT_WEB_TOKEN="scegli-un-token-lungo"
$env:OSINT_SIGNUPS_ENABLED="1"
python -m osint_bot.web --host 127.0.0.1 --port 8000
```

Apri:

```text
http://127.0.0.1:8000
```

La UI usa signup/login con password hashata e cookie `HttpOnly`. `OSINT_WEB_TOKEN` resta utile per automazioni API.

## Avvio con Docker

```powershell
cd C:\Users\gnudr\Documents\Codex\2026-06-24\cffe\outputs\osint-bot
$env:OSINT_WEB_TOKEN="scegli-un-token-lungo"
docker compose up --build
```

Il container espone `http://127.0.0.1:8000`, salva job/report in volumi Docker e include la dipendenza PDF (`reportlab`). Per HTTPS pubblico usa comunque reverse proxy, Cloudflare Tunnel, VPN o Cloudflare Access.

## Cloudflare Tunnel

Opzione consigliata: lascia il backend sulla tua macchina o VPS e pubblicalo con Cloudflare Tunnel verso:

```text
http://localhost:8000
```

### Tunnel rapido

Per usare subito la piattaforma da telefono senza aprire porte sul router, avvia:

```powershell
cd C:\Users\gnudr\Documents\Codex\2026-06-24\cffe\outputs\osint-bot
powershell -ExecutionPolicy Bypass -File .\scripts\start-online-cloudflare.ps1
```

Lo script:

- avvia il backend solo su `127.0.0.1`;
- disattiva nuove iscrizioni con `OSINT_SIGNUPS_ENABLED=0`;
- abilita cookie sicuri e HSTS per l'uso via HTTPS;
- avvia `cloudflared tunnel --url`;
- scrive il link pubblico nel log `web_jobs\cloudflared-8769.err.log`.

Il tunnel rapido usa un dominio `trycloudflare.com`: e comodo per prove immediate, ma l'URL cambia quando riavvii il tunnel e non ha garanzia di uptime.

### Tunnel stabile

Nel dashboard Cloudflare Zero Trust:

1. Crea un tunnel.
2. Installa `cloudflared` sulla macchina runner.
3. Aggiungi un Public Hostname, ad esempio `osint.tuodominio.it`.
4. Imposta il Service URL su `http://localhost:8000`.
5. Proteggi l'hostname con Cloudflare Access, SSO, email allowlist o mTLS.

## Esempio config ingress

Per un tunnel gestito via config file:

```yaml
tunnel: <TUNNEL_ID>
credentials-file: C:\Users\<utente>\.cloudflared\<TUNNEL_ID>.json

ingress:
  - hostname: osint.tuodominio.it
    service: http://localhost:8000
  - service: http_status:404
```

## Tool esterni

Configura i comandi tramite variabili d'ambiente se non sono nel `PATH`:

```powershell
$env:SHERLOCK_CMD="C:\tools\sherlock\sherlock.exe"
$env:MAIGRET_CMD="C:\tools\maigret\maigret.exe"
$env:HOLEHE_CMD="C:\tools\holehe\holehe.exe"
$env:NMAP_CMD="C:\Program Files (x86)\Nmap\nmap.exe"
$env:EXIFTOOL_CMD="C:\tools\exiftool.exe"
$env:FFPROBE_CMD="C:\ffmpeg\bin\ffprobe.exe"
$env:PHONEINFOGA_CMD="C:\tools\phoneinfoga.exe"
$env:SOCIAL_ANALYZER_CMD="C:\tools\social-analyzer.exe"
$env:H8MAIL_CMD="C:\tools\h8mail.exe"
$env:GHUNT_CMD="C:\tools\ghunt.exe"
$env:TOUTATIS_CMD="C:\tools\toutatis.exe"
$env:SINGLEFILE_CMD="C:\tools\single-file.cmd"
$env:SHODAN_CMD="C:\tools\shodan.exe"
$env:CENSYS_CMD="C:\tools\censys.exe"
```

Per controllare lo stato dei tool locali:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-tools.ps1 -CheckOnly
```

Per le ricerche web ampie non viene usato un solo browser come predefinito. La modalita `all` usa tutte le API configurate tra Bing, Brave e Serper, genera dork verificabili per Google/Bing/DuckDuckGo/Yandex e aggiunge link servizio per Shodan, Censys, HIBP, Hunter, IntelX, Epieos e Wayback quando pertinenti.

Per configurare le chiavi API in modo guidato:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-api-keys.ps1
```

Se vuoi configurare solo Bing:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-bing-key.ps1
```

Poi riavvia il backend o il tunnel online. Gli username usano Sherlock/Maigret/Social Analyzer/Toutatis/Osintgram per profili pubblici candidati quando autorizzati; email e telefoni di registrazione dei social non sono dati pubblici e non vengono recuperati.

I repository GitHub curati sono descritti in `config/tool_catalog.json`. Per clonarli nella piattaforma:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-repos.ps1 -CloneOnly
```

Gli agenti scelgono gli strumenti automaticamente; l'utente non deve selezionare repository o comandi. Se un comando manca, il report segnala lo strumento non disponibile invece di fallire.

SpiderFoot, Recon-ng, IntelOwl e Aleph sono piattaforme/framework esterni: il catalogo li rende selezionabili dal planner, ma per l'esecuzione piena servono setup e credenziali secondo la documentazione ufficiale. In assenza di setup, il report li registra come `manual_setup` invece di inventare risultati.

I dork e i link verso servizi esterni sono piste di verifica. Non vengono trattati come fatti osservati finche non apri le fonti e confermi manualmente le evidenze importanti.

## Sicurezza operativa

- Esegui il backend dietro Cloudflare Access o VPN.
- Usa un token lungo in `OSINT_WEB_TOKEN`.
- Non esporre il backend direttamente senza autenticazione.
- Esegui i tool in un utente dedicato, senza privilegi admin.
- Conserva i report in storage cifrato se contengono identificatori personali.
- Usa `--allow-network-scan` e `--allow-darkweb` solo per casi autorizzati.
- Dopo il primo setup pubblico valuta `OSINT_SIGNUPS_ENABLED=0`.
- Su HTTPS imposta `OSINT_SECURE_COOKIE=1` e `OSINT_HSTS=1`.
- Lascia `OSINT_MAX_UPLOAD_BYTES` basso se non devi analizzare video grandi.
- Usa Cloudflare WAF/rate limiting e Access con MFA.
- Non salvare API key o password nei report.

## Modello gratuito e upgrade

Il backend salva gli utenti con piano `free`. Il campo `plan` e gia nel file utenti e nella UI; puoi aggiungere in seguito:

- quote per numero di job/report;
- piano `pro`;
- integrazione pagamenti;
- tenant separati per team;
- log di audit per accessi e download report.
