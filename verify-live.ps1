#requires -version 5.1
<#
.SYNOPSIS
    Verifica post-deploy: il sito Argo live serve la versione NUOVA del codice?

.DESCRIPTION
    Esegue i controlli read-only del runbook (sezione 6/9):
      A. HTTP /api/dashboard: 401/403/200 = backend nuovo attivo;
         404 = backend vecchio (la rotta non esiste).
      B. /app.js include i marker della build corrente (renderAuditTab,
         "/api/dashboard"); se mancano, il server espone ancora la build vecchia.
      C. /app.css include il marker Fase 1 ("Dashboard + ricerca globale").
      D. /index.html include #panel-dashboard.

    Non richiede credenziali ne' chiavi SSH: solo HTTP(S) verso l'host pubblico.
    Nessun IP/segreto e' hardcoded.

.PARAMETER VMHost
    Hostname pubblico del sito (default: argo-cloud.duckdns.org).
    Alias: -Host.

.PARAMETER Scheme
    https (default) o http.

.EXAMPLE
    .\verify-live.ps1
    .\verify-live.ps1 -Host argo-cloud.duckdns.org
#>
[CmdletBinding()]
param(
    [Alias('Host', 'H')]
    [string] $VMHost = 'argo-cloud.duckdns.org',
    [ValidateSet('https', 'http')]
    [string] $Scheme = 'https'
)

$ErrorActionPreference = 'Continue'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "OK  $m" -ForegroundColor Green }
function Write-Fail($m) { Write-Host "ERR $m" -ForegroundColor Red }
function Write-Warn2($m){ Write-Host "!   $m" -ForegroundColor Yellow }

# --- HTTP helpers (curl.exe se disponibile, altrimenti Invoke-WebRequest) ---
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue

function Get-StatusCode([string]$url) {
    if ($curl) {
        $code = & curl.exe -s -o NUL -w '%{http_code}' --max-time 15 $url 2>$null
        if ($code) { return [int]$code } else { return -1 }
    }
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode.value__ }
        return -1
    }
}

function Get-Body([string]$url) {
    if ($curl) {
        return (& curl.exe -s --max-time 30 $url 2>$null) -join "`n"
    }
    try {
        return (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30).Content
    } catch { return "" }
}

$base = "${Scheme}://${VMHost}"
Write-Step "Verifica live: $base"

$failures = 0
$results  = @()

# --- A) /api/dashboard ------------------------------------------------------
Write-Step "A. /api/dashboard"
$code = Get-StatusCode "$base/api/dashboard"
switch ($code) {
    {$_ -in 200,401,403} {
        Write-Ok "HTTP $code -> backend NUOVO attivo (rotta presente, auth funzionante)."
        $results += @{name='api/dashboard'; ok=$true; detail="HTTP $code"}
    }
    404 {
        Write-Fail "HTTP 404 -> backend VECCHIO: /api/dashboard non esiste ancora online."
        $failures++; $results += @{name='api/dashboard'; ok=$false; detail='HTTP 404 (vecchio)'}
    }
    default {
        Write-Fail "HTTP $code -> stato inatteso. Controlla 'systemctl status argo-osint'."
        $failures++; $results += @{name='api/dashboard'; ok=$false; detail="HTTP $code"}
    }
}

# --- B) /app.js: marker della build corrente --------------------------------
Write-Step "B. /app.js (marker build corrente)"
$js = Get-Body "$base/app.js"
if (-not $js) {
    Write-Fail "Non sono riuscito a scaricare /app.js."
    $failures++; $results += @{name='app.js'; ok=$false; detail='download fallito'}
} else {
    $markers = @{
        'renderAuditTab'        = ($js -match 'function\s+renderAuditTab')
        '/api/dashboard'        = ($js -match '/api/dashboard')
        'evidenceHostLabel'     = ($js -match 'function\s+evidenceHostLabel')
    }
    $miss = $markers.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key }
    if (-not $miss) {
        Write-Ok ("Tutti i marker presenti: " + ($markers.Keys -join ', '))
        $results += @{name='app.js'; ok=$true; detail='marker NUOVI presenti'}
    } else {
        Write-Fail ("Marker MANCANTI in /app.js: " + ($miss -join ', '))
        Write-Warn2 "Il server espone ancora il vecchio app.js (oppure non hai rideployato gli static)."
        $failures++; $results += @{name='app.js'; ok=$false; detail=('mancanti: ' + ($miss -join ','))}
    }
}

# --- C) /app.css: marker Fase 1 --------------------------------------------
Write-Step "C. /app.css (marker Fase 1)"
$css = Get-Body "$base/app.css"
if (-not $css) {
    Write-Fail "Non sono riuscito a scaricare /app.css."
    $failures++; $results += @{name='app.css'; ok=$false; detail='download fallito'}
} elseif ($css -match 'Dashboard \+ ricerca globale') {
    Write-Ok "Marker Fase 1 presente in /app.css."
    $results += @{name='app.css'; ok=$true; detail='marker NUOVO presente'}
} else {
    Write-Fail "Marker Fase 1 mancante in /app.css -> probabile vecchio CSS in cache."
    $failures++; $results += @{name='app.css'; ok=$false; detail='marker assente'}
}

# --- D) /: panel-dashboard --------------------------------------------------
Write-Step "D. / (panel-dashboard)"
$idx = Get-Body "$base/"
if (-not $idx) {
    Write-Fail "Non sono riuscito a scaricare /."
    $failures++; $results += @{name='index.html'; ok=$false; detail='download fallito'}
} elseif ($idx -match 'id="panel-dashboard"') {
    Write-Ok "id=panel-dashboard presente in /."
    $results += @{name='index.html'; ok=$true; detail='panel-dashboard presente'}
} else {
    Write-Fail "id=panel-dashboard mancante in / -> vecchio index.html."
    $failures++; $results += @{name='index.html'; ok=$false; detail='panel-dashboard assente'}
}

# ============================================================================
Write-Host ""
Write-Step "Riepilogo"
$results | ForEach-Object {
    $mark = if ($_.ok) { 'OK ' } else { 'ERR' }
    $color = if ($_.ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-15} -> {1} ({2})" -f $_.name, $mark, $_.detail) -ForegroundColor $color
}
Write-Host ""
if ($failures -eq 0) {
    Write-Host "VERSIONE NUOVA ONLINE  - tutti i controlli sono OK." -ForegroundColor Green
    Write-Warn2 "Se il browser mostra ancora vecchio: Ctrl+F5 / DevTools 'Disable cache'."
    exit 0
} else {
    Write-Host "VERSIONE INCOMPLETA / VECCHIA - $failures controlli falliti." -ForegroundColor Red
    Write-Warn2 "Probabili cause: deploy non eseguito, restart mancato, rollback attivo, file static non copiati."
    Write-Warn2 "Suggerimenti: rilancia '.\deploy.ps1 -Host $VMHost -DryRun' e confronta l'elenco rsync."
    exit 1
}
