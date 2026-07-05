#requires -version 5.1
<#
.SYNOPSIS
    Rollback atomico di Argo OSINT al backup creato dal deploy precedente.

.DESCRIPTION
    Ripristina /opt/argo-osint/osint_bot da un backup
    /opt/argo-osint/osint_bot.bak-YYYYMMDD-HHMMSS creato in automatico da
    deploy.ps1, quindi riavvia il servizio systemd 'argo-osint'.

    Operazione distruttiva sulla versione corrente -> richiede conferma
    esplicita (saltabile con -Force). L'azione lato VM e' atomica: l'`mv`
    sostituisce la directory solo se la `rm` ha avuto successo (`&&`).

    Comportamento di default: usa il backup PIU' RECENTE. Per sceglierne uno
    specifico, passa -BackupName (con o senza prefisso 'osint_bot.bak-').

    Nessuna credenziale o IP e' hardcoded.

.PARAMETER VMHost
    Hostname/IP della VM (alias: -Host). Obbligatorio salvo -List.

.PARAMETER List
    Elenca i backup disponibili sulla VM e termina (read-only).

.PARAMETER BackupName
    Nome del backup specifico da ripristinare (es. 'osint_bot.bak-20260629-153002'
    o solo '20260629-153002'). Se omesso, usa il piu' recente.

.PARAMETER DryRun
    Mostra cosa verrebbe eseguito senza modificare la VM.

.PARAMETER Force
    Salta la conferma interattiva (utile per automazioni).

.EXAMPLE
    .\rollback.ps1 -Host argo.example.com -List

.EXAMPLE
    .\rollback.ps1 -Host argo.example.com -DryRun

.EXAMPLE
    .\rollback.ps1 -Host argo.example.com

.EXAMPLE
    .\rollback.ps1 -Host argo.example.com -BackupName 20260629-153002 -Force
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "IP o hostname della VM Oracle")]
    [Alias('Host', 'H')]
    [string] $VMHost,

    [string] $User         = 'ubuntu',
    [string] $RemotePath   = '/opt/argo-osint',
    [string] $Service      = 'argo-osint',
    [string] $HealthUrl    = 'https://argo.example.com/api/dashboard',
    [string] $IdentityFile = '',
    [int]    $Port         = 22,
    [string] $BackupName   = '',
    [switch] $List,
    [switch] $DryRun,
    [switch] $Force
)

# Vedi nota in deploy.ps1: 'Continue' + check su $LASTEXITCODE.
$ErrorActionPreference = 'Continue'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "OK  $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "!   $m" -ForegroundColor Yellow }
function Write-Err($m)  { Write-Host "ERR $m" -ForegroundColor Red }

# --- SSH options (nessun segreto inline) ------------------------------------
$sshBase = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new')
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile)) { Write-Err "IdentityFile non trovato: $IdentityFile"; exit 1 }
    $sshBase += @('-i', $IdentityFile)
}
$sshArgs = $sshBase + @('-p', "$Port")
$remote  = "$User@$VMHost"

function Test-Endpoint([string]$url) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $code = & curl.exe -s -o NUL -w '%{http_code}' --max-time 15 $url 2>$null
        if ($code) { return [int]$code }
        return -1
    }
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode.value__ }
        return -1
    }
}

# ============================================================================
Write-Host ""
Write-Step "Argo OSINT rollback  <-  ${remote}:$RemotePath/"
if ($DryRun) { Write-Warn2 "MODALITA' DryRun: nessuna modifica verra' applicata alla VM." }

# --- test SSH ---------------------------------------------------------------
Write-Step "Test connessione SSH"
$probe = & ssh @sshArgs $remote 'echo argo-ssh-ok' 2>$null
if ($LASTEXITCODE -ne 0 -or "$probe" -notmatch 'argo-ssh-ok') {
    Write-Err "SSH non riuscito verso $remote"
    Write-Err "Controlla host/IP, chiave (-IdentityFile), porta (-Port) e firewall (TCP 22)."
    exit 1
}
Write-Ok "SSH raggiungibile."

# --- elenca backup ----------------------------------------------------------
Write-Step "Backup disponibili in $RemotePath"
# `ls -1dt` ordina per mtime desc; `--` separa opzioni da path/glob.
$lsCmd = "ls -1dt -- '$RemotePath'/osint_bot.bak-* 2>/dev/null || true"
$rawList = & ssh @sshArgs $remote $lsCmd 2>$null
if (-not $rawList) {
    Write-Err "Nessun backup trovato in $RemotePath (atteso: osint_bot.bak-*)."
    Write-Warn2 "I backup vengono creati automaticamente da deploy.ps1 prima di ogni deploy."
    exit 1
}
$backups = @($rawList -split "`r?`n" | Where-Object { $_ -match 'osint_bot\.bak-' })
$backupBasenames = @($backups | ForEach-Object { Split-Path -Leaf $_ })

$i = 0
foreach ($b in $backupBasenames) {
    $tag = if ($i -eq 0) { ' (piu recente)' } else { '' }
    Write-Host ("  [{0}] {1}{2}" -f $i, $b, $tag)
    $i++
}

if ($List) { Write-Host ""; Write-Ok "Solo elenco richiesto. Nessuna modifica eseguita."; exit 0 }

# --- selezione backup -------------------------------------------------------
if (-not $BackupName) {
    $selected = $backupBasenames[0]
    Write-Step "Backup selezionato (auto): $selected"
} else {
    # accetta sia 'osint_bot.bak-20260629-153002' sia '20260629-153002'
    $needle = if ($BackupName -like 'osint_bot.bak-*') { $BackupName } else { "osint_bot.bak-$BackupName" }
    $match = $backupBasenames | Where-Object { $_ -eq $needle }
    if (-not $match) {
        Write-Err "Backup '$BackupName' non trovato. Usa -List per vedere i nomi esatti."
        exit 1
    }
    $selected = $match
    Write-Step "Backup selezionato: $selected"
}

$selectedFull = "$RemotePath/$selected"
$targetFull   = "$RemotePath/osint_bot"

# Backup di sicurezza della VERSIONE CORRENTE prima del rollback,
# cosi' un rollback errato e' a sua volta annullabile.
$ts            = Get-Date -Format 'yyyyMMdd-HHmmss'
$rescueName    = "osint_bot.rollback-rescue-$ts"
$rescueFull    = "$RemotePath/$rescueName"

# --- DryRun: mostra cosa farebbe e stop -------------------------------------
if ($DryRun) {
    Write-Host ""
    Write-Ok "DryRun terminato. Comandi che verrebbero eseguiti SENZA -DryRun:"
    Write-Host "    mv '$targetFull' '$rescueFull'        (rescue della versione attuale)"
    Write-Host "    cp -a '$selectedFull' '$targetFull'   (ripristino backup, non lo consuma)"
    Write-Host "    sudo systemctl restart $Service"
    Write-Host "    sudo systemctl status $Service --no-pager"
    Write-Host "    curl $HealthUrl   (atteso 200/401/403)"
    exit 0
}

# --- conferma esplicita -----------------------------------------------------
if (-not $Force) {
    Write-Host ""
    Write-Warn2 "AZIONE DISTRUTTIVA: la versione corrente verra' sostituita da '$selected'."
    Write-Warn2 "La versione attuale viene salvata in '$rescueName' (annullabile)."
    $ans = Read-Host "Procedere? (digita 'yes' per confermare)"
    if ($ans -ne 'yes') { Write-Err "Annullato dall'utente."; exit 1 }
}

# --- ROLLBACK ATOMICO -------------------------------------------------------
# Logica:
#   1) sposta osint_bot/  -> osint_bot.rollback-rescue-<ts>   (rescue, NON cancella)
#   2) copia backup       -> osint_bot/                       (ripristina, NON consuma)
# Tutto in una sola riga con &&: se un passo fallisce, gli altri non partono.
Write-Step "Rollback in corso (atomico)"
$cmd = "set -e; mv '$targetFull' '$rescueFull' && cp -a '$selectedFull' '$targetFull' && echo ROLLBACK_OK"
$out = & ssh @sshArgs $remote $cmd 2>$null
if ($LASTEXITCODE -ne 0 -or "$out" -notmatch 'ROLLBACK_OK') {
    Write-Err "Rollback fallito. La directory osint_bot potrebbe essere ora '$rescueName' (rescue)."
    Write-Warn2 "Recupero manuale (porta indietro la versione di prima):"
    Write-Host  "    ssh $remote `"if [ -d '$rescueFull' ] && [ ! -d '$targetFull' ]; then mv '$rescueFull' '$targetFull' && sudo systemctl restart $Service; fi`""
    exit 1
}
Write-Ok "Filesystem ripristinato. Backup originale '$selected' conservato."
Write-Ok "Versione precedente al rollback salvata in: $rescueName"

# --- restart + status -------------------------------------------------------
Write-Step "Riavvio servizio: sudo systemctl restart $Service"
& ssh @sshArgs $remote "sudo systemctl restart $Service" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Restart fallito. Per annullare il rollback:"
    Write-Host "    ssh $remote `"rm -rf '$targetFull' && mv '$rescueFull' '$targetFull' && sudo systemctl restart $Service`""
    exit 1
}
Write-Ok "Servizio riavviato."

Write-Step "Stato servizio"
& ssh @sshArgs $remote "sudo systemctl status $Service --no-pager" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Warn2 "systemctl status ha restituito exit $LASTEXITCODE." }

# --- health check -----------------------------------------------------------
Write-Step "Health check: $HealthUrl"
$code = Test-Endpoint $HealthUrl
if ($code -eq 200 -or $code -eq 401 -or $code -eq 403) {
    Write-Ok "Backend attivo (HTTP $code)."
} elseif ($code -eq 404) {
    Write-Warn2 "HTTP 404: stai servendo una versione che non espone /api/dashboard (probabilmente OK se hai voluto rollback alla pre-Fase 1)."
} else {
    Write-Warn2 "HTTP ${code}: verifica 'sudo journalctl -u $Service -n 80' lato VM."
}

Write-Host ""
Write-Ok "ROLLBACK COMPLETATO."
Write-Warn2 "Sul browser fai HARD REFRESH (Ctrl+F5): app.js e app.css sono cacheati."
Write-Host "Per ANNULLARE questo rollback (tornare alla versione che avevi prima del rollback):" -ForegroundColor DarkGray
Write-Host "    ssh $remote `"rm -rf '$targetFull' && mv '$rescueFull' '$targetFull' && sudo systemctl restart $Service`"" -ForegroundColor DarkGray
