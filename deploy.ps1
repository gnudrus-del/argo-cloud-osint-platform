#requires -version 5.1
<#
.SYNOPSIS
    Deploy delle modifiche locali di Argo OSINT sulla VM Oracle Cloud.

.DESCRIPTION
    Copia SOLO la directory osint_bot/ in /opt/argo-osint/osint_bot/ sulla VM,
    con backup remoto preventivo, riavvio del servizio systemd e health check.

    Allineato a docs/DEPLOY.md:
      - /opt/argo-osint e' di proprieta' dell'utente 'ubuntu' (vedi
        docs/DEPLOY.md, sez. "Deploy su VM": `sudo chown ubuntu:ubuntu
        argo-osint`), quindi le copie NON usano sudo; solo `systemctl` usa
        sudo.
      - servizio systemd: argo-osint (python -m osint_bot.web --port 7655).

    Nessuna credenziale, chiave privata o IP e' hardcoded: l'host e la chiave
    si passano come parametri.

.PARAMETER VMHost
    IP o hostname della VM Oracle. Alias: -Host. (Obbligatorio.)

.PARAMETER DryRun
    Mostra cosa verrebbe copiato (rsync -n) SENZA modificare la VM:
    niente backup, niente copia reale, niente restart.

.EXAMPLE
    .\deploy.ps1 -Host 203.0.113.10

.EXAMPLE
    .\deploy.ps1 -Host your-argo-host.example.com -DryRun

.EXAMPLE
    .\deploy.ps1 -Host 203.0.113.10 -IdentityFile $HOME\.ssh\id_ed25519
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "IP o hostname della VM Oracle")]
    [Alias('Host', 'H')]
    [string] $VMHost,

    [string] $User         = 'ubuntu',
    [string] $RemotePath   = '/opt/argo-osint',
    [string] $Service      = 'argo-osint',
    # HealthUrl derivato di default dall'host passato (evita hardcode del dominio).
    [string] $HealthUrl    = '',
    [string] $LocalPath    = '',
    [string] $IdentityFile = '',
    [int]    $Port         = 22,
    [switch] $DryRun
)

# 'Continue' (non 'Stop'): i comandi nativi (ssh/scp/rsync/curl) scrivono spesso
# su stderr anche con successo (es. avviso accept-new di ssh). Sotto 'Stop' quei
# messaggi verrebbero promossi a errore terminante. Usiamo check espliciti su
# $LASTEXITCODE + throw, e -ErrorAction Stop sui cmdlet critici.
$ErrorActionPreference = 'Continue'

# HealthUrl fallback: derivato dall'host passato se non specificato.
if (-not $HealthUrl) { $HealthUrl = "https://$VMHost/api/dashboard" }

# $PSScriptRoot puo' essere vuoto in alcuni contesti di invocazione (es. tramite
# wrapper). Derivo la directory dello script dal $MyInvocation che e' sempre
# popolato quando si esegue tramite `-File ...`.
if (-not $LocalPath) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    if ($scriptPath) { $LocalPath = Split-Path -Parent $scriptPath }
    if (-not $LocalPath) { $LocalPath = (Get-Location).Path }
}

# ---- helper di output -------------------------------------------------------
function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "OK  $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "!   $m" -ForegroundColor Yellow }
function Write-Err($m)  { Write-Host "ERR $m" -ForegroundColor Red }

# ---- costruzione opzioni SSH/SCP (nessun segreto inline) --------------------
$sshBase = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new')
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile)) { Write-Err "IdentityFile non trovato: $IdentityFile"; exit 1 }
    $sshBase += @('-i', $IdentityFile)
}
$sshArgs = $sshBase + @('-p', "$Port")   # ssh usa -p (minuscola)
$scpArgs = $sshBase + @('-P', "$Port")   # scp usa -P (maiuscola)
$remote  = "$User@$VMHost"

# Stringa -e per rsync (ssh + eventuali opzioni)
$rshString = ((@('ssh') + $sshBase + @('-p', "$Port")) -join ' ')

# ---- health check tollerante (200/401/403 = backend attivo) -----------------
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
Write-Step "Argo OSINT deploy  ->  ${remote}:$RemotePath/osint_bot/"
if ($DryRun) { Write-Warn2 "MODALITA' DryRun: nessuna modifica verra' applicata alla VM." }

# --- 2) verifica directory locale -------------------------------------------
Write-Step "Verifica sorgente locale"
$srcPkg = Join-Path $LocalPath 'osint_bot'
if (-not (Test-Path -LiteralPath $srcPkg -PathType Container)) {
    Write-Err "Directory non trovata: $srcPkg"
    Write-Err "Esegui lo script dalla cartella del progetto, oppure passa -LocalPath <percorso>."
    exit 1
}
Write-Ok "Trovato: $srcPkg"

# --- 3) verifica connessione SSH (read-only, ok anche in DryRun) ------------
Write-Step "Test connessione SSH"
$probe = & ssh @sshArgs $remote 'echo argo-ssh-ok' 2>$null
if ($LASTEXITCODE -ne 0 -or "$probe" -notmatch 'argo-ssh-ok') {
    Write-Err "SSH non riuscito verso $remote"
    Write-Err "Controlla host/IP, chiave (-IdentityFile), porta (-Port) e firewall (TCP 22)."
    Write-Err ("Dettaglio: " + ("$probe").Trim())
    exit 1
}
Write-Ok "SSH raggiungibile."

$ts          = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup      = "$RemotePath/osint_bot.bak-$ts"
$rollbackCmd = "ssh $remote `"rm -rf $RemotePath/osint_bot && mv $backup $RemotePath/osint_bot && sudo systemctl restart $Service`""
$backupMade  = $false

# Liste di esclusione (coerenti per rsync e per lo staging scp)
$excludeDirs  = @('.venv', '__pycache__', 'web_jobs', 'tests', '.pytest_cache')
$rsyncExclude = @('--exclude=.venv', '--exclude=__pycache__', '--exclude=web_jobs',
                  '--exclude=tests', '--exclude=.pytest_cache', '--exclude=*.pyc')

try {
    # --- 4) backup remoto (saltato in DryRun) -------------------------------
    if (-not $DryRun) {
        Write-Step "Backup remoto -> $backup"
        $bk = & ssh @sshArgs $remote "if [ -d '$RemotePath/osint_bot' ]; then cp -a '$RemotePath/osint_bot' '$backup' && echo BACKUP_OK; else echo NO_DIR; fi" 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Backup remoto fallito: $bk" }
        if ("$bk" -match 'BACKUP_OK') { $backupMade = $true; Write-Ok "Backup creato." }
        else { Write-Warn2 "Nessuna osint_bot/ remota preesistente: backup non necessario." }
    }

    # --- 5/6/7/8) copia: rsync se disponibile, altrimenti scp ---------------
    $rsync = Get-Command rsync -ErrorAction SilentlyContinue
    if ($rsync) {
        Write-Step ("Copia con rsync" + ($(if ($DryRun) { " (dry-run)" } else { "" })))
        # NB: uso percorso RELATIVO './osint_bot/' (dopo Push-Location) per
        # evitare che rsync interpreti 'C:' come host remoto.
        Push-Location $LocalPath
        try {
            $flags = if ($DryRun) { @('-azn', '--itemize-changes') } else { @('-az', '--delete') }
            $rsyncArgs = $flags + $rsyncExclude + @('-e', $rshString, './osint_bot/', "${remote}:$RemotePath/osint_bot/")
            & rsync @rsyncArgs
            if ($LASTEXITCODE -ne 0) { throw "rsync fallito (exit $LASTEXITCODE)." }
        } finally { Pop-Location }
        Write-Ok ($(if ($DryRun) { "Anteprima rsync completata." } else { "Copia rsync completata." }))
    }
    else {
        Write-Warn2 "rsync non trovato: uso fallback scp (senza --delete: i file rimossi NON vengono cancellati)."
        # Staging con esclusioni (scp non supporta --exclude).
        $staging  = Join-Path ([System.IO.Path]::GetTempPath()) "argo-deploy-$ts"
        $stagePkg = Join-Path $staging 'osint_bot'
        New-Item -ItemType Directory -Force -Path $staging -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $srcPkg -Destination $stagePkg -Recurse -Force -ErrorAction Stop
        Get-ChildItem -LiteralPath $stagePkg -Recurse -Force -File -Filter '*.pyc' |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $stagePkg -Recurse -Force -Directory |
            Where-Object { $excludeDirs -contains $_.Name } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        if ($DryRun) {
            Write-Warn2 "[DryRun] scp copierebbe (relativo a osint_bot/):"
            Get-ChildItem -LiteralPath $stagePkg -Recurse -File |
                ForEach-Object { "    " + $_.FullName.Substring($stagePkg.Length).TrimStart('\') }
        } else {
            Write-Step "Copia con scp"
            Push-Location $staging
            try {
                & scp @scpArgs -r 'osint_bot' "${remote}:$RemotePath/"
                if ($LASTEXITCODE -ne 0) { throw "scp fallito (exit $LASTEXITCODE)." }
            } finally { Pop-Location }
            Write-Ok "Copia scp completata."
        }
        Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    }

    # --- DryRun: stop qui, niente modifiche sulla VM ------------------------
    if ($DryRun) {
        Write-Host ""
        Write-Ok "DryRun terminato. Comandi che verrebbero eseguiti SENZA -DryRun:"
        Write-Host "    cp -a $RemotePath/osint_bot $backup   (backup)"
        Write-Host "    sudo systemctl restart $Service"
        Write-Host "    sudo systemctl status $Service --no-pager"
        Write-Host "    curl $HealthUrl   (atteso 200/401)"
        exit 0
    }

    # --- 9) restart servizio ------------------------------------------------
    Write-Step "Riavvio servizio: sudo systemctl restart $Service"
    & ssh @sshArgs $remote "sudo systemctl restart $Service" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Restart servizio fallito (sudo/permessi?)." }
    Write-Ok "Servizio riavviato."

    # --- 10) status ---------------------------------------------------------
    Write-Step "Stato servizio"
    & ssh @sshArgs $remote "sudo systemctl status $Service --no-pager" 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Warn2 "systemctl status ha restituito exit $LASTEXITCODE (servizio non attivo?)." }

    # --- 11) health check ---------------------------------------------------
    Write-Step "Health check: $HealthUrl"
    $code = Test-Endpoint $HealthUrl
    if ($code -eq 200 -or $code -eq 401 -or $code -eq 403) {
        Write-Ok "Backend attivo (HTTP $code; 401/403 = rotta presente, auth richiesta)."
    } else {
        throw "Health check fallito (HTTP $code). Il sito potrebbe essere down."
    }

    Write-Host ""
    Write-Ok "DEPLOY COMPLETATO."
    Write-Warn2 "Sul browser fai HARD REFRESH (Ctrl+F5): app.js e app.css sono cacheati."
    if ($backupMade) { Write-Host "Backup disponibile su: $backup" -ForegroundColor DarkGray }
}
catch {
    Write-Host ""
    Write-Err $_.Exception.Message
    if ($backupMade) {
        Write-Warn2 "ROLLBACK (ripristina la versione precedente):"
        Write-Host "    $rollbackCmd" -ForegroundColor Yellow
    } else {
        Write-Warn2 "Nessun backup creato: nessun rollback automatico necessario."
    }
    exit 1
}
