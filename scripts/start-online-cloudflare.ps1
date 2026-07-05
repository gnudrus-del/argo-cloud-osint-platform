param(
    [int]$Port = 8769,
    [string]$HostName = "127.0.0.1",
    [string]$PythonPath = "",
    [string]$CloudflaredPath = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$JobDir = Join-Path $ProjectRoot "web_jobs"
$ToolDir = Join-Path $ProjectRoot "tools"

if (-not (Test-Path $JobDir)) {
    New-Item -ItemType Directory -Path $JobDir | Out-Null
}

if (-not $CloudflaredPath) {
    $CloudflaredPath = Join-Path $ToolDir "cloudflared.exe"
}

if (-not (Test-Path $PythonPath)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python non trovato. Passa -PythonPath con il percorso del runtime Python."
    }
    $PythonPath = $pythonCommand.Source
}

if (-not (Test-Path $CloudflaredPath)) {
    throw "cloudflared.exe non trovato in $CloudflaredPath. Scaricalo in tools\cloudflared.exe oppure passa -CloudflaredPath."
}

$env:OSINT_SIGNUPS_ENABLED = "0"
$env:OSINT_SECURE_COOKIE = "1"
$env:OSINT_HSTS = "1"
$env:OSINT_SESSION_TTL_SECONDS = "28800"
if (-not $env:OSINT_WEB_TOKEN) {
    $env:OSINT_WEB_TOKEN = [guid]::NewGuid().ToString("N")
}

$serverOut = Join-Path $JobDir "server-online-$Port.out.log"
$serverErr = Join-Path $JobDir "server-online-$Port.err.log"
$tunnelOut = Join-Path $JobDir "cloudflared-$Port.out.log"
$tunnelErr = Join-Path $JobDir "cloudflared-$Port.err.log"

Start-Process `
    -FilePath $PythonPath `
    -ArgumentList "-m","osint_bot.web","--host",$HostName,"--port",$Port `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $serverOut `
    -RedirectStandardError $serverErr `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

Start-Process `
    -FilePath $CloudflaredPath `
    -ArgumentList "tunnel","--url","http://$HostName`:$Port" `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $tunnelOut `
    -RedirectStandardError $tunnelErr `
    -WindowStyle Hidden

Write-Host "Server locale avviato su http://$HostName`:$Port"
Write-Host "Tunnel Cloudflare in avvio. Attendi qualche secondo, poi leggi:"
Write-Host $tunnelErr
Write-Host "Cerca nel log la riga: Visit it at https://....trycloudflare.com"
