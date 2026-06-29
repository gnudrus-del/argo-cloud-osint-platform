param(
    [switch]$CloneOnly,
    [switch]$InstallTools
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$catalogPath = Join-Path $root "config\tool_catalog.json"
$repoRoot = Join-Path $root "tools\repos"
New-Item -ItemType Directory -Force -Path $repoRoot | Out-Null

$catalog = Get-Content $catalogPath -Raw | ConvertFrom-Json

foreach ($tool in $catalog.catalogo) {
    if (-not $tool.repo) { continue }
    $target = Join-Path $repoRoot $tool.nome
    if (Test-Path $target) {
        Write-Host ("OK       {0} gia presente" -f $tool.nome)
        continue
    }
    Write-Host ("CLONE    {0} -> {1}" -f $tool.nome, $target)
    git clone --depth 1 $tool.repo $target
}

if ($InstallTools) {
    Write-Host ""
    Write-Host "Installazione comandi da catalogo. Verifica licenze, permessi e uso autorizzato prima di continuare."
    foreach ($tool in $catalog.catalogo) {
        if (-not $tool.installazione) { continue }
        Write-Host ("TODO     {0}: {1}" -f $tool.nome, $tool.installazione)
    }
}

if (-not $CloneOnly -and -not $InstallTools) {
    Write-Host ""
    Write-Host "Repository clonati. Usa -InstallTools per stampare i comandi di installazione consigliati."
}
