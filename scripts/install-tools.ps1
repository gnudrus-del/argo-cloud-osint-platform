param(
    [switch]$CheckOnly,
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"

function HasCommand($Name) {
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        return $true
    }
    $localBin = Join-Path (Split-Path -Parent $PSScriptRoot) "tools\bin"
    $toolsRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "tools"
    if (Test-Path (Join-Path $localBin $Name)) {
        return $true
    }
    if (Test-Path (Join-Path $localBin "$Name.exe")) {
        return $true
    }
    if (Test-Path (Join-Path $toolsRoot $Name)) {
        return $true
    }
    if (Test-Path (Join-Path $toolsRoot "$Name.exe")) {
        return $true
    }
    if (Test-Path $PythonPath) {
        $scriptsDir = Join-Path (Split-Path $PythonPath -Parent) "Scripts"
        if (Test-Path (Join-Path $scriptsDir $Name)) {
            return $true
        }
        if (Test-Path (Join-Path $scriptsDir "$Name.exe")) {
            return $true
        }
    }
    $nodeBin = Join-Path (Split-Path -Parent $PSScriptRoot) "tools\node-tools\node_modules\.bin"
    if (Test-Path (Join-Path $nodeBin $Name)) {
        return $true
    }
    if (Test-Path (Join-Path $nodeBin "$Name.cmd")) {
        return $true
    }
    return $false
}

function Report($Name, $Status, $Hint) {
    $status = $Status
    Write-Host ("{0,-10} {1} {2}" -f $Name, $status, $Hint)
}

function HasPythonModule($ModuleName) {
    if (-not (Test-Path $PythonPath)) {
        return $false
    }
    & $PythonPath -c "import $ModuleName" 2>$null
    return $LASTEXITCODE -eq 0
}

$tools = @(
    @{ Name = "nmap"; Hint = "winget install Insecure.Nmap" },
    @{ Name = "exiftool"; Hint = "winget install OliverBetz.ExifTool" },
    @{ Name = "ffprobe"; Hint = "winget install Gyan.FFmpeg" },
    @{ Name = "ffmpeg"; Hint = "winget install Gyan.FFmpeg" },
    @{ Name = "firefox"; Hint = "winget install Mozilla.Firefox" },
    @{ Name = "tor"; Hint = "Installa Tor Browser o Tor Expert Bundle dal sito ufficiale" },
    @{ Name = "cloudflared"; Hint = "winget install Cloudflare.cloudflared" },
    @{ Name = "sherlock"; Hint = "pipx install sherlock-project" },
    @{ Name = "maigret"; Hint = "pipx install maigret" },
    @{ Name = "holehe"; Hint = "pipx install holehe" },
    @{ Name = "socialscan"; Hint = "pipx install socialscan" },
    @{ Name = "social-analyzer"; Hint = "pipx install social-analyzer" },
    @{ Name = "h8mail"; Hint = "pipx install h8mail" },
    @{ Name = "phoneinfoga"; Hint = "Scarica release ufficiale o go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest" },
    @{ Name = "ghunt"; Hint = "pipx install ghunt" },
    @{ Name = "toutatis"; Hint = "pipx install toutatis" },
    @{ Name = "osintgram"; Hint = "Setup manuale repo Datalux/Osintgram" },
    @{ Name = "theHarvester"; Hint = "pipx install theHarvester" },
    @{ Name = "spiderfoot"; Hint = "Repo locale in tools\\repos\\spiderfoot o comando SPIDERFOOT_CMD configurato" },
    @{ Name = "recon-ng"; Hint = "Repo locale in tools\\repos\\recon-ng o comando RECON_NG_CMD configurato" },
    @{ Name = "amass"; Hint = "winget install OWASP.Amass" },
    @{ Name = "subfinder"; Hint = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
    @{ Name = "waybackurls"; Hint = "go install github.com/tomnomnom/waybackurls@latest" },
    @{ Name = "gau"; Hint = "go install github.com/lc/gau/v2/cmd/gau@latest" },
    @{ Name = "gitleaks"; Hint = "winget install Gitleaks.Gitleaks" },
    @{ Name = "single-file"; Hint = "npm install -g single-file-cli" },
    @{ Name = "shodan"; Hint = "pipx install shodan" },
    @{ Name = "censys"; Hint = "pipx install censys" }
)

foreach ($tool in $tools) {
    $present = HasCommand $tool.Name
    if (-not $present -and $tool.Name -eq "sherlock") {
        $present = HasPythonModule "sherlock_project"
    }
    $status = if ($present) { "OK" } else { "MISSING" }
    if (-not $present) {
        $repoName = $tool.Name
        if ($tool.Name -eq "recon-ng") { $repoName = "recon-ng" }
        $repoPath = Join-Path (Split-Path -Parent $PSScriptRoot) ("tools\repos\{0}" -f $repoName)
        if (Test-Path $repoPath) {
            $status = "REPO"
        }
    }
    Report $tool.Name $status $tool.Hint
}

if ($CheckOnly) {
    return
}

Write-Host ""
Write-Host "Installazione automatica non eseguita."
Write-Host "Esegui manualmente solo i tool necessari e autorizzati usando gli hint sopra."
