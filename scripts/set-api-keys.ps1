param(
    [switch]$ProcessOnly
)

$ErrorActionPreference = "Stop"

$keys = @(
    @{ Name = "BING_SEARCH_API_KEY"; Label = "Bing Search API" },
    @{ Name = "BRAVE_SEARCH_API_KEY"; Label = "Brave Search API" },
    @{ Name = "SERPER_API_KEY"; Label = "Serper Google Search API" },
    @{ Name = "SHODAN_API_KEY"; Label = "Shodan API" },
    @{ Name = "CENSYS_API_ID"; Label = "Censys API ID"; Plain = $true },
    @{ Name = "CENSYS_API_SECRET"; Label = "Censys API Secret" },
    @{ Name = "HIBP_API_KEY"; Label = "Have I Been Pwned API" },
    @{ Name = "HUNTER_API_KEY"; Label = "Hunter.io API" },
    @{ Name = "INTELX_API_KEY"; Label = "IntelligenceX API" },
    @{ Name = "EPIEOS_API_KEY"; Label = "Epieos API" },
    @{ Name = "INTELOWL_API_URL"; Label = "IntelOwl API URL"; Plain = $true },
    @{ Name = "INTELOWL_API_KEY"; Label = "IntelOwl API Key" },
    @{ Name = "ALEPH_API_URL"; Label = "Aleph API URL"; Plain = $true },
    @{ Name = "ALEPH_API_KEY"; Label = "Aleph API Key" }
)

foreach ($key in $keys) {
    $answer = Read-Host -Prompt ("Configurare {0}? [s/N]" -f $key.Label)
    if ($answer -notin @("s", "S", "si", "SI", "Si", "y", "Y", "yes", "YES")) {
        continue
    }

    if ($key.Plain) {
        $value = Read-Host -Prompt $key.Name
    } else {
        $secureValue = Read-Host -Prompt $key.Name -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        try {
            $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    if (-not $value -or -not $value.Trim()) {
        Write-Host ("Saltata {0}: valore vuoto." -f $key.Name)
        continue
    }

    Set-Item -Path ("Env:\{0}" -f $key.Name) -Value $value.Trim()
    if (-not $ProcessOnly) {
        [Environment]::SetEnvironmentVariable($key.Name, $value.Trim(), "User")
    }
    Write-Host ("Configurata {0}." -f $key.Name)
}

if ($ProcessOnly) {
    Write-Host "Chiavi configurate solo per questa sessione PowerShell."
} else {
    Write-Host "Chiavi salvate nell'utente Windows. Riavvia Gufo OSINT per leggerle."
}
