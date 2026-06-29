param(
    [switch]$ProcessOnly
)

$ErrorActionPreference = "Stop"

$secureKey = Read-Host -Prompt "Incolla BING_SEARCH_API_KEY" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)

try {
    $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if (-not $plainKey -or $plainKey.Trim().Length -lt 10) {
        throw "Chiave Bing vuota o troppo corta."
    }

    $env:BING_SEARCH_API_KEY = $plainKey.Trim()
    if (-not $ProcessOnly) {
        [Environment]::SetEnvironmentVariable("BING_SEARCH_API_KEY", $env:BING_SEARCH_API_KEY, "User")
        Write-Host "BING_SEARCH_API_KEY configurata per l'utente Windows."
        Write-Host "Riavvia Gufo OSINT o esegui scripts\start-online-cloudflare.ps1 per farla leggere al backend."
    } else {
        Write-Host "BING_SEARCH_API_KEY configurata solo per questa sessione PowerShell."
    }
} finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}
