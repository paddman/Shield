#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Regenerate NT Shield Central HTTPS certificate with public/LAN SANs.

.DESCRIPTION
  Self-signed certs created by older builds only included localhost. Remote
  clients connecting to a public IP (e.g. https://203.0.113.10:7443) failed
  certificate name checks. This script deletes central.pfx, updates appsettings
  CertificateExtraSans / PublicHost, restarts Central, and optionally trusts
  the new cert in LocalMachine Root on this machine.

.EXAMPLE
  .\regenerate-central-cert.ps1 -PublicHost 203.0.113.10
  .\regenerate-central-cert.ps1 -PublicHost 203.0.113.10 -InstallDir "C:\Program Files\NT Shield Central"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublicHost,

    [string]$InstallDir = "",
    [string]$DataDir = "C:\ProgramData\NTShield\Server",
    [string]$ServiceName = "NTShieldCentral",
    [string]$Port = "7443",
    [switch]$NoTrust
)

$ErrorActionPreference = "Stop"

function Resolve-InstallDir {
    param([string]$Hint)
    $candidates = @()
    if ($Hint) { $candidates += $Hint }
    $candidates += @(
        "${env:ProgramFiles}\NT Shield Central",
        "${env:ProgramFiles}\NT Shield\Central",
        "${env:ProgramFiles}\NTShield\Central"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c "NTShield.Server.exe"))) {
            return (Resolve-Path $c).Path
        }
    }
    throw "NTShield.Server.exe not found. Pass -InstallDir."
}

$InstallDir = Resolve-InstallDir -Hint $InstallDir
$publicHostClean = ($PublicHost -replace '^\s+|\s+$', '')
if ($publicHostClean -match '^https?://') {
    try { $publicHostClean = ([Uri]$publicHostClean).Host } catch { }
}
if ($publicHostClean -match ':\d+$' -and $publicHostClean -notmatch '^\[[0-9a-fA-F:]+\]') {
    $publicHostClean = $publicHostClean -replace ':\d+$', ''
}
if (-not $publicHostClean) { throw "PublicHost is empty after parse." }

$portNum = 7443
[void][int]::TryParse($Port, [ref]$portNum)
if ($portNum -lt 1 -or $portNum -gt 65535) { $portNum = 7443 }

$certPath = Join-Path $DataDir "certs\central.pfx"
$cerPath = Join-Path $DataDir "certs\central.cer"
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "certs") | Out-Null

Write-Host "Stopping $ServiceName..." -ForegroundColor DarkYellow
$ErrorActionPreference = "SilentlyContinue"
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
& sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 1
Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$ErrorActionPreference = "Stop"
Start-Sleep -Milliseconds 500

if (Test-Path $certPath) {
    $bak = "$certPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item $certPath $bak -Force
    Remove-Item $certPath -Force
    Write-Host "Backed up and removed old PFX -> $bak"
}
if (Test-Path $cerPath) { Remove-Item $cerPath -Force -ErrorAction SilentlyContinue }

# Collect SANs: public + all local IPv4
$sans = New-Object System.Collections.Generic.List[string]
[void]$sans.Add($publicHostClean)
try {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { if (-not $sans.Contains($_.IPAddress)) { [void]$sans.Add($_.IPAddress) } }
} catch { }
$extraSans = ($sans -join ',')

$appsettings = Join-Path $InstallDir "appsettings.json"
if (-not (Test-Path $appsettings)) {
    throw "appsettings.json missing: $appsettings"
}

$raw = Get-Content $appsettings -Raw -Encoding UTF8
$cfg = $raw | ConvertFrom-Json

if (-not $cfg.Security) {
    $cfg | Add-Member -NotePropertyName Security -NotePropertyValue ([pscustomobject]@{}) -Force
}
$cfg.Security | Add-Member -NotePropertyName CertificatePath -NotePropertyValue $certPath -Force
$cfg.Security | Add-Member -NotePropertyName CertificatePassword -NotePropertyValue "NTShield!" -Force
$cfg.Security | Add-Member -NotePropertyName CertificateExtraSans -NotePropertyValue $extraSans -Force
$cfg.Security | Add-Member -NotePropertyName PublicHost -NotePropertyValue $publicHostClean -Force
$cfg.Security | Add-Member -NotePropertyName RegenerateCertificate -NotePropertyValue $false -Force
if (-not $cfg.Kestrel) {
    $cfg | Add-Member -NotePropertyName Kestrel -NotePropertyValue ([pscustomobject]@{ Port = $portNum }) -Force
} else {
    $cfg.Kestrel | Add-Member -NotePropertyName Port -NotePropertyValue $portNum -Force
}

$cfg | ConvertTo-Json -Depth 12 | Set-Content $appsettings -Encoding UTF8
Write-Host "OK: appsettings PublicHost=$publicHostClean CertificateExtraSans=$extraSans"

Write-Host "Starting $ServiceName..." -ForegroundColor Cyan
Start-Service -Name $ServiceName
$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path $cerPath) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}

if (-not (Test-Path $certPath)) {
    Write-Warning "PFX not created yet - check service status / logs under $DataDir\logs"
} else {
    Write-Host "OK: new PFX at $certPath"
}

if (-not $NoTrust -and (Test-Path $cerPath)) {
    try {
        $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite")
        $store.Add($certObj)
        $store.Close()
        Write-Host "OK: trusted in LocalMachine Root thumbprint=$($certObj.Thumbprint)"
    } catch {
        Write-Warning "Trust import failed: $_"
    }
}

Write-Host ""
Write-Host "Verify (self-signed still needs -k until clients trust central.cer):" -ForegroundColor Green
Write-Host ("  curl.exe -k https://{0}:{1}/api/v1/health" -f $publicHostClean, $portNum)
Write-Host ("  curl.exe -k https://localhost:{0}/api/v1/health" -f $portNum)
Write-Host ""
Write-Host ("Remote Agent Server.Url = https://{0}:{1}" -f $publicHostClean, $portNum)
Write-Host "  AllowUntrustedServerCertificate = true"
Write-Host ("Or copy {0} to clients and import to Trusted Root." -f $cerPath)
