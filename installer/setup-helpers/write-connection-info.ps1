#Requires -Version 3.0
<#
.SYNOPSIS
  Write shared connection.json so separate Agent/Dashboard installs can find Central.

  Path: C:\ProgramData\NTShield\connection.json
#>
param(
    [Parameter(Mandatory = $true)][string]$CentralUrl,
    [string]$DataDir = "C:\ProgramData\NTShield\Server",
    [string]$EnrollmentToken = "",
    [string]$OperatorApiKey = "",
    [int]$Port = 7443
)

$ErrorActionPreference = "Stop"
$root = "C:\ProgramData\NTShield"
New-Item -ItemType Directory -Force -Path $root | Out-Null

# Prefer secrets.json if tokens not passed
$secretsPath = Join-Path $DataDir "secrets.json"
if ((-not $EnrollmentToken -or -not $OperatorApiKey) -and (Test-Path $secretsPath)) {
    try {
        $sec = Get-Content $secretsPath -Raw | ConvertFrom-Json
        if (-not $EnrollmentToken -and $sec.EnrollmentToken) { $EnrollmentToken = [string]$sec.EnrollmentToken }
        if (-not $OperatorApiKey -and $sec.OperatorApiKey) { $OperatorApiKey = [string]$sec.OperatorApiKey }
    } catch { }
}

# Detect primary LAN IPv4 for remote agents
$lanIp = $null
try {
    $lanIp = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike '127.*' -and
            $_.IPAddress -notlike '169.254.*' -and
            $_.PrefixOrigin -ne 'WellKnown'
        } |
        Sort-Object -Property InterfaceMetric |
        Select-Object -First 1 -ExpandProperty IPAddress
} catch { }

$url = $CentralUrl.Trim().TrimEnd('/')
# If URL still localhost but we have a LAN IP, also publish RemoteUrl
$remoteUrl = $url
if ($lanIp -and ($url -match 'localhost|127\.0\.0\.1')) {
    $remoteUrl = ($url -replace 'localhost|127\.0\.0\.1', $lanIp)
}

$payload = [ordered]@{
    Product            = "NT Shield"
    UpdatedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
    CentralUrl         = $url
    RemoteUrl          = $remoteUrl
    HostIp             = $lanIp
    Port               = $Port
    EnrollmentToken    = $EnrollmentToken
    OperatorApiKey     = $OperatorApiKey
    Notes              = "Agent: set Server.Url to RemoteUrl (not localhost) on other PCs. Dashboard: Settings URL + OperatorApiKey. Copy secrets from Server\secrets.json if empty."
}

$out = Join-Path $root "connection.json"
$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $out -Encoding UTF8
Write-Host "OK: connection info -> $out"
Write-Host "    Local  : $url"
Write-Host "    Remote : $remoteUrl"
if ($EnrollmentToken) { Write-Host "    EnrollmentToken: (set)" } else { Write-Host "    EnrollmentToken: (empty — start Central once to generate secrets.json)" }
