#Requires -Version 3.0
<#
.SYNOPSIS
  Write non-secret connection metadata so separate Agent and Dashboard installs
  can locate Central.

  Path: C:\ProgramData\NTShield\connection.json

.SECURITY
  This file is discovery metadata, not a credential store. EnrollmentToken,
  OperatorApiKey and private signing keys are never copied into it.
#>
param(
    [Parameter(Mandatory = $true)][string]$CentralUrl,
    [string]$DataDir = "C:\ProgramData\NTShield\Server",
    # Retained only for backward-compatible callers. Deliberately ignored.
    [string]$EnrollmentToken = "",
    [string]$OperatorApiKey = "",
    [string]$CaCertificatePath = "",
    [int]$Port = 7443
)

$ErrorActionPreference = "Stop"
$root = "C:\ProgramData\NTShield"
New-Item -ItemType Directory -Force -Path $root | Out-Null

if ($EnrollmentToken -or $OperatorApiKey) {
    Write-Warning "Credentials were supplied to write-connection-info.ps1 but were not written. Read protected Server\secrets.json as Administrator when provisioning."
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
$remoteUrl = $url
if ($lanIp -and ($url -match 'localhost|127\.0\.0\.1')) {
    $remoteUrl = ($url -replace 'localhost|127\.0\.0\.1', $lanIp)
}

$resolvedCa = ""
if ($CaCertificatePath) {
    $candidate = [Environment]::ExpandEnvironmentVariables($CaCertificatePath)
    if (-not (Test-Path $candidate -PathType Leaf)) {
        throw "CA certificate not found: $candidate"
    }
    $resolvedCa = (Resolve-Path $candidate).Path
} else {
    foreach ($candidate in @(
        (Join-Path $DataDir "certs\central-ca.cer"),
        (Join-Path $DataDir "certs\central.cer"),
        (Join-Path $DataDir "certs\central-ca.pem")
    )) {
        if (Test-Path $candidate -PathType Leaf) {
            $resolvedCa = (Resolve-Path $candidate).Path
            break
        }
    }
}

$payload = [ordered]@{
    Product            = "NT Shield"
    UpdatedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
    CentralUrl         = $url
    RemoteUrl          = $remoteUrl
    HostIp             = $lanIp
    Port               = $Port
    CaCertificatePath  = $resolvedCa
    RequiresAuth       = $true
    Notes              = "Public connection metadata only. Provision Agent with EnrollmentToken and Dashboard with OperatorApiKey from protected Server\secrets.json."
}

$out = Join-Path $root "connection.json"
$temp = $out + ".tmp"
$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $temp -Encoding UTF8
Move-Item -Path $temp -Destination $out -Force
Write-Host "OK: public connection info -> $out"
Write-Host "    Local  : $url"
Write-Host "    Remote : $remoteUrl"
if ($resolvedCa) {
    Write-Host "    CA cert: $resolvedCa"
} else {
    Write-Warning "No exported Central CA certificate was found. Remote agents must use system trust or receive a CA certificate explicitly."
}
