#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Point the Agent at a Central Server and restart the service.

.DESCRIPTION
  Secure defaults require HTTPS and a certificate trusted by Windows or by an
  explicitly supplied CA certificate. Skipping certificate validation requires
  the explicit -AllowUntrustedServerCertificate switch.

.EXAMPLE
  .\set-agent-central-url.ps1 -ServerHost 10.0.0.5 -Port 7443 `
    -CaCertificatePath .\central-ca.cer -EnrollmentToken '<token>'

.EXAMPLE
  # Isolated migration lab only
  .\set-agent-central-url.ps1 -ServerHost 10.0.0.5 -Port 7443 `
    -AllowUntrustedServerCertificate
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [Parameter(Mandatory = $false)]
    [string]$CentralUrl = "",
    [Alias("ServerIp", "Ip", "Host")]
    [string]$ServerHost = "",
    [int]$Port = 0,
    [ValidateSet("https", "http")]
    [string]$Scheme = "https",
    [string]$ServiceName = "NTShieldAgent",
    [switch]$NoRestart,
    [switch]$EnableSyslog,
    [string]$SyslogHost = "",
    [int]$SyslogPort = 5514,
    [string]$CaCertificatePath = "",
    [switch]$AllowUntrustedServerCertificate,
    [switch]$AllowHttp,
    [string]$EnrollmentToken = ""
)

$ErrorActionPreference = "Stop"

function Resolve-InstallDir {
    param([string]$Dir)
    if ($Dir -and (Test-Path (Join-Path $Dir "appsettings.json"))) { return $Dir }
    $candidates = @(
        "${env:ProgramFiles}\NT Shield Agent",
        "${env:ProgramFiles}\NT Shield\Agent",
        "C:\Program Files\NT Shield Agent",
        "C:\Program Files\NT Shield\Agent"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path (Join-Path $candidate "appsettings.json")) { return $candidate }
    }
    return $null
}

function Build-CentralUrl {
    param([string]$HostName, [int]$PortNum, [string]$UseScheme)
    $hostValue = $HostName.Trim().TrimEnd('/')
    if ($hostValue -match '^https?://') { return $hostValue.TrimEnd('/') }
    if ($PortNum -le 0) { $PortNum = 7443 }
    return ("{0}://{1}:{2}" -f $UseScheme.ToLowerInvariant(), $hostValue, $PortNum)
}

function Copy-TrustedCa {
    param([string]$SourcePath)
    if (-not $SourcePath) { return "" }
    $expanded = [Environment]::ExpandEnvironmentVariables($SourcePath)
    if (-not (Test-Path $expanded -PathType Leaf)) {
        throw "CA certificate not found: $expanded"
    }

    $agentData = "C:\ProgramData\NTShield\Agent"
    New-Item -ItemType Directory -Force -Path $agentData | Out-Null
    $extension = [IO.Path]::GetExtension($expanded)
    if (-not $extension) { $extension = ".cer" }
    $destination = Join-Path $agentData ("central-ca" + $extension.ToLowerInvariant())
    $sourceFull = (Resolve-Path $expanded).Path
    $destinationFull = [IO.Path]::GetFullPath($destination)
    if (-not $sourceFull.Equals($destinationFull, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -Path $sourceFull -Destination $destinationFull -Force
    }
    return $destinationFull
}

$InstallDir = Resolve-InstallDir -Dir $InstallDir
if (-not $InstallDir) {
    throw "Cannot find Agent install (appsettings.json). Pass -InstallDir."
}

$appsettings = Join-Path $InstallDir "appsettings.json"
$current = ""
$currentCa = ""
try {
    $existing = Get-Content $appsettings -Raw | ConvertFrom-Json
    if ($existing.Server -and $existing.Server.Url) { $current = [string]$existing.Server.Url }
    if ($existing.Server -and $existing.Server.CaCertificatePath) { $currentCa = [string]$existing.Server.CaCertificatePath }
} catch { }

if (-not $CentralUrl -and $ServerHost) {
    if ($Port -le 0) { $Port = 7443 }
    $CentralUrl = Build-CentralUrl -HostName $ServerHost -PortNum $Port -UseScheme $Scheme
}

if (-not $CentralUrl) {
    Write-Host ""
    Write-Host "=== NT Shield Agent -> Central Server ===" -ForegroundColor Cyan
    Write-Host "Current: $current"
    $inputHost = Read-Host "Central Server IP / Host"
    if (-not $inputHost) { throw "Host/IP is required." }
    $inputPort = Read-Host "Port [7443]"
    if (-not $inputPort) { $inputPort = "7443" }
    $portNumber = 0
    if (-not [int]::TryParse($inputPort, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
        throw "Invalid port: $inputPort"
    }

    $CentralUrl = Build-CentralUrl -HostName $inputHost -PortNum $portNumber -UseScheme "https"
    $ServerHost = $inputHost.Trim()
    $Port = $portNumber

    $inputCa = Read-Host "CA certificate path [blank = Windows trust store]"
    if ($inputCa) { $CaCertificatePath = $inputCa }

    $unsafe = Read-Host "Skip TLS certificate validation? ISOLATED LAB ONLY (y/N)"
    if ($unsafe -match '^(y|yes)$') { $AllowUntrustedServerCertificate = $true }

    if (-not $EnableSyslog) {
        $EnableSyslog = $true
        if (-not $SyslogHost) { $SyslogHost = $ServerHost }
    }
}

$CentralUrl = $CentralUrl.Trim().TrimEnd('/')
if ($CentralUrl -notmatch '^https?://') {
    if ($CentralUrl -match '^([^:/]+)(?::(\d+))?$') {
        $hostValue = $Matches[1]
        $portValue = if ($Matches[2]) { [int]$Matches[2] } else { 7443 }
        $CentralUrl = Build-CentralUrl -HostName $hostValue -PortNum $portValue -UseScheme $Scheme
    } else {
        throw "URL must start with https:// or http://, or pass -ServerHost and -Port. Got: $CentralUrl"
    }
}

if ($CentralUrl -match '^http://') {
    if (-not $AllowHttp) {
        throw "Plain HTTP is disabled. Use HTTPS, or pass -AllowHttp only in an isolated migration lab."
    }
    Write-Warning "Plain HTTP enabled: telemetry, credentials and policy are not protected in transit."
}

if (-not $ServerHost) {
    try {
        $uri = [Uri]$CentralUrl
        $ServerHost = $uri.Host
        if ($Port -le 0) { $Port = if ($uri.IsDefaultPort) { 7443 } else { $uri.Port } }
    } catch { }
}

# connection.json is public discovery metadata only. It may provide URL and a
# local CA path, never enrollment or operator credentials.
$connectionPath = "C:\ProgramData\NTShield\connection.json"
if (Test-Path $connectionPath) {
    try {
        $connection = Get-Content $connectionPath -Raw | ConvertFrom-Json
        if (($CentralUrl -match 'localhost|127\.0\.0\.1') -and $connection.RemoteUrl -and
            -not (Get-Service NTShieldCentral -ErrorAction SilentlyContinue)) {
            $CentralUrl = [string]$connection.RemoteUrl
            Write-Host "NOTE: using RemoteUrl from connection.json: $CentralUrl" -ForegroundColor Yellow
        }
        if (-not $CaCertificatePath -and $connection.CaCertificatePath -and
            (Test-Path ([string]$connection.CaCertificatePath) -PathType Leaf)) {
            $CaCertificatePath = [string]$connection.CaCertificatePath
        }
    } catch { }
}

# Local full-stack provisioning may read the protected Central secrets file as
# Administrator. Secrets are never copied into connection.json.
if (-not $EnrollmentToken) {
    $localSecrets = "C:\ProgramData\NTShield\Server\secrets.json"
    if (Test-Path $localSecrets -PathType Leaf) {
        try {
            $secrets = Get-Content $localSecrets -Raw | ConvertFrom-Json
            if ($secrets.EnrollmentToken) {
                $EnrollmentToken = [string]$secrets.EnrollmentToken
                Write-Host "OK: EnrollmentToken loaded from protected local Central secrets" -ForegroundColor Green
            }
        } catch { }
    }
}

$trustedCa = ""
if ($CaCertificatePath) {
    $trustedCa = Copy-TrustedCa -SourcePath $CaCertificatePath
} elseif ($currentCa -and (Test-Path $currentCa -PathType Leaf)) {
    $trustedCa = $currentCa
}

$json = Get-Content $appsettings -Raw | ConvertFrom-Json
if (-not $json.Server) {
    $json | Add-Member -NotePropertyName Server -NotePropertyValue ([pscustomobject]@{}) -Force
}
$json.Server | Add-Member -NotePropertyName Url -NotePropertyValue $CentralUrl -Force
$json.Server | Add-Member -NotePropertyName AllowUntrustedServerCertificate -NotePropertyValue ([bool]$AllowUntrustedServerCertificate) -Force
$json.Server | Add-Member -NotePropertyName CaCertificatePath -NotePropertyValue $trustedCa -Force
if ($EnrollmentToken) {
    $json.Server | Add-Member -NotePropertyName EnrollmentToken -NotePropertyValue $EnrollmentToken -Force
    Write-Host "OK: EnrollmentToken set for first enrollment" -ForegroundColor Green
}

if ($EnableSyslog) {
    if (-not $SyslogHost) { $SyslogHost = if ($ServerHost) { $ServerHost } else { "127.0.0.1" } }
    $json.Server | Add-Member -NotePropertyName SyslogEnabled -NotePropertyValue $true -Force
    $json.Server | Add-Member -NotePropertyName SyslogHost -NotePropertyValue $SyslogHost -Force
    $json.Server | Add-Member -NotePropertyName SyslogPort -NotePropertyValue $SyslogPort -Force
    Write-Host "OK: Syslog -> ${SyslogHost}:$SyslogPort" -ForegroundColor Green
}

$json | ConvertTo-Json -Depth 12 | Set-Content $appsettings -Encoding UTF8
Write-Host "OK: Server.Url = $CentralUrl" -ForegroundColor Green
if ($AllowUntrustedServerCertificate) {
    Write-Warning "TLS validation is DISABLED by explicit request. This is not production-safe."
} elseif ($trustedCa) {
    Write-Host "    TLS trust: custom CA $trustedCa" -ForegroundColor Green
} else {
    Write-Host "    TLS trust: Windows certificate trust store" -ForegroundColor Green
}
Write-Host "    File: $appsettings"

if ($CentralUrl -match 'localhost|127\.0\.0\.1') {
    Write-Warning "URL is localhost; remote agents require Central LAN/DNS address with a matching certificate SAN."
}

if (-not $NoRestart) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $service.Refresh()
        Write-Host "Service $ServiceName : $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    } else {
        Write-Warning "Service $ServiceName not found. Start it after install."
    }
}

Write-Host ""
Write-Host "Dashboard must use the same Central URL:" -ForegroundColor Cyan
Write-Host "  $CentralUrl"
Write-Host "Agent $env:COMPUTERNAME should appear after authenticated enrollment and heartbeat."
