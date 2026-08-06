#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Point the Agent at a Central Server (IP/host + port) and restart the service.

.DESCRIPTION
  Agent sends telemetry only to Central HTTPS API (not to Dashboard).
  Dashboard must use the SAME base URL to see this host.

.EXAMPLE
  # By IP + port (recommended)
  .\set-agent-central-url.ps1 -ServerHost 10.0.0.5 -Port 7443

  # Full URL
  .\set-agent-central-url.ps1 -CentralUrl https://10.0.0.5:7443

  # Interactive (prompts for IP and port)
  .\set-agent-central-url.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [Parameter(Mandatory = $false)]
    [string]$CentralUrl = "",
    # Prefer these for simple IP/port config
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
    [switch]$AllowUntrustedServerCertificate,
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
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "appsettings.json")) { return $c }
    }
    return $null
}

function Build-CentralUrl {
    param([string]$HostName, [int]$PortNum, [string]$UseScheme)
    $h = $HostName.Trim().TrimEnd('/')
    if ($h -match '^https?://') {
        # User pasted a full URL into host field
        return $h.TrimEnd('/')
    }
    if ($PortNum -le 0) { $PortNum = 7443 }
    return ("{0}://{1}:{2}" -f $UseScheme.ToLowerInvariant(), $h, $PortNum)
}

$InstallDir = Resolve-InstallDir -Dir $InstallDir
if (-not $InstallDir) {
    throw "Cannot find Agent install (appsettings.json). Pass -InstallDir."
}

$appsettings = Join-Path $InstallDir "appsettings.json"
$current = ""
try {
    $j0 = Get-Content $appsettings -Raw | ConvertFrom-Json
    if ($j0.Server -and $j0.Server.Url) { $current = [string]$j0.Server.Url }
} catch { }

# Resolve CentralUrl from parameters or prompts
if (-not $CentralUrl) {
    if ($ServerHost) {
        if ($Port -le 0) { $Port = 7443 }
        $CentralUrl = Build-CentralUrl -HostName $ServerHost -PortNum $Port -UseScheme $Scheme
    }
}

if (-not $CentralUrl) {
    Write-Host ""
    Write-Host "=== NT Shield Agent → Central Server ===" -ForegroundColor Cyan
    Write-Host "Agent ส่งข้อมูลไป Central เท่านั้น (ไม่ต่อ Dashboard โดยตรง)"
    Write-Host "Current: $current"
    Write-Host ""
    Write-Host "ใส่ IP หรือชื่อเซิร์ฟเวอร์ + พอร์ต (ค่าเริ่มต้น 7443)"
    Write-Host "ตัวอย่าง: 10.0.0.5   พอร์ต 7443  →  https://10.0.0.5:7443"
    Write-Host ""
    $inHost = Read-Host "Central Server IP / Host"
    if (-not $inHost) { throw "Host/IP is required." }
    $inPort = Read-Host "Port [7443]"
    if (-not $inPort) { $inPort = "7443" }
    $portNum = 0
    if (-not [int]::TryParse($inPort, [ref]$portNum) -or $portNum -lt 1 -or $portNum -gt 65535) {
        throw "Invalid port: $inPort"
    }
    $useHttp = Read-Host "Use HTTP instead of HTTPS? (y/N)"
    $sch = if ($useHttp -match '^(y|yes)$') { "http" } else { "https" }
    $CentralUrl = Build-CentralUrl -HostName $inHost -PortNum $portNum -UseScheme $sch
    $ServerHost = $inHost.Trim()
    $Port = $portNum
    if (-not $EnableSyslog) {
        $EnableSyslog = $true
        if (-not $SyslogHost) { $SyslogHost = $ServerHost }
    }
    $AllowUntrustedServerCertificate = $true
}

$CentralUrl = $CentralUrl.Trim().TrimEnd('/')
if ($CentralUrl -notmatch '^https?://') {
    # Allow bare host:port or host
    if ($CentralUrl -match '^([^:/]+)(?::(\d+))?$') {
        $h = $Matches[1]
        $p = if ($Matches[2]) { [int]$Matches[2] } else { 7443 }
        $CentralUrl = Build-CentralUrl -HostName $h -PortNum $p -UseScheme $Scheme
    } else {
        throw "URL must start with https:// or http:// — or pass -ServerHost and -Port. Got: $CentralUrl"
    }
}

# Derive host for syslog default
if (-not $ServerHost) {
    try {
        $u = [Uri]$CentralUrl
        $ServerHost = $u.Host
        if ($Port -le 0) { $Port = if ($u.IsDefaultPort) { 7443 } else { $u.Port } }
    } catch { }
}

# Pull enrollment token from shared connection file if not provided
if (-not $EnrollmentToken -and (Test-Path "C:\ProgramData\NTShield\connection.json")) {
    try {
        $c = Get-Content "C:\ProgramData\NTShield\connection.json" -Raw | ConvertFrom-Json
        if ($c.EnrollmentToken) { $EnrollmentToken = [string]$c.EnrollmentToken }
        if (($CentralUrl -match 'localhost|127\.0\.0\.1') -and $c.RemoteUrl -and -not (Get-Service NTShieldCentral -ErrorAction SilentlyContinue)) {
            $CentralUrl = [string]$c.RemoteUrl
            Write-Host "NOTE: using RemoteUrl from connection.json: $CentralUrl" -ForegroundColor Yellow
        }
    } catch { }
}

$json = Get-Content $appsettings -Raw | ConvertFrom-Json
if (-not $json.Server) {
    $json | Add-Member -NotePropertyName Server -NotePropertyValue ([pscustomobject]@{ Url = $CentralUrl }) -Force
} else {
    $json.Server.Url = $CentralUrl
}

# Self-signed Central cert — always on for separate installs unless explicitly disabled later
$json.Server | Add-Member -NotePropertyName AllowUntrustedServerCertificate -NotePropertyValue $true -Force
if ($EnrollmentToken) {
    $json.Server | Add-Member -NotePropertyName EnrollmentToken -NotePropertyValue $EnrollmentToken -Force
    Write-Host "OK: EnrollmentToken set" -ForegroundColor Green
}

if ($EnableSyslog) {
    if (-not $SyslogHost) { $SyslogHost = if ($ServerHost) { $ServerHost } else { "127.0.0.1" } }
    $json.Server | Add-Member -NotePropertyName SyslogEnabled -NotePropertyValue $true -Force
    $json.Server | Add-Member -NotePropertyName SyslogHost -NotePropertyValue $SyslogHost -Force
    $json.Server | Add-Member -NotePropertyName SyslogPort -NotePropertyValue $SyslogPort -Force
    Write-Host "OK: Syslog → ${SyslogHost}:$SyslogPort" -ForegroundColor Green
}

$json | ConvertTo-Json -Depth 12 | Set-Content $appsettings -Encoding UTF8
Write-Host "OK: Server.Url = $CentralUrl" -ForegroundColor Green
Write-Host "    AllowUntrustedServerCertificate = true"
Write-Host "    File: $appsettings"
if ($CentralUrl -match 'localhost|127\.0\.0\.1') {
    Write-Warning "URL is localhost — only works if Central is on THIS PC. Remote agents need LAN IP."
}

if (-not $NoRestart) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svc.Refresh()
        Write-Host "Service $ServiceName : $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    } else {
        Write-Warning "Service $ServiceName not found. Start it after install."
    }
}

Write-Host ""
Write-Host "Dashboard ต้องใช้ URL เดียวกันใน Settings:" -ForegroundColor Cyan
Write-Host "  $CentralUrl"
Write-Host "Agent เครื่องนี้ ($env:COMPUTERNAME) ควรขึ้นในรายการ Agents ภายใน ~1 นาที"
