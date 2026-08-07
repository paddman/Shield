#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs NT Shield Agent on Windows Server 2012+ (x64).
#>
[CmdletBinding()]
param(
    [string]$SourceDir = ".\artifacts\agent-win-x64",
    [string]$InstallDir = "C:\Program Files\NT Shield Agent",
    [string]$DataDir = "C:\ProgramData\NTShield",
    [string]$CentralUrl = "https://sentinel.example.local",
    [string]$ServiceName = "NTShieldAgent",
    [string]$DisplayName = "NT Shield Agent"
)

$ErrorActionPreference = "Stop"
$AgentData = Join-Path $DataDir "Agent"
$LogDir = Join-Path $AgentData "logs"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "  OK: $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; throw $msg }

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-VcRedist {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $installed = (Get-ItemProperty $k -ErrorAction SilentlyContinue).Installed
            if ($installed -eq 1) { return $true }
        }
    }
    $hits = Get-ItemProperty @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    ) -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Visual C\+\+ (2015|2017|2019|2022).+x64' }
    return [bool]$hits
}

function Set-DirectoryAcl([string]$Path, [string]$Description) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    # SYSTEM + Administrators full; Users read/execute only on install dir
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $rules = @(
        (New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")),
        (New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"))
    )
    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -Path $Path -AclObject $acl
    Write-Ok "ACL set on $Description ($Path)"
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " NT Shield Agent Installer (Server 2012+)    " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1) Admin
if (-not (Test-Administrator)) { Write-Fail "Administrator privilege required." }
Write-Ok "Running elevated"

# 2) x64
if (-not [Environment]::Is64BitOperatingSystem) { Write-Fail "x64 OS required." }
Write-Ok "OS is x64"

# 3) Windows version >= 6.2 (Server 2012)
$os = [Environment]::OSVersion.Version
if ($os.Major -lt 6 -or ($os.Major -eq 6 -and $os.Minor -lt 2)) {
    Write-Fail "Unsupported Windows version $os. Minimum is Windows Server 2012 (6.2)."
}
Write-Ok "Windows version $os meets minimum (Server 2012+)"

# 4) VC++ Redistributable
if (-not (Test-VcRedist)) {
    Write-Host "WARNING: Microsoft Visual C++ Redistributable (x64) not detected." -ForegroundColor Yellow
    Write-Host "Install from https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
    $c = Read-Host "Continue without VC++ Redistributable? (y/N)"
    if ($c -ne 'y' -and $c -ne 'Y') { Write-Fail "VC++ Redistributable prerequisite missing." }
} else {
    Write-Ok "Visual C++ Redistributable x64 present"
}

# 5) Source binaries
$exeName = "NTShield.Agent.exe"
$exe = Join-Path $SourceDir $exeName
if (-not (Test-Path $exe)) { Write-Fail "Agent binary not found: $exe" }
Write-Ok "Found $exe"

# 6) Stop existing service + kill processes (in-place upgrade safe)
Write-Step "Stopping existing Agent / Tray (force kill for upgrade)"
$stopHelper = Join-Path $PSScriptRoot "setup-helpers\stop-agent-for-upgrade.ps1"
if (Test-Path $stopHelper) {
    & $stopHelper -ServiceName $ServiceName -InstallDir $InstallDir
} else {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe stop $ServiceName | Out-Null
    foreach ($n in @("NTShield.Agent", "NTShield.Agent.Tray")) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
    }
    Start-Sleep -Seconds 1
}
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
Write-Ok "Previous instance stopped"

# 7) Directories + ACL
Write-Step "Creating directories and ACLs"
Set-DirectoryAcl -Path $InstallDir -Description "install"
Set-DirectoryAcl -Path $DataDir -Description "programdata root"
Set-DirectoryAcl -Path $AgentData -Description "agent data"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $AgentData "evidence") | Out-Null

# 8) Copy files
Write-Step "Copying binaries"
Copy-Item -Path (Join-Path $SourceDir "*") -Destination $InstallDir -Recurse -Force
Write-Ok "Files copied to $InstallDir"

# Brand icon for Start Menu / explorer
$repoIcon = Join-Path $PSScriptRoot "..\assets\icons\NTShield.ico"
$iconDest = Join-Path $InstallDir "NTShield.ico"
if (Test-Path $repoIcon) {
    Copy-Item $repoIcon $iconDest -Force
    Write-Ok "Icon copied"
} elseif (Test-Path (Join-Path $SourceDir "NTShield.ico")) {
    Copy-Item (Join-Path $SourceDir "NTShield.ico") $iconDest -Force
}

# 9) Configure appsettings
$appsettings = Join-Path $InstallDir "appsettings.json"
if (Test-Path $appsettings) {
    try {
        $json = Get-Content $appsettings -Raw | ConvertFrom-Json
        if ($json.Server) { $json.Server.Url = $CentralUrl }
        if ($json.CentralServer) { $json.CentralServer.BaseUrl = $CentralUrl }
        if ($json.Agent) {
            $json.Agent.DataDirectory = $AgentData
            $json.Agent.ComputerName = $env:COMPUTERNAME
            $json.Agent.DetectOnly = $true
        }
        if ($json.LoggingPaths) { $json.LoggingPaths.Directory = $LogDir }
        if ($json.Response) {
            $json.Response.DetectOnly = $true
            $json.Response.LogOnlyMode = $true
            $json.Response.EvidenceDirectory = (Join-Path $AgentData "evidence")
        }
        $json | ConvertTo-Json -Depth 12 | Set-Content -Path $appsettings -Encoding UTF8
        Write-Ok "Configured Central URL and DetectOnly=true"
    } catch {
        Write-Host "WARNING: could not patch appsettings.json: $_" -ForegroundColor Yellow
    }
}

# 10) Event source (Application log) — never clear Security log
Write-Step "Registering Application event source"
$source = "NTShieldAgent"
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    New-EventLog -LogName Application -Source $source
    Write-Ok "Event source $source created"
} else {
    Write-Ok "Event source already exists"
}

# 11) Install service
Write-Step "Creating Windows Service"
$binPath = "`"$InstallDir\$exeName`""
New-Service -Name $ServiceName `
    -BinaryPathName $binPath `
    -DisplayName $DisplayName `
    -Description "NT Shield Endpoint Security Monitoring Agent (detect-only default)" `
    -StartupType Automatic | Out-Null

# Delayed auto-start + recovery restart on crash (Server 2012 compatible sc.exe)
& sc.exe config $ServiceName start= delayed-auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Write-Ok "Service created with Automatic (Delayed) start and recovery restart"

# 12) Start + health
Write-Step "Starting service"
Start-Service -Name $ServiceName
Start-Sleep -Seconds 5
$svc = Get-Service -Name $ServiceName
if ($svc.Status -ne "Running") {
    Write-Host "Service status: $($svc.Status). Check logs at $LogDir" -ForegroundColor Yellow
} else {
    Write-Ok "Service is Running"
}

# Health: process present
$proc = Get-Process -Name "NTShield.Agent" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Ok "Process running (PID $($proc.Id), WS $([math]::Round($proc.WorkingSet64/1MB,1)) MB)"
} else {
    Write-Host "WARNING: process not observed yet; review $LogDir" -ForegroundColor Yellow
}

# Start Menu folder + logs shortcut with brand icon
try {
    $sm = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NT Shield"
    New-Item -ItemType Directory -Force -Path $sm | Out-Null
    $w = New-Object -ComObject WScript.Shell
    $logShortcut = $w.CreateShortcut((Join-Path $sm "Agent Logs.lnk"))
    $logShortcut.TargetPath = $LogDir
    if (Test-Path $iconDest) { $logShortcut.IconLocation = "$iconDest,0" }
    $logShortcut.Description = "NT Shield Agent logs"
    $logShortcut.Save()
    Write-Ok "Start Menu shortcut created"
} catch {
    Write-Host "NOTE: Start Menu shortcut skipped: $_" -ForegroundColor Yellow
}

# System tray companion (notification area icon)
$trayHelper = Join-Path $PSScriptRoot "setup-helpers\register-agent-tray.ps1"
if (-not (Test-Path $trayHelper)) {
    $trayHelper = Join-Path $InstallDir "Installer\register-agent-tray.ps1"
}
if (Test-Path $trayHelper) {
    Write-Step "Registering system tray icon"
    try {
        & $trayHelper -InstallDir $InstallDir -StartNow "1" -RunAtLogon "1"
        Write-Ok "Tray icon registered (notification area)"
    } catch {
        Write-Host "NOTE: tray registration skipped: $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host "  Service : $ServiceName ($DisplayName)"
Write-Host "  Install : $InstallDir"
Write-Host "  Data    : $AgentData"
Write-Host "  Logs    : $LogDir"
Write-Host "  Icon    : $iconDest"
Write-Host "  Tray    : NTShield.Agent.Tray (system tray / notification area)"
Write-Host "  Mode    : DetectOnly (no auto block/kill)"
Write-Host ""
Write-Host "Rollback instructions:" -ForegroundColor Yellow
Write-Host "  1. Stop-Service $ServiceName"
Write-Host "  2. sc.exe delete $ServiceName"
Write-Host "  3. Remove-Item -Recurse -Force `"$InstallDir`""
Write-Host "  4. (optional) Remove-Item -Recurse -Force `"$DataDir`""
Write-Host "  Or run: .\installer\uninstall-agent.ps1"
