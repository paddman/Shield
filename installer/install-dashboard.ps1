#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs NT Shield Dashboard (native WPF app) with icon shortcuts.
#>
[CmdletBinding()]
param(
    [string]$SourceDir = ".\artifacts\dashboard-win-x64",
    [string]$InstallDir = "C:\Program Files\NT Shield\Dashboard",
    [string]$IconSource = ".\assets\icons\NTShield.ico",
    [string]$ServerUrl = "https://localhost:7443",
    [switch]$StartAfterInstall
)

$ErrorActionPreference = "Stop"
$ProductName = "NT Shield Dashboard"
$ExeName = "NTShield.Dashboard.exe"

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "  OK: $m" -ForegroundColor Green }
function Write-Fail($m) { throw $m }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) { Write-Fail "Administrator privilege required." }
if (-not [Environment]::Is64BitOperatingSystem) { Write-Fail "x64 OS required." }

$exe = Join-Path $SourceDir $ExeName
if (-not (Test-Path $exe)) {
    Write-Fail "Dashboard binary not found: $exe`nPublish first:`n  dotnet publish src\NTShield.Dashboard\NTShield.Dashboard.csproj -c Release -r win-x64 --self-contained true -o artifacts\dashboard-win-x64"
}

Write-Step "Creating install directory"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")))
Set-Acl $InstallDir $acl
Write-Ok $InstallDir

Write-Step "Copying files"
Copy-Item -Path (Join-Path $SourceDir "*") -Destination $InstallDir -Recurse -Force

# Ensure icon next to exe
$iconDest = Join-Path $InstallDir "NTShield.ico"
if (Test-Path $IconSource) {
    Copy-Item $IconSource $iconDest -Force
    Write-Ok "Icon installed"
} elseif (Test-Path (Join-Path $SourceDir "Assets\NTShield.ico")) {
    Copy-Item (Join-Path $SourceDir "Assets\NTShield.ico") $iconDest -Force
} elseif (Test-Path (Join-Path $SourceDir "NTShield.ico")) {
    Copy-Item (Join-Path $SourceDir "NTShield.ico") $iconDest -Force
} else {
    Write-Host "  WARN: icon not found; shortcuts may use default icon" -ForegroundColor Yellow
}

# Start menu + desktop shortcuts via WScript
function New-Shortcut([string]$path, [string]$target, [string]$icon, [string]$args = "") {
    $w = New-Object -ComObject WScript.Shell
    $s = $w.CreateShortcut($path)
    $s.TargetPath = $target
    if ($args) { $s.Arguments = $args }
    $s.WorkingDirectory = Split-Path $target
    if (Test-Path $icon) { $s.IconLocation = "$icon,0" }
    $s.Description = $ProductName
    $s.Save()
}

Write-Step "Creating shortcuts"
$startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NT Shield"
New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
$targetExe = Join-Path $InstallDir $ExeName
New-Shortcut (Join-Path $startMenu "$ProductName.lnk") $targetExe $iconDest
New-Shortcut (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "$ProductName.lnk") $targetExe $iconDest
Write-Ok "Start Menu + Desktop shortcuts"

# Uninstall helper
$uninst = @"
#Requires -RunAsAdministrator
`$InstallDir = '$InstallDir'
`$startMenu = '$startMenu'
Stop-Process -Name 'NTShield.Dashboard' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) '$ProductName.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath `$startMenu -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path `$InstallDir) { Remove-Item `$InstallDir -Recurse -Force }
Write-Host 'Dashboard uninstalled.'
"@
Set-Content -Path (Join-Path $InstallDir "uninstall-dashboard.ps1") -Value $uninst -Encoding UTF8

Write-Host ""
Write-Host "Installed: $ProductName" -ForegroundColor Green
Write-Host "  Path    : $InstallDir"
Write-Host "  Icon    : $iconDest"
Write-Host "  Server  : $ServerUrl (change in Settings tab)"
Write-Host "  Remove  : $InstallDir\uninstall-dashboard.ps1"

if ($StartAfterInstall) {
    Start-Process $targetExe
}
