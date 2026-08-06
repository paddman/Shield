#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\NT Shield Agent",
    [string]$ServiceName = "NTShieldAgent",
    [switch]$RemoveData,
    [string]$DataDir = "C:\ProgramData\NTShield"
)

$ErrorActionPreference = "Stop"
Write-Host "== NT Shield Agent Uninstall ==" -ForegroundColor Cyan

# Kill tray + agent processes first so uninstall can delete files
$stopHelper = Join-Path $PSScriptRoot "setup-helpers\stop-agent-for-upgrade.ps1"
if (Test-Path $stopHelper) {
    & $stopHelper -ServiceName $ServiceName -InstallDir $InstallDir
} else {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    foreach ($n in @("NTShield.Agent", "NTShield.Agent.Tray")) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
    }
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "Service removed: $ServiceName"
}

Get-Process -Name "NTShield.Agent.Tray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "Removed $InstallDir"
}

if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Path $DataDir -Recurse -Force
    Write-Host "Removed data $DataDir"
}

Write-Host "Uninstall complete. Security Event Log was never cleared by this agent." -ForegroundColor Green
