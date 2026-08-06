#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$SourceDir = ".\publish\agent",
    [string]$InstallDir = "C:\Program Files\NTShield\Agent",
    [string]$DataDir = "C:\ProgramData\NTShield\Agent",
    [string]$ServiceName = "NTShieldAgent",
    [string]$CentralUrl = ""
)

$ErrorActionPreference = "Stop"
Write-Host "== NT Shield Agent Upgrade ==" -ForegroundColor Cyan

$exe = Join-Path $SourceDir "NTShield.Agent.exe"
if (-not (Test-Path $exe)) {
    throw "New agent binary not found: $exe"
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 3
}

# Preserve local config and SQLite DB (DataDir untouched)
$backupConfig = Join-Path $env:TEMP "ntshield-appsettings.backup.json"
$liveConfig = Join-Path $InstallDir "appsettings.json"
if (Test-Path $liveConfig) {
    Copy-Item $liveConfig $backupConfig -Force
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $SourceDir "*") -Destination $InstallDir -Recurse -Force

if (Test-Path $backupConfig) {
    # Keep previous central URL / agent id unless caller overrides CentralUrl
    $old = Get-Content $backupConfig -Raw | ConvertFrom-Json
    $newPath = Join-Path $InstallDir "appsettings.json"
    $new = Get-Content $newPath -Raw | ConvertFrom-Json
    if ($old.Agent) { $new.Agent = $old.Agent }
    if ($old.CentralServer) { $new.CentralServer = $old.CentralServer }
    if ($old.Detection) { $new.Detection = $old.Detection }
    if ($CentralUrl) { $new.CentralServer.BaseUrl = $CentralUrl }
    $new.Agent.DataDirectory = $DataDir
    $new | ConvertTo-Json -Depth 10 | Set-Content $newPath -Encoding UTF8
}

if ($svc) {
    Start-Service -Name $ServiceName
} else {
    & "$PSScriptRoot\install-agent.ps1" -SourceDir $SourceDir -InstallDir $InstallDir -DataDir $DataDir -ServiceName $ServiceName
}

Write-Host "Upgrade complete. Local DB/bookmarks retained under $DataDir" -ForegroundColor Green
