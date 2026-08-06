#Requires -Version 3.0
<#
.SYNOPSIS
  Publish Agent + Dashboard and optionally install (elevated for install).
#>
[CmdletBinding()]
param(
    [switch]$InstallAgent,
    [switch]$InstallDashboard,
    [string]$CentralUrl = "https://localhost:7443"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:Path = "C:\Program Files\dotnet;" + $env:Path

Write-Host "== Publish NT Shield ==" -ForegroundColor Cyan

# Icons must exist
$ico = Join-Path $Root "assets\icons\NTShield.ico"
if (-not (Test-Path $ico)) {
    Write-Warning "Icon missing at $ico — run icon generation first."
}

Write-Host "Publishing Agent (self-contained win-x64)..."
dotnet publish src\NTShield.Agent\NTShield.Agent.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts\agent-win-x64
Copy-Item config\rules.json artifacts\agent-win-x64\ -Force -ErrorAction SilentlyContinue
if (Test-Path $ico) { Copy-Item $ico artifacts\agent-win-x64\ -Force }

Write-Host "Publishing Dashboard..."
dotnet publish src\NTShield.Dashboard\NTShield.Dashboard.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts\dashboard-win-x64
if (Test-Path $ico) {
    Copy-Item $ico artifacts\dashboard-win-x64\ -Force
    New-Item -ItemType Directory -Force -Path artifacts\dashboard-win-x64\Assets | Out-Null
    Copy-Item $ico artifacts\dashboard-win-x64\Assets\ -Force
}

Write-Host "Publish complete:" -ForegroundColor Green
Write-Host "  artifacts\agent-win-x64"
Write-Host "  artifacts\dashboard-win-x64"

if ($InstallAgent) {
    Write-Host "Installing Agent (elevated)..."
    Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $Root "installer\install-agent.ps1"),
        "-SourceDir", (Join-Path $Root "artifacts\agent-win-x64"),
        "-CentralUrl", $CentralUrl
    )
}

if ($InstallDashboard) {
    Write-Host "Installing Dashboard (elevated)..."
    Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $Root "installer\install-dashboard.ps1"),
        "-SourceDir", (Join-Path $Root "artifacts\dashboard-win-x64"),
        "-IconSource", $ico,
        "-ServerUrl", $CentralUrl,
        "-StartAfterInstall"
    )
}

Write-Host "Done."
