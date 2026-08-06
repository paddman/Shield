#Requires -Version 3.0
<#
.SYNOPSIS
  Rebuild ALL NT Shield installers after code changes.

.EXAMPLE
  .\installer\rebuild-all-setups.ps1
  .\installer\rebuild-all-setups.ps1 -AgentVersion 1.0.12 -CentralVersion 1.0.4 -FullVersion 1.0.7
#>
[CmdletBinding()]
param(
    # Empty = use Directory.Build.props Version for ALL packages (recommended)
    [string]$AgentVersion = "",
    [string]$CentralVersion = "",
    [string]$FullVersion = "",
    [switch]$SkipFull
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "NTShield.sln"))) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location $Root
$env:Path = "C:\Program Files\dotnet;" + $env:Path

# Single product version — Setup names match binary ProductVersion
$productVersion = "1.0.0"
$props = Get-Content (Join-Path $Root "Directory.Build.props") -Raw
if ($props -match '<Version>([^<]+)</Version>') { $productVersion = $Matches[1].Trim() }
if (-not $AgentVersion) { $AgentVersion = $productVersion }
if (-not $CentralVersion) { $CentralVersion = $productVersion }
if (-not $FullVersion) { $FullVersion = $productVersion }
Write-Host "Product version: $productVersion  (Agent=$AgentVersion Central=$CentralVersion Full=$FullVersion)" -ForegroundColor Green

Write-Host "Stopping services/processes that lock publish outputs..." -ForegroundColor DarkYellow
Stop-Service NTShieldAgent,NTShieldCentral -Force -ErrorAction SilentlyContinue
foreach ($n in @("NTShield.Agent","NTShield.Server","NTShield.Agent.Tray","NTShield.Dashboard")) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# signatures for central package
New-Item -ItemType Directory -Force -Path (Join-Path $Root "artifacts\server-win-x64\signatures") | Out-Null
Copy-Item (Join-Path $Root "config\signatures\opensource-signatures.json") `
    (Join-Path $Root "artifacts\server-win-x64\signatures\") -Force -ErrorAction SilentlyContinue

Write-Host "`n[1/3] Agent Setup $AgentVersion" -ForegroundColor Cyan
& (Join-Path $Root "installer\build-setup-agent.ps1") -Version $AgentVersion
if ($LASTEXITCODE -ne 0) { throw "Agent setup failed" }

Write-Host "`n[2/3] Central Setup $CentralVersion" -ForegroundColor Cyan
& (Join-Path $Root "installer\build-setup-central.ps1") -Version $CentralVersion
if ($LASTEXITCODE -ne 0) { throw "Central setup failed" }

if (-not $SkipFull) {
    Write-Host "`n[3/3] Full Setup $FullVersion" -ForegroundColor Cyan
    & (Join-Path $Root "installer\build-setup.ps1") -Version $FullVersion
    if ($LASTEXITCODE -ne 0) { throw "Full setup failed" }
}

Write-Host "`n=== Latest installers ===" -ForegroundColor Green
Get-ChildItem (Join-Path $Root "artifacts\setup\*.exe") |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 6 Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}, LastWriteTime |
    Format-Table -AutoSize

Start-Service NTShieldCentral -ErrorAction SilentlyContinue
Start-Service NTShieldAgent -ErrorAction SilentlyContinue
Write-Host "Done." -ForegroundColor Green
