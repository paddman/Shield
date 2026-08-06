#Requires -Version 3.0
<#
.SYNOPSIS
  Publish Central + Agent + Dashboard and build full NTShield-Setup-x.y.z.exe

.EXAMPLE
  .\installer\build-setup.ps1
  .\installer\build-setup.ps1 -Version 1.0.7
  .\installer\build-setup.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish,
    [string]$Configuration = "Release",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "NTShield.sln"))) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location $Root
$env:Path = "C:\Program Files\dotnet;" + $env:Path

if (-not $Version) {
    $props = Get-Content (Join-Path $Root "Directory.Build.props") -Raw
    if ($props -match '<Version>([^<]+)</Version>') { $Version = $Matches[1].Trim() }
    else { $Version = "1.1.0" }
}
Write-Host "Setup/Product Version: $Version" -ForegroundColor Green

function Find-ISCC {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:LocalAppData}\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 7\ISCC.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $found = Get-ChildItem -Path "$env:LocalAppData\Programs","${env:ProgramFiles(x86)}","$env:ProgramFiles" `
        -Filter "ISCC.exe" -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    return $found
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " NT Shield - Build Setup.exe" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ico = Join-Path $Root "assets\icons\NTShield.ico"
if (-not (Test-Path $ico)) {
    throw "Missing icon: $ico"
}

if (-not $SkipPublish) {
    Write-Host ""
    # All components are self-contained win-x64 — target PCs need NO installed .NET
    Write-Host "[1/4] Publishing Central Server (self-contained win-x64)..." -ForegroundColor Yellow
    $serverOut = Join-Path $Root "artifacts\server-win-x64"
    $tmp = Join-Path $Root "artifacts\server-publish-tmp"
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    # Clean old framework-dependent leftovers so installer does not ship mixed builds
    if (Test-Path $serverOut) {
        Get-ChildItem $serverOut -Force | Where-Object { $_.Name -ne 'logs' } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $tmp, $serverOut | Out-Null
    dotnet publish (Join-Path $Root "src\NTShield.Server\NTShield.Server.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=false `
        -o $tmp
    if ($LASTEXITCODE -ne 0) { throw "Central publish failed" }
    Copy-Item (Join-Path $tmp "*") $serverOut -Recurse -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $serverOut "signatures") | Out-Null
    Copy-Item (Join-Path $Root "config\signatures\opensource-signatures.json") (Join-Path $serverOut "signatures\") -Force -ErrorAction SilentlyContinue
    Copy-Item $ico $serverOut -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "[2/4] Publishing Agent (self-contained win-x64)..." -ForegroundColor Yellow
    $agentOut = Join-Path $Root "artifacts\agent-win-x64"
    if (Test-Path $agentOut) {
        Get-ChildItem $agentOut -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $agentOut | Out-Null
    dotnet publish (Join-Path $Root "src\NTShield.Agent\NTShield.Agent.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $agentOut
    if ($LASTEXITCODE -ne 0) { throw "Agent publish failed" }

    Copy-Item (Join-Path $Root "config\rules.json") $agentOut -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $Root "config\allowlist.json") $agentOut -Force -ErrorAction SilentlyContinue
    Copy-Item $ico $agentOut -Force

    Write-Host ""
    Write-Host "[2b/4] Publishing Agent Tray (self-contained)..." -ForegroundColor Yellow
    dotnet publish (Join-Path $Root "src\NTShield.Agent.Tray\NTShield.Agent.Tray.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:SelfContained=true `
        -o $agentOut
    if ($LASTEXITCODE -ne 0) { throw "Agent Tray publish failed" }

    Write-Host ""
    Write-Host "[3/4] Publishing Dashboard (self-contained win-x64)..." -ForegroundColor Yellow
    $dashOut = Join-Path $Root "artifacts\dashboard-win-x64"
    if (Test-Path $dashOut) {
        Get-ChildItem $dashOut -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $dashOut | Out-Null
    dotnet publish (Join-Path $Root "src\NTShield.Dashboard\NTShield.Dashboard.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $dashOut
    if ($LASTEXITCODE -ne 0) { throw "Dashboard publish failed" }

    Copy-Item $ico $dashOut -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $dashOut "Assets") | Out-Null
    Copy-Item $ico (Join-Path $dashOut "Assets\") -Force
} else {
    Write-Host "[skip] Publish (using existing artifacts)" -ForegroundColor DarkYellow
}

$agentExe = Join-Path $Root "artifacts\agent-win-x64\NTShield.Agent.exe"
$dashExe = Join-Path $Root "artifacts\dashboard-win-x64\NTShield.Dashboard.exe"
$centralExe = Join-Path $Root "artifacts\server-win-x64\NTShield.Server.exe"
if (-not (Test-Path $agentExe)) { throw "Missing agent exe. Run without -SkipPublish." }
if (-not (Test-Path $dashExe)) { throw "Missing dashboard exe. Run without -SkipPublish." }
if (-not (Test-Path $centralExe)) { throw "Missing central exe. Run without -SkipPublish." }

Write-Host ""
Write-Host "[4/4] Compiling Full Setup.exe with Inno Setup..." -ForegroundColor Yellow
$iscc = Find-ISCC
if (-not $iscc) {
    throw "ISCC.exe not found. Install: winget install JRSoftware.InnoSetup"
}
Write-Host "  Using: $iscc"

$iss = Join-Path $Root "installer\NTShield.iss"
$outDir = Join-Path $Root "artifacts\setup"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$rootFwd = $Root -replace '\\', '/'
& $iscc "/DMyAppVersion=$Version" "/DSourceRoot=$rootFwd" $iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed (exit $LASTEXITCODE)" }

$setup = Get-ChildItem $outDir -Filter "NTShield-Setup-*.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $setup) { throw "Setup.exe was not produced in $outDir" }

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " SUCCESS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Installer: $($setup.FullName)"
Write-Host " Size     : $([math]::Round($setup.Length / 1MB, 1)) MB"
Write-Host ""
Write-Host " Full stack = Central + Agent + Dashboard"
Write-Host " Runtime    = self-contained (no .NET install required on target PC)"
Write-Host " Run as Administrator:"
Write-Host "   $($setup.FullName)"
Write-Host " Choose type: Full stack (recommended)"
Write-Host ""
