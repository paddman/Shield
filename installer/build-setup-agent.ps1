#Requires -Version 3.0
<#
.SYNOPSIS
  Publish Agent + Tray and build NTShield-Agent-Setup-x.y.z.exe (Inno Setup).

.EXAMPLE
  .\installer\build-setup-agent.ps1
  .\installer\build-setup-agent.ps1 -SkipPublish
  .\installer\build-setup-agent.ps1 -Version 1.0.6
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish,
    [string]$Configuration = "Release",
    # Empty = auto from Directory.Build.props (must match Agent ProductVersion)
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "NTShield.sln"))) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location $Root
$env:Path = "C:\Program Files\dotnet;" + $env:Path

# Keep Setup filename version == assembly ProductVersion (avoid 1.0.20 setup shipping 1.0.16 binary)
if (-not $Version) {
    $props = Get-Content (Join-Path $Root "Directory.Build.props") -Raw
    if ($props -match '<Version>([^<]+)</Version>') {
        $Version = $Matches[1].Trim()
    } else {
        $Version = "1.0.0"
    }
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
Write-Host " NT Shield - Agent Setup.exe" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ico = Join-Path $Root "assets\icons\NTShield.ico"
if (-not (Test-Path $ico)) {
    throw "Missing icon: $ico"
}

$agentOut = Join-Path $Root "artifacts\agent-win-x64"

if (-not $SkipPublish) {
    Write-Host ""
    Write-Host "[1/3] Publishing Agent (self-contained win-x64)..." -ForegroundColor Yellow
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

    New-Item -ItemType Directory -Force -Path (Join-Path $agentOut "config") | Out-Null
    Copy-Item (Join-Path $Root "config\rules.json") (Join-Path $agentOut "config\") -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $Root "config\allowlist.json") (Join-Path $agentOut "config\") -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "[2/3] Publishing Agent Tray (system tray icon, self-contained)..." -ForegroundColor Yellow
    # Same folder as Agent so Setup packages one directory.
    # Self-contained so Server 2012+ works without desktop runtime install.
    dotnet publish (Join-Path $Root "src\NTShield.Agent.Tray\NTShield.Agent.Tray.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:SelfContained=true `
        -o $agentOut
    if ($LASTEXITCODE -ne 0) { throw "Agent Tray publish failed" }
    Copy-Item $ico $agentOut -Force
} else {
    Write-Host "[skip] Publish (using existing artifacts\agent-win-x64)" -ForegroundColor DarkYellow
}

$agentExe = Join-Path $agentOut "NTShield.Agent.exe"
$trayExe = Join-Path $agentOut "NTShield.Agent.Tray.exe"
if (-not (Test-Path $agentExe)) { throw "Missing agent exe. Run without -SkipPublish." }
if (-not (Test-Path $trayExe)) {
    Write-Host "Tray exe missing - publishing tray only..." -ForegroundColor Yellow
    dotnet publish (Join-Path $Root "src\NTShield.Agent.Tray\NTShield.Agent.Tray.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:SelfContained=true `
        -o $agentOut
    if ($LASTEXITCODE -ne 0) { throw "Agent Tray publish failed" }
    if (-not (Test-Path $trayExe)) { throw "Missing tray exe after publish." }
}

Write-Host ""
Write-Host "[3/3] Compiling Agent Setup.exe with Inno Setup..." -ForegroundColor Yellow
$iscc = Find-ISCC
if (-not $iscc) {
    throw "ISCC.exe not found. Install: winget install JRSoftware.InnoSetup"
}
Write-Host "  Using: $iscc"

$iss = Join-Path $Root "installer\NTShield-Agent.iss"
$outDir = Join-Path $Root "artifacts\setup"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$rootFwd = $Root -replace '\\', '/'
& $iscc "/DMyAppVersion=$Version" "/DSourceRoot=$rootFwd" $iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed (exit $LASTEXITCODE)" }

$setup = Get-ChildItem $outDir -Filter "NTShield-Agent-Setup-*.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $setup) { throw "Agent Setup.exe was not produced in $outDir" }

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " SUCCESS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Installer: $($setup.FullName)"
Write-Host " Size     : $([math]::Round($setup.Length / 1MB, 1)) MB"
Write-Host ""
Write-Host " Install (GUI - enter Central URL in wizard):"
Write-Host "   $($setup.FullName)"
Write-Host ""
Write-Host " Silent:"
Write-Host "   $($setup.FullName) /VERYSILENT /CentralUrl=https://10.0.0.5:7443"
Write-Host ""
Write-Host " Tray icon appears in the system tray (notification area)."
Write-Host " Dashboard: set Settings URL to the SAME Central address."
Write-Host ""
