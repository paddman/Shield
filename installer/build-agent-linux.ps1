#Requires -Version 3.0
<#
.SYNOPSIS
  Publish Linux Agent (self-contained linux-x64) and pack install tarball.

.EXAMPLE
  .\installer\build-agent-linux.ps1
  .\installer\build-agent-linux.ps1 -Version 1.0.12
  .\installer\build-agent-linux.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish,
    [string]$Configuration = "Release",
    # Empty = auto from Directory.Build.props
    [string]$Version = "",
    [string]$Runtime = "linux-x64"
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
    else { $Version = "1.0.0" }
}

$publishDir = Join-Path $Root "artifacts\linux-agent"
$stageName = "NTShield-Linux-Agent-$Version-$Runtime"
$stageDir = Join-Path $Root "artifacts\linux-agent-stage\$stageName"
$setupDir = Join-Path $Root "artifacts\setup"
$tarball = Join-Path $setupDir "$stageName.tar.gz"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " NT Shield - Linux Agent package" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Version : $Version"
Write-Host " Runtime : $Runtime"

if (-not $SkipPublish) {
    Write-Host ""
    Write-Host "[1/2] Publishing Linux Agent ($Runtime self-contained)..." -ForegroundColor Yellow
    if (Test-Path $publishDir) {
        Remove-Item $publishDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

    $proj = Join-Path $Root "src\NTShield.Agent.Linux\NTShield.Agent.Linux.csproj"
    dotnet publish $proj `
        -c $Configuration `
        -r $Runtime `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:Version=$Version `
        -p:InformationalVersion=$Version `
        -o $publishDir
    if ($LASTEXITCODE -ne 0) { throw "Linux agent publish failed" }

    Copy-Item (Join-Path $Root "src\NTShield.Agent.Linux\appsettings.json") $publishDir -Force
    Copy-Item (Join-Path $Root "src\NTShield.Agent.Linux\ntshield-agent.service") $publishDir -Force
} else {
    Write-Host "[skip] Publish" -ForegroundColor DarkYellow
    if (-not (Test-Path (Join-Path $publishDir "NTShield.Agent.Linux")) -and
        -not (Test-Path (Join-Path $publishDir "NTShield.Agent.Linux.dll"))) {
        throw "Missing publish output in $publishDir"
    }
}

Write-Host ""
Write-Host "[2/2] Packing tarball + install scripts..." -ForegroundColor Yellow
if (Test-Path (Split-Path $stageDir)) {
    Remove-Item (Split-Path $stageDir) -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $stageDir, $setupDir | Out-Null

Copy-Item (Join-Path $publishDir "*") $stageDir -Recurse -Force
Copy-Item (Join-Path $Root "installer\linux\install-agent.sh") $stageDir -Force
Copy-Item (Join-Path $Root "installer\linux\uninstall-agent.sh") $stageDir -Force
Copy-Item (Join-Path $Root "installer\linux\set-central-url.sh") $stageDir -Force
Copy-Item (Join-Path $Root "installer\linux\README.md") $stageDir -Force

# Normalize line endings for shell scripts (LF)
foreach ($sh in @("install-agent.sh", "uninstall-agent.sh", "set-central-url.sh")) {
    $p = Join-Path $stageDir $sh
    if (Test-Path $p) {
        $t = [IO.File]::ReadAllText($p) -replace "`r`n", "`n" -replace "`r", "`n"
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllText($p, $t, $utf8NoBom)
    }
}

# Create tar.gz (prefer tar.exe on Windows 10+)
$parent = Split-Path $stageDir
$leaf = Split-Path $stageDir -Leaf
if (Test-Path $tarball) { Remove-Item $tarball -Force }

$tar = Get-Command tar.exe -ErrorAction SilentlyContinue
if ($tar) {
    Push-Location $parent
    try {
        & tar.exe -czf $tarball $leaf
        if ($LASTEXITCODE -ne 0) { throw "tar failed" }
    } finally {
        Pop-Location
    }
} else {
    # Fallback zip if tar missing
    $zip = Join-Path $setupDir "$stageName.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path $stageDir -DestinationPath $zip -Force
    $tarball = $zip
}

$sizeMb = [math]::Round((Get-Item $tarball).Length / 1MB, 1)
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " SUCCESS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Package : $tarball"
Write-Host " Size    : $sizeMb MB"
Write-Host ""
Write-Host " On Linux:"
Write-Host "   tar -xzf $(Split-Path $tarball -Leaf)"
Write-Host "   cd $stageName"
Write-Host "   sudo ./install-agent.sh --host <CENTRAL_IP> --port 7443"
Write-Host ""
