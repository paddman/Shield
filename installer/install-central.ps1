#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NT Shield Central Server as a Windows Service (default SQLite, port 7443).

.EXAMPLE
  .\installer\install-central.ps1
  .\installer\install-central.ps1 -SourceDir .\artifacts\server-win-x64 -Port 7443
#>
[CmdletBinding()]
param(
    [string]$SourceDir = ".\artifacts\server-win-x64",
    [string]$InstallDir = "C:\Program Files\NT Shield Central",
    [string]$DataDir = "C:\ProgramData\NTShield\Server",
    [string]$ServiceName = "NTShieldCentral",
    [string]$DisplayName = "NT Shield Central",
    [int]$Port = 7443
)

$ErrorActionPreference = "Stop"
$env:Path = "C:\Program Files\dotnet;" + $env:Path

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "  OK: $m" -ForegroundColor Green }

$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "NTShield.sln"))) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

if (-not (Test-Path (Join-Path $SourceDir "NTShield.Server.exe"))) {
    Write-Step "Publishing Central Server..."
    $out = Join-Path $Root "artifacts\server-win-x64"
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    Push-Location $Root
    try {
        dotnet publish (Join-Path $Root "src\NTShield.Server\NTShield.Server.csproj") `
            -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o $out
        if ($LASTEXITCODE -ne 0) { throw "publish failed" }
        $SourceDir = $out
    } finally {
        Pop-Location
    }
}

$SourceDir = (Resolve-Path $SourceDir).Path
$exeSrc = Join-Path $SourceDir "NTShield.Server.exe"
if (-not (Test-Path $exeSrc)) { throw "Missing $exeSrc" }

Write-Step "Stopping existing Central if present"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep 1
    & sc.exe stop $ServiceName | Out-Null
    Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 1
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep 2
}
Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Step "Install files -> $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, (Join-Path $DataDir "logs") | Out-Null
Copy-Item -Path (Join-Path $SourceDir "*") -Destination $InstallDir -Recurse -Force

# Patch appsettings for this host
$appsettings = Join-Path $InstallDir "appsettings.json"
$json = @{
    Kestrel = @{ Port = $Port }
    Security = @{ EnableMtls = $false }
    Database = @{ Provider = "Sqlite" }
    Sqlite = @{ DatabasePath = (Join-Path $DataDir "central.db") }
    Postgres = @{
        ConnectionString = "Host=127.0.0.1;Port=5432;Database=ntshield;Username=ntshield;Password=ntshield"
    }
    Correlation = @{ TimestampToleranceSeconds = 120 }
    LoggingPaths = @{ Directory = (Join-Path $DataDir "logs") }
    Serilog = @{
        MinimumLevel = @{
            Default = "Information"
            Override = @{ "Microsoft.AspNetCore" = "Warning" }
        }
    }
    AllowedHosts = "*"
}
$json | ConvertTo-Json -Depth 8 | Set-Content $appsettings -Encoding UTF8

$exe = Join-Path $InstallDir "NTShield.Server.exe"
Write-Step "Register Windows Service $ServiceName"
# Use sc create with binPath; ASP.NET needs working directory = install dir
# Wrap with cmd /c cd /d ... && exe  OR set service AppDirectory via registry
New-Service -Name $ServiceName `
    -BinaryPathName "`"$exe`"" `
    -DisplayName $DisplayName `
    -Description "NT Shield Central API (agents + dashboard connect here)" `
    -StartupType Automatic | Out-Null

# Ensure service runs from install directory (appsettings + content root)
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
# Prefer delayed auto
& sc.exe config $ServiceName start= delayed-auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

# Set AppEnvironment / working directory via registry ImagePath + AppDirectory
# Windows Services don't use WorkingDirectory easily; set ASPNETCORE_CONTENTROOT
$envKey = Join-Path $reg "Environment"
if (-not (Test-Path $envKey)) { New-Item -Path $envKey -Force | Out-Null }
# Multi-string environment
$envVals = @(
    "ASPNETCORE_CONTENTROOT=$InstallDir",
    "DOTNET_CONTENTROOT=$InstallDir"
)
New-ItemProperty -Path $reg -Name "Environment" -PropertyType MultiString -Value $envVals -Force | Out-Null

Write-Step "Start service"
# Launch via nssm-style not available; start service and also set Application path
# Kestrel needs content root = InstallDir: use wrapper script
$wrapper = Join-Path $InstallDir "run-central.cmd"
@"
@echo off
cd /d "$InstallDir"
"$exe"
"@ | Set-Content $wrapper -Encoding ASCII

& sc.exe config $ServiceName binPath= "`"$wrapper`"" | Out-Null
# cmd as service is flaky; better: use powershell host or sc with quoted exe + AppDirectory
# Final approach: binary is Server.exe and we copy appsettings next to it; Content root defaults to exe directory for single-file/framework apps.
& sc.exe config $ServiceName binPath= "`"$exe`"" | Out-Null

Start-Service $ServiceName
Start-Sleep 4
$svc = Get-Service $ServiceName
Write-Ok "Service status: $($svc.Status)"

# Health check
Start-Sleep 2
add-type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class CertBypass { public static void Enable() {
  ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
  ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
}}
"@
[CertBypass]::Enable()
$url = "https://localhost:$Port/api/v1/health"
try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
    Write-Ok "Health $url => $($r.StatusCode) $($r.Content)"
} catch {
    Write-Host "WARNING: health check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Check logs: $(Join-Path $DataDir 'logs')" -ForegroundColor Yellow
    # Fallback: run interactively once if service failed
    if ($svc.Status -ne 'Running') {
        Write-Step "Service not running - starting process manually for diagnosis"
        Start-Process -FilePath $exe -WorkingDirectory $InstallDir -WindowStyle Hidden
        Start-Sleep 3
        try {
            $r2 = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
            Write-Ok "Manual start health => $($r2.StatusCode)"
        } catch {
            Write-Host "Manual health still failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Central installed." -ForegroundColor Green
Write-Host "  Service : $ServiceName"
Write-Host "  URL     : https://localhost:$Port"
Write-Host "  Install : $InstallDir"
Write-Host "  Data    : $DataDir"
Write-Host "  DB      : $(Join-Path $DataDir 'central.db') (SQLite)"
Write-Host ""
Write-Host "Agent appsettings Server.Url  = https://localhost:$Port"
Write-Host "Dashboard Settings URL        = https://localhost:$Port"
Write-Host ""
