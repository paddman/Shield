#Requires -Version 3.0
# Called by NTShield-Central-Setup.exe after files are copied.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$ServiceName = "NTShieldCentral",
    [string]$DisplayName = "NT Shield Central",
    [string]$StartService = "1",
    [string]$Port = "7443",
    # Public / NAT IP or DNS for HTTPS cert SAN (e.g. 203.0.113.10)
    [string]$PublicHost = "",
    # 1 = import generated cert into LocalMachine\Root (browser trust on this host)
    [string]$TrustCertificate = "1",
    # 1 = delete existing central.pfx so Central recreates with new SANs
    [string]$RegenerateCertificate = "0"
)

$ErrorActionPreference = "Stop"
$LogDir = Join-Path $DataDir "logs"
$DbPath = Join-Path $DataDir "central.db"
$exe = Join-Path $InstallDir "NTShield.Server.exe"

if (-not (Test-Path $exe)) {
    throw "Central executable not found: $exe"
}

$SigDir = Join-Path $DataDir "signatures"
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir, (Join-Path $DataDir "certs"), $SigDir | Out-Null

# Open-source signature pack
$sigSrc = Join-Path $InstallDir "signatures\opensource-signatures.json"
if (-not (Test-Path $sigSrc)) {
    $sigSrc = Join-Path $InstallDir "opensource-signatures.json"
}
$sigDst = Join-Path $SigDir "opensource-signatures.json"
if (Test-Path $sigSrc) {
    Copy-Item $sigSrc $sigDst -Force
    Write-Host "OK: open-source signatures -> $sigDst"
}

# Force-stop old instance (in-place upgrade)
$ErrorActionPreference = "SilentlyContinue"
& sc.exe stop $ServiceName | Out-Null
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600
Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& taskkill.exe /F /IM "NTShield.Server.exe" /T 2>$null | Out-Null
Start-Sleep -Milliseconds 400
$ErrorActionPreference = "Stop"

$portNum = 7443
[void][int]::TryParse($Port, [ref]$portNum)
if ($portNum -lt 1 -or $portNum -gt 65535) { $portNum = 7443 }

# Pre-create secrets so separate Agent installs can enroll (also written to connection.json)
$secretsPath = Join-Path $DataDir "secrets.json"
$enrollToken = ""
$operatorKey = ""
if (Test-Path $secretsPath) {
    try {
        $sec = Get-Content $secretsPath -Raw | ConvertFrom-Json
        $enrollToken = [string]$sec.EnrollmentToken
        $operatorKey = [string]$sec.OperatorApiKey
    } catch { }
}
if (-not $enrollToken) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $b1 = New-Object byte[] 32
    $b2 = New-Object byte[] 32
    $rng.GetBytes($b1); $rng.GetBytes($b2)
    $enrollToken = ([BitConverter]::ToString($b1) -replace '-','').ToLowerInvariant()
    $operatorKey = ([BitConverter]::ToString($b2) -replace '-','').ToLowerInvariant()
    @{
        GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString("o")
        EnrollmentToken   = $enrollToken
        OperatorApiKey    = $operatorKey
        Note              = "Copy EnrollmentToken to Agents. Copy OperatorApiKey to Dashboard Settings."
    } | ConvertTo-Json | Set-Content $secretsPath -Encoding UTF8
    Write-Host "OK: generated secrets.json (Enrollment + Operator keys)"
}

# Detect public/LAN hosts for cert SAN + connection hints
$publicHostClean = ($PublicHost -replace '^\s+|\s+$', '')
if ($publicHostClean -match '^https?://') {
    try { $publicHostClean = ([Uri]$publicHostClean).Host } catch { }
}
if ($publicHostClean -match ':(\d+)$' -and $publicHostClean -notmatch '^\[[0-9a-fA-F:]+\]') {
    $publicHostClean = $publicHostClean -replace ':\d+$', ''
}

$allSans = New-Object System.Collections.Generic.List[string]
if ($publicHostClean) { [void]$allSans.Add($publicHostClean) }
try {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { if (-not $allSans.Contains($_.IPAddress)) { [void]$allSans.Add($_.IPAddress) } }
} catch { }

$extraSans = ($allSans -join ',')
$certPath = Join-Path $DataDir "certs\central.pfx"
$certDir = Join-Path $DataDir "certs"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

# Force cert recreate when PublicHost set or explicit flag (old certs only had localhost)
$regen = ($RegenerateCertificate -eq "1") -or ($publicHostClean -ne "")
if ($regen -and (Test-Path $certPath)) {
    $bak = "$certPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    try {
        Copy-Item $certPath $bak -Force
        Remove-Item $certPath -Force
        Write-Host "OK: removed old cert (backup $bak) — Central will issue new SAN cert"
    } catch {
        Write-Warning "Could not remove old cert: $_"
    }
}

# Write/patch appsettings for this install
$appsettings = Join-Path $InstallDir "appsettings.json"
$config = @{
    Kestrel      = @{ Port = $portNum }
    Security     = @{
        EnableMtls                  = $false
        RequireAuth                 = $false
        AutoGenerateSecretsOnBoot   = $true
        SecretsFilePath             = $secretsPath
        EnrollmentToken             = $enrollToken
        OperatorApiKey              = $operatorKey
        CertificatePath             = $certPath
        CertificatePassword         = "NTShield!"
        CertificateExtraSans        = $extraSans
        PublicHost                  = $publicHostClean
        RegenerateCertificate       = $false
    }
    Database     = @{ Provider = "Sqlite" }
    Sqlite       = @{ DatabasePath = $DbPath }
    Postgres     = @{
        ConnectionString = "Host=127.0.0.1;Port=5432;Database=ntshield;Username=ntshield;Password=ntshield"
    }
    Syslog       = @{
        Enabled                   = $true
        UdpPort                   = 5514
        TcpPort                   = 0
        MatchOpenSourceSignatures = $true
        SignaturesPath            = (Join-Path $DataDir "signatures\opensource-signatures.json")
    }
    Correlation  = @{ TimestampToleranceSeconds = 120 }
    LoggingPaths = @{ Directory = $LogDir }
    Serilog      = @{
        MinimumLevel = @{
            Default  = "Information"
            Override = @{ "Microsoft.AspNetCore" = "Warning" }
        }
    }
    AllowedHosts = "*"
}
$config | ConvertTo-Json -Depth 10 | Set-Content -Path $appsettings -Encoding UTF8
Write-Host "OK: appsettings.json Port=$portNum Sqlite=$DbPath"

# Event source
$source = "NTShieldCentral"
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    try { New-EventLog -LogName Application -Source $source } catch { }
}

# Recreate service
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$binPath = "`"$exe`""
New-Service -Name $ServiceName `
    -BinaryPathName $binPath `
    -DisplayName $DisplayName `
    -Description "NT Shield Central API - Agents and Dashboard connect here (port $portNum)" `
    -StartupType Automatic | Out-Null

# Automatic (not delayed) so Agent can connect soon after reboot
& sc.exe config $ServiceName start= auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# Content root env for ASP.NET (exe directory usually enough)
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$envVals = @(
    "ASPNETCORE_CONTENTROOT=$InstallDir",
    "DOTNET_CONTENTROOT=$InstallDir"
)
try {
    New-ItemProperty -Path $reg -Name "Environment" -PropertyType MultiString -Value $envVals -Force | Out-Null
} catch { }

if ($StartService -eq "1") {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 4
    $svc = Get-Service -Name $ServiceName
    Write-Host "Service $ServiceName : $($svc.Status)"

    # After first start, Central writes central.pfx + central.cer — optionally trust for browsers on this host
    if ($TrustCertificate -eq "1") {
        $cerPath = [System.IO.Path]::ChangeExtension($certPath, ".cer")
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path $cerPath) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        if (Test-Path $cerPath) {
            try {
                $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($certObj)
                $store.Close()
                Write-Host "OK: trusted HTTPS cert in LocalMachine\Root thumbprint=$($certObj.Thumbprint)"
            } catch {
                Write-Warning "Could not import cert to Trusted Root: $_"
            }
        } else {
            Write-Warning "central.cer not found yet — run Installer\regenerate-central-cert.ps1 later to trust"
        }
    }
}

# Always write CONNECTION.txt (desktop / Start Menu rely on this)
$hostName = $env:COMPUTERNAME
try { $hostName = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Name } catch { }
$centralVer = "?"
try {
    $exe = Join-Path $InstallDir "NTShield.Server.exe"
    if (Test-Path $exe) {
        $centralVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
        if (-not $centralVer) { $centralVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion }
    }
} catch { }
$lanIp = $null
try {
    $lanIp = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
} catch { }
$remoteHost = if ($publicHostClean) { $publicHostClean } elseif ($lanIp) { $lanIp } else { $hostName }

$hint = @"
NT Shield Central
=======================
Product      : NT Shield Central
Version      : $centralVer
URL (local)  : https://localhost:$portNum
URL (remote) : https://${remoteHost}:$portNum
Public host  : $(if ($publicHostClean) { $publicHostClean } else { '(set PublicHost for NAT/public IP SAN)' })
Cert SANs    : $extraSans
Cert PFX     : $certPath
Cert CER     : $([System.IO.Path]::ChangeExtension($certPath, '.cer'))
Syslog UDP   : 5514 (open-source signatures)
Signatures   : $DataDir\signatures\opensource-signatures.json
Service      : $ServiceName
Install dir  : $InstallDir
Data         : $DataDir
Database     : $DbPath (SQLite)
Secrets      : $secretsPath
Shared link  : C:\ProgramData\NTShield\connection.json

IMPORTANT — HTTPS / separate Agent installs:
  Do NOT use localhost on remote PCs.
  Agent Server.Url = https://${remoteHost}:$portNum
  EnrollmentToken  = (from secrets.json or connection.json)
  AllowUntrustedServerCertificate = true  (required for self-signed)
  Or import central.cer into Trusted Root on client machines.

Dashboard Settings URL = same as Agent Server.Url
Operator API Key       = OperatorApiKey from secrets.json

Health (skip cert check if self-signed):
  curl.exe -k https://${remoteHost}:$portNum/api/v1/health
  curl.exe -k https://localhost:$portNum/api/v1/health

Regenerate cert with public IP (Admin):
  powershell -File "$InstallDir\Installer\regenerate-central-cert.ps1" -PublicHost $remoteHost

Start / stop (Admin PowerShell):
  Start-Service $ServiceName
  Stop-Service $ServiceName
  Get-Service $ServiceName

Logs:
  $LogDir
"@
try {
    Set-Content -Path (Join-Path $InstallDir "CONNECTION.txt") -Value $hint -Encoding UTF8 -Force
    Set-Content -Path (Join-Path $DataDir "CONNECTION.txt") -Value $hint -Encoding UTF8 -Force
    Write-Host "OK: CONNECTION.txt written"
} catch {
    Write-Warning "Could not write CONNECTION.txt: $_"
}

# Shared file for separate Agent / Dashboard installs (same PC or copy to remote)
try {
    $writeConn = Join-Path $PSScriptRoot "write-connection-info.ps1"
    if (-not (Test-Path $writeConn)) {
        $writeConn = Join-Path $InstallDir "Installer\write-connection-info.ps1"
    }
    if (Test-Path $writeConn) {
        & $writeConn -CentralUrl "https://${remoteHost}:$portNum" -DataDir $DataDir -Port $portNum `
            -EnrollmentToken $enrollToken -OperatorApiKey $operatorKey
    }
} catch {
    Write-Warning "Could not write connection.json: $_"
}

Write-Host "Central service registered: $ServiceName on port $portNum"
Write-Host "Remote agents must use: https://${remoteHost}:$portNum  (not localhost)"
