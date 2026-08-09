#Requires -Version 3.0
# Called by NTShield-Central-Setup.exe after files are copied.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$ServiceName = "NTShieldCentral",
    [string]$DisplayName = "NT Shield Central",
    [string]$StartService = "1",
    [string]$Port = "7443",
    # Public / NAT IP or DNS for HTTPS cert SAN (e.g. shield.example.go.th)
    [string]$PublicHost = "",
    # 1 = import generated public cert into LocalMachine\Root on this host
    [string]$TrustCertificate = "1",
    # 1 = intentionally rotate the existing Central HTTPS certificate
    [string]$RegenerateCertificate = "0"
)

$ErrorActionPreference = "Stop"
$LogDir = Join-Path $DataDir "logs"
$DbPath = Join-Path $DataDir "central.db"
$exe = Join-Path $InstallDir "NTShield.Server.exe"

function Protect-SecretFile([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { return }
    try {
        # LocalSystem SID and built-in Administrators SID; locale-independent.
        & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
        Write-Host "OK: restricted ACL -> $Path"
    } catch {
        throw "Could not secure ACL on $Path : $_"
    }
}

function Protect-PrivateCertificate([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { return }
    try {
        & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
        Write-Host "OK: restricted certificate ACL -> $Path"
    } catch {
        throw "Could not secure certificate ACL on $Path : $_"
    }
}

if (-not (Test-Path $exe -PathType Leaf)) {
    throw "Central executable not found: $exe"
}

$SigDir = Join-Path $DataDir "signatures"
$CertDir = Join-Path $DataDir "certs"
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir, $CertDir, $SigDir | Out-Null

# Open-source signature pack
$sigSrc = Join-Path $InstallDir "signatures\opensource-signatures.json"
if (-not (Test-Path $sigSrc)) { $sigSrc = Join-Path $InstallDir "opensource-signatures.json" }
$sigDst = Join-Path $SigDir "opensource-signatures.json"
if (Test-Path $sigSrc -PathType Leaf) {
    Copy-Item $sigSrc $sigDst -Force
    Write-Host "OK: open-source signatures -> $sigDst"
}

# Force-stop old instance for in-place upgrade.
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

# Detect public/LAN hosts for certificate SAN and public connection metadata.
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

$certPath = Join-Path $CertDir "central.pfx"
$cerPath = [System.IO.Path]::ChangeExtension($certPath, ".cer")
$secretsPath = Join-Path $DataDir "secrets.json"

# Preserve a custom existing certificate password, but migrate the historic
# repository-wide password by rotating the certificate once.
$existingPassword = ""
$oldAppsettings = Join-Path $InstallDir "appsettings.json"
if (Test-Path $oldAppsettings -PathType Leaf) {
    try {
        $oldConfig = Get-Content $oldAppsettings -Raw | ConvertFrom-Json
        if ($oldConfig.Security -and $oldConfig.Security.CertificatePassword) {
            $existingPassword = [string]$oldConfig.Security.CertificatePassword
        }
    } catch { }
}

$certificatePassword = $existingPassword
$regen = ($RegenerateCertificate -eq "1") -or ($publicHostClean -ne "")
if ($certificatePassword -eq "NTShield!") {
    Write-Warning "Migrating the legacy shared PFX password by rotating central.pfx. Remote clients must trust the newly exported central.cer."
    $certificatePassword = ""
    $regen = $true
}

if ($regen -and (Test-Path $certPath -PathType Leaf)) {
    $backup = "$certPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item $certPath $backup -Force
    Remove-Item $certPath -Force
    if (Test-Path $cerPath) { Remove-Item $cerPath -Force }
    Write-Host "OK: existing certificate backed up to $backup; Central will issue a new SAN certificate"
}

# Do not put EnrollmentToken, OperatorApiKey, private action-signing key or other
# credentials into appsettings.json. SecretBootstrapper generates/loads them only
# from the protected server-side secrets.json file.
$appsettings = Join-Path $InstallDir "appsettings.json"
$config = @{
    Kestrel      = @{ Port = $portNum }
    Security     = @{
        EnableMtls                        = $false
        RequireAuth                       = $true
        AllowLegacyAnonymousAgentIngest   = $false
        AutoGenerateSecretsOnBoot         = $true
        SecretsFilePath                   = $secretsPath
        EnrollmentToken                   = ""
        OperatorApiKey                    = ""
        CertificatePath                   = $certPath
        CertificatePassword               = $certificatePassword
        CertificateExtraSans              = $extraSans
        PublicHost                        = $publicHostClean
        RegenerateCertificate             = $false
        RequireSignedAgent                = $false
        ApprovedAgentSha256                = @()
        ActionSigningPrivateKeyPem         = ""
        ActionSigningPublicKeyPem          = ""
        ActionSigningKeyId                 = ""
        ActionLifetimeMinutes              = 5
        MaxActionLifetimeMinutes           = 15
    }
    LLMGateway   = @{
        Enabled                  = $true
        BaseUrl                  = "http://127.0.0.1:8000/v1"
        ApiKey                   = ""
        Model                    = ""
        SkipTlsVerify            = $false
        TimeoutSeconds           = 120
        DefaultTokenLifetimeDays = 90
        MaxTokenLifetimeDays     = 3650
    }
    Database     = @{ Provider = "Sqlite" }
    Sqlite       = @{ DatabasePath = $DbPath }
    Postgres     = @{
        ConnectionString = "Host=127.0.0.1;Port=5432;Database=ntshield;Username=ntshield;Password=CHANGE_ME"
    }
    Syslog       = @{
        Enabled                   = $true
        UdpPort                   = 5514
        TcpPort                   = 0
        MatchOpenSourceSignatures = $true
        SignaturesPath            = $sigDst
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
$config | ConvertTo-Json -Depth 12 | Set-Content -Path $appsettings -Encoding UTF8
Write-Host "OK: hardened appsettings.json Port=$portNum RequireAuth=true Sqlite=$DbPath"

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
    -Description "NT Shield Central API - authenticated Agent and Operator control plane (port $portNum)" `
    -StartupType Automatic | Out-Null

& sc.exe config $ServiceName start= auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

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
    $service = Get-Service -Name $ServiceName
    Write-Host "Service $ServiceName : $($service.Status)"
    if ($service.Status -ne "Running") {
        throw "Central service did not reach Running state. Check $LogDir"
    }

    # Wait for Central to generate the complete secret set and public certificate.
    $deadline = (Get-Date).AddSeconds(30)
    while ((-not (Test-Path $secretsPath -PathType Leaf) -or -not (Test-Path $cerPath -PathType Leaf)) -and
           (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }

    if (-not (Test-Path $secretsPath -PathType Leaf)) {
        throw "Central did not create protected secrets.json. Refusing an apparently open or incomplete installation."
    }
    Protect-SecretFile $secretsPath
    if (Test-Path $certPath -PathType Leaf) { Protect-PrivateCertificate $certPath }

    # Verify the P0 bootstrap material exists without printing any secret value.
    try {
        $secrets = Get-Content $secretsPath -Raw | ConvertFrom-Json
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($name in @(
            "EnrollmentToken",
            "OperatorApiKey",
            "ActionSigningPrivateKeyPem",
            "ActionSigningPublicKeyPem",
            "ActionSigningKeyId"
        )) {
            if (-not $secrets.$name) { [void]$missing.Add($name) }
        }
        if ($missing.Count -gt 0) {
            throw "Missing bootstrap fields: $($missing -join ', ')"
        }
        Write-Host "OK: enrollment, operator and action-signing secrets generated in protected storage"
    } catch {
        throw "Central secrets validation failed: $_"
    }

    if ($TrustCertificate -eq "1") {
        if (Test-Path $cerPath -PathType Leaf) {
            try {
                $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($certObj)
                $store.Close()
                Write-Host "OK: trusted Central certificate on this host thumbprint=$($certObj.Thumbprint)"
            } catch {
                Write-Warning "Could not import central.cer into LocalMachine\Root: $_"
            }
        } else {
            Write-Warning "central.cer was not exported. Remote Agents must receive another trusted certificate before enrollment."
        }
    }
}

$hostName = $env:COMPUTERNAME
try { $hostName = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Name } catch { }
$centralVer = "?"
try {
    $centralVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
    if (-not $centralVer) { $centralVer = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion }
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
Public host  : $(if ($publicHostClean) { $publicHostClean } else { '(set PublicHost for DNS/NAT certificate SAN)' })
Cert SANs    : $extraSans
Cert PFX     : $certPath  (private; SYSTEM/Administrators only)
Cert CER     : $cerPath   (public; distribute to Agents when not using public PKI)
Syslog UDP   : 5514
Service      : $ServiceName
Install dir  : $InstallDir
Data         : $DataDir
Database     : $DbPath (SQLite lab/small deployment)
Secrets      : $secretsPath  (SYSTEM/Administrators only)
Metadata     : C:\ProgramData\NTShield\connection.json  (contains no credentials)

SECURE AGENT PROVISIONING:
  1. Use https://${remoteHost}:$portNum, never localhost from another PC.
  2. Trust $cerPath on the Agent or pass it as CaCertificatePath.
  3. Read EnrollmentToken from protected secrets.json as Administrator.
  4. After enrollment the Agent stores a per-agent key and removes its enrollment token.
  5. Never set AllowUntrustedServerCertificate=true outside an isolated migration lab.

CONTROL CENTER:
  URL              = https://${remoteHost}:$portNum
  Operator API Key = read OperatorApiKey from protected secrets.json

Health with trusted certificate:
  curl.exe --cacert "$cerPath" https://${remoteHost}:$portNum/api/v1/health

Start / stop (Administrator PowerShell):
  Start-Service $ServiceName
  Stop-Service $ServiceName
  Get-Service $ServiceName

Logs:
  $LogDir
"@
try {
    Set-Content -Path (Join-Path $InstallDir "CONNECTION.txt") -Value $hint -Encoding UTF8 -Force
    Set-Content -Path (Join-Path $DataDir "CONNECTION.txt") -Value $hint -Encoding UTF8 -Force
    Write-Host "OK: CONNECTION.txt written without credentials"
} catch {
    Write-Warning "Could not write CONNECTION.txt: $_"
}

# Public discovery metadata only. Credentials remain in protected secrets.json.
try {
    $writeConn = Join-Path $PSScriptRoot "write-connection-info.ps1"
    if (-not (Test-Path $writeConn)) {
        $writeConn = Join-Path $InstallDir "Installer\write-connection-info.ps1"
    }
    if (Test-Path $writeConn) {
        & $writeConn -CentralUrl "https://${remoteHost}:$portNum" -DataDir $DataDir -Port $portNum `
            -CaCertificatePath $(if (Test-Path $cerPath -PathType Leaf) { $cerPath } else { "" })
    }
} catch {
    Write-Warning "Could not write public connection metadata: $_"
}

Write-Host "Central service registered: $ServiceName on port $portNum"
Write-Host "RequireAuth=true; anonymous operator/action APIs are disabled"
Write-Host "Remote Agents must use https://${remoteHost}:$portNum with a trusted certificate"
