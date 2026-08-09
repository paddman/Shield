#Requires -Version 3.0
# Called by NTShield-Setup.exe after files are copied.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$ServiceName = "NTShieldAgent",
    [string]$DisplayName = "NT Shield Agent",
    [string]$StartService = "1",
    [string]$CentralUrl = "https://localhost:7443",
    [string]$EnrollmentToken = "",
    [string]$CaCertificatePath = "",
    [string]$AllowUntrustedServerCertificate = "0"
)

$ErrorActionPreference = "Stop"
$LogDir = Join-Path $DataDir "logs"
$exe = Join-Path $InstallDir "NTShield.Agent.exe"
$allowUntrusted = $AllowUntrustedServerCertificate -match '^(1|true|yes|y)$'

function Copy-TrustedCa([string]$SourcePath) {
    if (-not $SourcePath) { return "" }
    $expanded = [Environment]::ExpandEnvironmentVariables($SourcePath)
    if (-not (Test-Path $expanded -PathType Leaf)) {
        throw "CA certificate not found: $expanded"
    }
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $extension = [IO.Path]::GetExtension($expanded)
    if (-not $extension) { $extension = ".cer" }
    $destination = Join-Path $DataDir ("central-ca" + $extension.ToLowerInvariant())
    $sourceFull = (Resolve-Path $expanded).Path
    $destinationFull = [IO.Path]::GetFullPath($destination)
    if (-not $sourceFull.Equals($destinationFull, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -Path $sourceFull -Destination $destinationFull -Force
    }
    return $destinationFull
}

if (-not (Test-Path $exe)) {
    $fallbacks = @(
        (Join-Path ${env:ProgramFiles} "NT Shield Agent\NTShield.Agent.exe"),
        (Join-Path ${env:ProgramFiles} "NT Shield\Agent\NTShield.Agent.exe")
    )
    foreach ($fallback in $fallbacks) {
        if (Test-Path $fallback) {
            Write-Warning "InstallDir missing Agent.exe; using fallback $fallback"
            $exe = $fallback
            $InstallDir = Split-Path -Parent $fallback
            break
        }
    }
}

if (-not (Test-Path $exe)) {
    throw "Agent executable not found: $exe (refusing to register broken service path)"
}

$installedProduct = "?"
try {
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    $installedProduct = $versionInfo.ProductVersion
    if ($installedProduct -and $installedProduct.Contains("+")) {
        $installedProduct = $installedProduct.Split("+")[0]
    }
    Write-Host "OK: binary ProductVersion=$installedProduct FileVersion=$($versionInfo.FileVersion) Path=$exe"
} catch {
    Write-Warning "Could not read exe version: $_"
}

New-Item -ItemType Directory -Force -Path $DataDir, $LogDir, (Join-Path $DataDir "evidence") | Out-Null

$ErrorActionPreference = "SilentlyContinue"
& sc.exe stop $ServiceName | Out-Null
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
foreach ($name in @("NTShield.Agent", "NTShield.Agent.Tray")) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & taskkill.exe /F /IM "$name.exe" /T 2>$null | Out-Null
}
Start-Sleep -Milliseconds 500
$ErrorActionPreference = "Stop"

# connection.json contains public discovery metadata only.
$connectionPath = "C:\ProgramData\NTShield\connection.json"
if (Test-Path $connectionPath) {
    try {
        $connection = Get-Content $connectionPath -Raw | ConvertFrom-Json
        $isLocal = $CentralUrl -match 'localhost|127\.0\.0\.1'
        if ($isLocal -and $connection.RemoteUrl) {
            $centralService = Get-Service -Name "NTShieldCentral" -ErrorAction SilentlyContinue
            if (-not $centralService) {
                $CentralUrl = [string]$connection.RemoteUrl
                Write-Host "OK: switched Agent to public metadata RemoteUrl=$CentralUrl"
            }
        }
        if (-not $CaCertificatePath -and $connection.CaCertificatePath -and
            (Test-Path ([string]$connection.CaCertificatePath) -PathType Leaf)) {
            $CaCertificatePath = [string]$connection.CaCertificatePath
        }
    } catch {
        Write-Warning "Could not read public connection metadata: $_"
    }
}

# Local full-stack install may read protected Central secrets as Administrator.
if (-not $EnrollmentToken) {
    $localSecrets = "C:\ProgramData\NTShield\Server\secrets.json"
    if (Test-Path $localSecrets -PathType Leaf) {
        try {
            $secrets = Get-Content $localSecrets -Raw | ConvertFrom-Json
            if ($secrets.EnrollmentToken) {
                $EnrollmentToken = [string]$secrets.EnrollmentToken
                Write-Host "OK: EnrollmentToken loaded from protected local Central secrets"
            }
        } catch {
            Write-Warning "Could not read local Central secrets: $_"
        }
    }
}

if ($CentralUrl -notmatch '^https://') {
    throw "CentralUrl must use HTTPS. Refusing insecure Agent registration URL: $CentralUrl"
}
if ($CentralUrl -match 'localhost|127\.0\.0\.1') {
    Write-Warning "Agent CentralUrl is localhost. Remote Dashboard will not see this host unless Central runs on this PC."
}

$trustedCa = ""
if ($CaCertificatePath) {
    $trustedCa = Copy-TrustedCa $CaCertificatePath
}

$appsettings = Join-Path $InstallDir "appsettings.json"
if (Test-Path $appsettings) {
    try {
        $json = Get-Content $appsettings -Raw | ConvertFrom-Json
        if (-not $json.Server) {
            $json | Add-Member -NotePropertyName Server -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $json.Server | Add-Member -NotePropertyName Url -NotePropertyValue $CentralUrl -Force
        $json.Server | Add-Member -NotePropertyName AllowUntrustedServerCertificate -NotePropertyValue ([bool]$allowUntrusted) -Force
        $json.Server | Add-Member -NotePropertyName CaCertificatePath -NotePropertyValue $trustedCa -Force
        if ($EnrollmentToken) {
            $json.Server | Add-Member -NotePropertyName EnrollmentToken -NotePropertyValue $EnrollmentToken -Force
        }

        if (-not $json.Agent) {
            $json | Add-Member -NotePropertyName Agent -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $json.Agent | Add-Member -NotePropertyName DataDirectory -NotePropertyValue $DataDir -Force
        $json.Agent | Add-Member -NotePropertyName ComputerName -NotePropertyValue $env:COMPUTERNAME -Force
        $json.Agent | Add-Member -NotePropertyName DetectOnly -NotePropertyValue $true -Force
        if ($installedProduct -and $installedProduct -ne "?") {
            $json.Agent | Add-Member -NotePropertyName Version -NotePropertyValue $installedProduct -Force
        }
        if ($json.LoggingPaths) { $json.LoggingPaths.Directory = $LogDir }
        if ($json.Response) {
            $json.Response.DetectOnly = $true
            $json.Response.LogOnlyMode = $true
            $json.Response.EvidenceDirectory = (Join-Path $DataDir "evidence")
        }
        $json | ConvertTo-Json -Depth 12 | Set-Content $appsettings -Encoding UTF8
        Write-Host "OK: appsettings Server.Url=$CentralUrl"
        if ($allowUntrusted) {
            Write-Warning "TLS validation disabled by explicit installer argument. ISOLATED LAB ONLY."
        } elseif ($trustedCa) {
            Write-Host "OK: TLS custom CA=$trustedCa"
        } else {
            Write-Host "OK: TLS uses Windows certificate trust store"
        }
    } catch {
        throw "Could not securely patch appsettings.json: $_"
    }
}

$source = "NTShieldAgent"
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    try { New-EventLog -LogName Application -Source $source } catch { }
}

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
    -Description "NT Shield Endpoint Security Monitoring Agent" `
    -StartupType Automatic | Out-Null

& sc.exe config $ServiceName start= auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

if ($StartService -ne "0") {
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $status = (Get-Service -Name $ServiceName).Status
        Write-Host "Agent service start: $status"
        if ($status -ne 'Running') {
            Write-Warning "Service not Running after start; retrying once"
            Start-Sleep -Seconds 2
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Write-Host ("Agent service status: {0}" -f (Get-Service -Name $ServiceName).Status)
        }
    } catch {
        Write-Warning "Start-Service failed: $_ Check Event Viewer / $LogDir"
        try {
            & sc.exe start $ServiceName | Out-Null
            Start-Sleep -Seconds 2
            Write-Host ("sc start fallback status: {0}" -f (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status)
        } catch { }
    }
} else {
    Write-Host "StartService=0; service left stopped"
}

try {
    $utc = (Get-Date).ToUniversalTime().ToString('o')
    $versionLines = @(
        'NT Shield Agent'
        "ProductVersion=$installedProduct"
        "InstallDir=$InstallDir"
        "Service=$ServiceName"
        "CentralUrl=$CentralUrl"
        "RegisteredUtc=$utc"
    )
    Set-Content -Path (Join-Path $InstallDir "VERSION.txt") -Value $versionLines -Encoding UTF8 -Force
    Set-Content -Path (Join-Path $DataDir "VERSION.txt") -Value $versionLines -Encoding UTF8 -Force
} catch {
    Write-Warning "Could not write VERSION.txt: $_"
}

$legacy = Join-Path $env:ProgramFiles "NT Shield\Agent\NTShield.Agent.exe"
if ((Test-Path $legacy) -and -not ($legacy.Equals($exe, [StringComparison]::OrdinalIgnoreCase))) {
    try {
        $legacyInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($legacy)
        $legacyProduct = $legacyInfo.ProductVersion
        if ($legacyProduct -and $legacyProduct.Contains('+')) { $legacyProduct = $legacyProduct.Split('+')[0] }
        Write-Host "NOTE: leftover Full-stack Agent at $legacy (ProductVersion=$legacyProduct); service uses $InstallDir ($installedProduct)"
    } catch { }
}

Write-Host "Agent service registered: $ServiceName ProductVersion=$installedProduct"
Write-Host "Central URL: $CentralUrl"
Write-Host "Binary: $exe"
