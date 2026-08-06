#Requires -Version 3.0
# Called by NTShield-Setup.exe (Inno) after files are copied.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$ServiceName = "NTShieldAgent",
    [string]$DisplayName = "NT Shield Agent",
    [string]$StartService = "1",
    [string]$CentralUrl = "https://localhost:7443",
    [string]$EnrollmentToken = ""
)

$ErrorActionPreference = "Stop"
$LogDir = Join-Path $DataDir "logs"
$exe = Join-Path $InstallDir "NTShield.Agent.exe"

if (-not (Test-Path $exe)) {
    # Fallback: other common install roots (never register a missing path)
    $fallbacks = @(
        (Join-Path ${env:ProgramFiles} "NT Shield Agent\NTShield.Agent.exe"),
        (Join-Path ${env:ProgramFiles} "NT Shield\Agent\NTShield.Agent.exe")
    )
    foreach ($f in $fallbacks) {
        if (Test-Path $f) {
            Write-Warning "InstallDir missing Agent.exe — using fallback $f"
            $exe = $f
            $InstallDir = Split-Path -Parent $f
            break
        }
    }
}

if (-not (Test-Path $exe)) {
    throw "Agent executable not found: $exe  (refusing to register broken service path)"
}

# Report binary version being registered (this is what Dashboard will show after heartbeat)
$installedProduct = "?"
try {
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    $installedProduct = $vi.ProductVersion
    if ($installedProduct -and $installedProduct.Contains("+")) {
        $installedProduct = $installedProduct.Split("+")[0]
    }
    Write-Host "OK: binary ProductVersion=$installedProduct FileVersion=$($vi.FileVersion) Path=$exe"
} catch {
    Write-Warning "Could not read exe version: $_"
}

New-Item -ItemType Directory -Force -Path $DataDir, $LogDir, (Join-Path $DataDir "evidence") | Out-Null

# Force-stop old service + kill leftover processes (safe for in-place upgrade)
$ErrorActionPreference = "SilentlyContinue"
& sc.exe stop $ServiceName | Out-Null
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
foreach ($n in @("NTShield.Agent", "NTShield.Agent.Tray")) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
}
Start-Sleep -Milliseconds 500
$ErrorActionPreference = "Stop"

# Prefer shared connection.json when installer left localhost (common separate-install mistake)
$connPath = "C:\ProgramData\NTShield\connection.json"
if (Test-Path $connPath) {
    try {
        $conn = Get-Content $connPath -Raw | ConvertFrom-Json
        $isLocal = $CentralUrl -match 'localhost|127\.0\.0\.1'
        if ($isLocal -and $conn.RemoteUrl) {
            Write-Host "NOTE: CentralUrl was localhost — using connection.json RemoteUrl=$($conn.RemoteUrl)"
            # Keep localhost only if Central service is on this same machine
            $centralSvc = Get-Service -Name "NTShieldCentral" -ErrorAction SilentlyContinue
            if (-not $centralSvc) {
                $CentralUrl = [string]$conn.RemoteUrl
                Write-Host "OK: switched Agent to $CentralUrl (Central not on this PC)"
            }
        }
        if (-not $EnrollmentToken -and $conn.EnrollmentToken) {
            $EnrollmentToken = [string]$conn.EnrollmentToken
            Write-Host "OK: EnrollmentToken from connection.json"
        }
    } catch {
        Write-Warning "Could not read connection.json: $_"
    }
}

if ($CentralUrl -match 'localhost|127\.0\.0\.1') {
    Write-Warning "Agent CentralUrl is LOCALHOST. Remote Dashboard will not see this host unless Central runs on this PC."
}

# Patch appsettings if present
$appsettings = Join-Path $InstallDir "appsettings.json"
if (Test-Path $appsettings) {
    try {
        $json = Get-Content $appsettings -Raw | ConvertFrom-Json
        if (-not $json.Server) { $json | Add-Member -NotePropertyName Server -NotePropertyValue ([pscustomobject]@{}) -Force }
        $json.Server.Url = $CentralUrl
        # Self-signed Central cert — required for separate installs without a trusted cert
        $json.Server | Add-Member -NotePropertyName AllowUntrustedServerCertificate -NotePropertyValue $true -Force
        if ($EnrollmentToken) {
            $json.Server | Add-Member -NotePropertyName EnrollmentToken -NotePropertyValue $EnrollmentToken -Force
        }
        if (-not $json.Agent) { $json | Add-Member -NotePropertyName Agent -NotePropertyValue ([pscustomobject]@{}) -Force }
        $json.Agent.DataDirectory = $DataDir
        $json.Agent.ComputerName = $env:COMPUTERNAME
        $json.Agent.DetectOnly = $true
        # Keep appsettings Version in sync with binary (avoid stale 1.0.0/1.0.11 in files)
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
        Write-Host "OK: appsettings Server.Url=$CentralUrl AllowUntrusted=true"
    } catch {
        Write-Warning "Could not patch appsettings.json: $_"
    }
}

# Event source (Application log only - never clear Security log)
$source = "NTShieldAgent"
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
    -Description "NT Shield Endpoint Security Monitoring Agent" `
    -StartupType Automatic | Out-Null

# Automatic (not delayed) so status appears sooner after reboot
& sc.exe config $ServiceName start= auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# Always try to start unless explicitly disabled (StartService=0).
# Reinstalls with Inno checkedonce used to skip start and leave the service Stopped.
if ($StartService -ne "0") {
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $st = (Get-Service -Name $ServiceName).Status
        Write-Host "Agent service start: $st"
        if ($st -ne 'Running') {
            Write-Warning "Service not Running after start - retrying once..."
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
    Write-Host "StartService=0 - service left stopped"
}

# Persist version for support / tray (ProgramData + install dir)
try {
    $utc = (Get-Date).ToUniversalTime().ToString('o')
    $verLines = @(
        'NT Shield Agent'
        "ProductVersion=$installedProduct"
        "InstallDir=$InstallDir"
        "Service=$ServiceName"
        "CentralUrl=$CentralUrl"
        "RegisteredUtc=$utc"
    )
    Set-Content -Path (Join-Path $InstallDir "VERSION.txt") -Value $verLines -Encoding UTF8 -Force
    Set-Content -Path (Join-Path $DataDir "VERSION.txt") -Value $verLines -Encoding UTF8 -Force
} catch {
    Write-Warning "Could not write VERSION.txt: $_"
}

# If Full-stack Agent folder still has another binary, note it
$legacy = Join-Path $env:ProgramFiles "NT Shield\Agent\NTShield.Agent.exe"
if ((Test-Path $legacy) -and -not ($legacy.Equals($exe, [StringComparison]::OrdinalIgnoreCase))) {
    try {
        $lvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($legacy)
        $lp = $lvi.ProductVersion
        if ($lp -and $lp.Contains('+')) { $lp = $lp.Split('+')[0] }
        Write-Host "NOTE: leftover Full-stack Agent at $legacy (ProductVersion=$lp) - service uses $InstallDir ($installedProduct)"
    } catch { }
}

Write-Host "Agent service registered: $ServiceName ProductVersion=$installedProduct"
Write-Host "Central URL: $CentralUrl"
Write-Host "Binary: $exe"
