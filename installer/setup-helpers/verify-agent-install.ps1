#Requires -Version 3.0
# Post-install check: prove the NEW binary is what the service runs.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [string]$ServiceName = "NTShieldAgent",
    [string]$MinVersion = ""
)

$ErrorActionPreference = "Continue"
$exe = Join-Path $InstallDir "NTShield.Agent.exe"
Write-Host "=== verify-agent-install ==="
Write-Host "InstallDir=$InstallDir"

if (-not (Test-Path $exe)) {
    Write-Error "MISSING: $exe"
    exit 2
}

$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
$product = $vi.ProductVersion
if ($product -and $product.Contains("+")) { $product = $product.Split("+")[0] }
$fileVer = $vi.FileVersion
$write = (Get-Item $exe).LastWriteTime
Write-Host "EXE ProductVersion=$product FileVersion=$fileVer LastWrite=$write"

# Write VERSION.txt for support / tray display
$verTxt = @"
NT Shield Agent
ProductVersion=$product
FileVersion=$fileVer
InstallDir=$InstallDir
InstalledUtc=$((Get-Date).ToUniversalTime().ToString("o"))
"@
Set-Content -Path (Join-Path $InstallDir "VERSION.txt") -Value $verTxt -Encoding UTF8
Set-Content -Path "C:\ProgramData\NTShield\Agent\VERSION.txt" -Value $verTxt -Encoding UTF8 -Force

$wmi = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $wmi) {
    Write-Warning "Service $ServiceName not found yet"
    exit 0
}

$bin = ($wmi.PathName -replace '^"', '' -replace '"$', '')
Write-Host "Service PathName=$bin State=$($wmi.State)"

if ($bin -and -not ($bin.Equals($exe, [StringComparison]::OrdinalIgnoreCase))) {
    Write-Warning "Service points to DIFFERENT path than this install!"
    Write-Warning "  Service: $bin"
    Write-Warning "  Setup:   $exe"
    if (Test-Path $bin) {
        $svi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($bin)
        $sp = $svi.ProductVersion
        if ($sp -and $sp.Contains("+")) { $sp = $sp.Split("+")[0] }
        Write-Host "  Service EXE ProductVersion=$sp"
    }
}

if ($MinVersion) {
    try {
        $a = [version](($product -split '-')[0])
        $b = [version]$MinVersion
        if ($a -lt $b) {
            Write-Error "Installed product $product is older than required $MinVersion - file replace likely FAILED (file lock)."
            exit 3
        }
    } catch {
        Write-Warning "Could not compare versions: $_"
    }
}

Write-Host "OK: agent binary present ProductVersion=$product"
Write-Host "=== verify done ==="
exit 0
