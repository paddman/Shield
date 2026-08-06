#Requires -Version 3.0
# Stop Central service + kill process so in-place upgrade can overwrite files.
param(
    [string]$ServiceName = "NTShieldCentral",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "=== NT Shield Central: stop for upgrade ==="

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Stopping service $ServiceName..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe stop $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        $svc.Refresh()
        if ($svc.Status -eq 'Stopped') { break }
    } while ((Get-Date) -lt $deadline)
    Write-Host "Service status: $($svc.Status)"
}

Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Killing $($_.ProcessName) PID=$($_.Id)"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
& taskkill.exe /F /IM "NTShield.Server.exe" /T 2>$null | Out-Null

if ($InstallDir -and (Test-Path $InstallDir)) {
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
    } | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Milliseconds 600
Write-Host "=== stop-central done ==="
