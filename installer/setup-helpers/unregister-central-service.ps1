#Requires -Version 3.0
param(
    [string]$ServiceName = "NTShieldCentral"
)

$ErrorActionPreference = "SilentlyContinue"
& sc.exe stop $ServiceName | Out-Null
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Get-Process -Name "NTShield.Server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& taskkill.exe /F /IM "NTShield.Server.exe" /T 2>$null | Out-Null
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
Write-Host "Central service removed: $ServiceName"
