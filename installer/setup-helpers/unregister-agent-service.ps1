param(
    [string]$ServiceName = "NTShieldAgent"
)

$ErrorActionPreference = "SilentlyContinue"
& sc.exe stop $ServiceName | Out-Null
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
foreach ($n in @("NTShield.Agent", "NTShield.Agent.Tray")) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
}
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
Write-Host "Service removed: $ServiceName"
