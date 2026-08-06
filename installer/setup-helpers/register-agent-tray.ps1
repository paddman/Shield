#Requires -Version 3.0
<#
.SYNOPSIS
  Register Agent system-tray companion and start it now.
#>
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [string]$StartNow = "1",
    [string]$RunAtLogon = "1"
)

$ErrorActionPreference = "Stop"

$exe = Join-Path $InstallDir "NTShield.Agent.Tray.exe"
if (-not (Test-Path $exe)) {
    $alt = Get-ChildItem -Path $InstallDir -Filter "NTShield.Agent.Tray.exe" -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if ($alt) { $exe = $alt }
}

if (-not (Test-Path $exe)) {
    Write-Warning "Tray exe not found under $InstallDir - skip tray registration."
    return
}

$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$valueName = "NTShieldAgentTray"
$cmd = '"' + $exe + '" --install-dir "' + $InstallDir + '"'

if ($RunAtLogon -eq "1") {
    try {
        if (-not (Test-Path $runKey)) {
            New-Item -Path $runKey -Force | Out-Null
        }
        Set-ItemProperty -Path $runKey -Name $valueName -Value $cmd -Type String -Force
        Write-Host "OK: Run at logon registered ($valueName)"
    } catch {
        $cu = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $cu -Name $valueName -Value $cmd -Type String -Force
        Write-Host "OK: Run at logon registered for current user"
    }
}

try {
    $startup = [Environment]::GetFolderPath("CommonStartup")
    if (-not $startup) {
        $startup = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"
    }
    if (Test-Path $startup) {
        $lnkPath = Join-Path $startup "NT Shield Agent Tray.lnk"
        $w = New-Object -ComObject WScript.Shell
        $s = $w.CreateShortcut($lnkPath)
        $s.TargetPath = $exe
        $s.Arguments = '--install-dir "' + $InstallDir + '"'
        $s.WorkingDirectory = $InstallDir
        $s.WindowStyle = 7
        $s.Description = "NT Shield Agent system tray icon"
        $ico = Join-Path $InstallDir "NTShield.ico"
        if (Test-Path $ico) { $s.IconLocation = $ico }
        $s.Save()
        Write-Host "OK: Startup shortcut: $lnkPath"
    }
} catch {
    Write-Warning "Could not create Startup shortcut: $_"
}

# Kill old tray instances so we always show a fresh icon
Get-Process -Name "NTShield.Agent.Tray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

if ($StartNow -eq "1") {
    try {
        Start-Process -FilePath $exe -ArgumentList @("--install-dir", $InstallDir) -WorkingDirectory $InstallDir -WindowStyle Hidden
        Write-Host "OK: Tray process started"
    } catch {
        Write-Warning "Could not start tray: $($_.Exception.Message)"
    }
}
