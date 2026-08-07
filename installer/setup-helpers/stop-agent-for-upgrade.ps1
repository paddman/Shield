#Requires -Version 3.0
# Force-stop Agent service and kill tray/agent so in-place upgrade can overwrite files.
# Called by Setup BEFORE files are copied (PrepareToInstall).
#
# IMPORTANT: Only unlock the TARGET install dir and the service path if it is that dir.
# Never delete Full-stack Agent files when upgrading Agent-only (and vice versa).
param(
    [string]$ServiceName = "NTShieldAgent",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "=== NT Shield: stop for upgrade ==="

function Stop-NamedService([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    Write-Host "Stopping service $Name (status=$($svc.Status))..."
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch { }
    & sc.exe stop $Name | Out-Null
    $deadline = (Get-Date).AddSeconds(25)
    do {
        Start-Sleep -Milliseconds 400
        try { $svc.Refresh() } catch { break }
        if ($svc.Status -eq 'Stopped') { break }
    } while ((Get-Date) -lt $deadline)
    Write-Host "Service $Name status: $($svc.Status)"
}

function Kill-AgentProcs {
    foreach ($n in @("NTShield.Agent", "NTShield.Agent.Tray")) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Killing $($_.ProcessName) PID=$($_.Id)"
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
        & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
    }
}

function Unlock-MainBinaries([string]$Dir) {
    if (-not $Dir -or -not (Test-Path $Dir)) { return }
    Write-Host "Unlocking main binaries under: $Dir"

    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and ($_.Path.StartsWith($Dir, [StringComparison]::OrdinalIgnoreCase)) }
        catch { $false }
    } | ForEach-Object {
        Write-Host "Killing path-locked $($_.ProcessName) PID=$($_.Id)"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }

    # Only move or rename the primary locked executables; do not mass-delete every DLL.
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $mains = @(
        "NTShield.Agent.exe",
        "NTShield.Agent.Tray.exe",
        "NTShield.Agent.pdb",
        "NTShield.Agent.Tray.pdb"
    )
    foreach ($name in $mains) {
        $old = Join-Path $Dir $name
        if (-not (Test-Path $old)) { continue }
        $bak = "$old.upgrade_old_$stamp"
        try {
            Move-Item -LiteralPath $old -Destination $bak -Force -ErrorAction Stop
            Write-Host "Renamed $name -> $(Split-Path $bak -Leaf)"
        } catch {
            try {
                Remove-Item -LiteralPath $old -Force -ErrorAction Stop
                Write-Host "Removed $name"
            } catch {
                Write-Host "WARN: could not unlock $name : $($_.Exception.Message)"
            }
        }
    }
}

# 1) Stop service
Stop-NamedService -Name $ServiceName

# 2) Kill processes
Kill-AgentProcs
Start-Sleep -Milliseconds 500
Kill-AgentProcs

# 3) Unlock ONLY the destination of THIS setup
$target = $InstallDir
if (-not $target) {
    # Fallback: prefer service path if set
    try {
        $wmi = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($wmi -and $wmi.PathName) {
            $bin = ($wmi.PathName -replace '^"', '' -replace '"$', '')
            $target = Split-Path -Parent $bin
        }
    } catch { }
}

if ($target) {
    Unlock-MainBinaries -Dir $target
} else {
    Write-Host "No InstallDir - skipped file unlock (service stop + kill only)"
}

# If service binary path differs from target, do not delete that other tree.
# register-agent-service will repoint the service to the new InstallDir after copy.
try {
    $wmi = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($wmi -and $wmi.PathName) {
        $bin = ($wmi.PathName -replace '^"', '' -replace '"$', '')
        $svcDir = Split-Path -Parent $bin
        if ($svcDir -and $target -and -not $svcDir.Equals($target, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "NOTE: service currently points to $svcDir (will be re-registered to $target after copy)"
            Get-Process -ErrorAction SilentlyContinue | Where-Object {
                try { $_.Path -and ($_.Path.StartsWith($svcDir, [StringComparison]::OrdinalIgnoreCase)) }
                catch { $false }
            } | ForEach-Object {
                Write-Host "Killing stale-path $($_.ProcessName) PID=$($_.Id)"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
} catch { }

Kill-AgentProcs
Start-Sleep -Milliseconds 400
Write-Host "=== stop-for-upgrade done ==="
