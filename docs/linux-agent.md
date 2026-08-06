# NT Shield — Linux Agent (full)

Self-contained **linux-x64** agent under systemd. Registers + heartbeats to Central, collects **host metrics** and **application logs**, ships events/alerts via ingest, and runs **allowlisted remediation** (Central actions or local auto-remediate).

## Capabilities

| Area | What |
|------|------|
| **CPU** | `/proc/stat` percent (idle-aware) |
| **RAM** | `/proc/meminfo` used % (MemAvailable) |
| **Disk** | Mount usage via `DriveInfo` (root + volumes) |
| **Network** | `/proc/net/dev` RX/TX bytes/sec |
| **Disk I/O** | `/proc/diskstats` read/write bytes/sec |
| **Load** | `/proc/loadavg` |
| **Logs** | nginx, Apache, PHP-FPM, Docker, Node/PM2, syslog, auth, MySQL, Postgres, Redis, Caddy, Traefik, fail2ban |
| **Detection** | Pattern rules (5xx, SQLi, webshell probes, OOM, SSH fails, disk full, …) |
| **Remediation** | systemctl restart/reload/stop, docker restart, kill PID, iptables block, journal vacuum, diagnostics |

> **Not** “run arbitrary shell as root.” All actions are on a fixed allowlist. Auto-remediate is limited to restarts / journal vacuum with cooldowns.

## Metrics on Central / Dashboard

Heartbeat fields:

- `CpuPercentEstimate` — host CPU %
- `WorkingSetBytes` — host memory **used** bytes (not only agent process)
- `Status` — e.g. `Healthy | cpu=12.3% mem=45.1% disk=/ 62.0% net_rx=… io_r=…`
- `Platform` = `linux`
- Local file: `/var/lib/ntshield/status.json` (or `./data/status.json`)

Threshold alerts (default 90% CPU / mem / disk) → Central ingest as `DetectionAlert`.

## Log paths

Configured in `appsettings.json` → `Linux:LogPaths` (globs supported). Defaults cover common distro layouts. Missing paths are skipped.

## Remediation actions (from Central)

`POST /api/v1/actions` with `TargetAgentId` = Linux agent id:

| ActionType | Params |
|------------|--------|
| `RestartService` / `StartService` / `StopService` / `ReloadService` | `ServiceName` (e.g. `nginx`, `php8.3-fpm`) |
| `ReloadNginx` | — |
| `RestartDockerContainer` / `DockerRestart` | `ServiceName` = container name |
| `TerminateProcess` | `ProcessId` |
| `BlockSourceIp` / `BlockDestinationIp` | `TargetIp` |
| `BlockPort` / `OpenPort` | `TargetPort`, optional `Protocol` |
| `VacuumJournal` | free journal space (disk pressure) |
| `CollectDiagnostics` | write diag file under `/var/log/ntshield` |
| `QuarantineHost` | restrictive iptables (keeps SSH 22) — use carefully |
| `LogOnly` | audit only |

Auto-remediate (`Linux:AutoRemediate: true`) may restart nginx/php-fpm/docker on matching critical log patterns (15‑minute cooldown per action).

## Install

```bash
tar -xzf NTShield-Linux-Agent-*-linux-x64.tar.gz
cd NTShield-Linux-Agent-*-linux-x64
sudo ./install-agent.sh --host <CENTRAL_IP> --port 7443
```

```bash
systemctl status ntshield-agent
journalctl -u ntshield-agent -f
cat /var/lib/ntshield/status.json
```

Agent needs **root** (or CAP_NET_ADMIN + service control) for iptables and `systemctl` remediation.

## Build (Windows host)

```powershell
cd C:\data_nt\NTShieldAgent
.\installer\build-agent-linux.ps1 -Version 1.0.12
```

## Config keys

| Key | Default |
|-----|---------|
| `Server:Url` | `https://localhost:7443` |
| `Server:HeartbeatIntervalSeconds` | 60 |
| `Linux:MetricsIntervalSeconds` | 30 |
| `Linux:LogScanIntervalSeconds` | 15 |
| `Linux:IngestIntervalSeconds` | 30 |
| `Linux:AutoRemediate` | true |
| `Linux:CpuAlertPercent` | 90 |
| `Linux:MemAlertPercent` | 90 |
| `Linux:DiskAlertPercent` | 90 |
