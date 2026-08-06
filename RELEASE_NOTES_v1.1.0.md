# NT Shield v1.1.0

Release date: 2026-07-29

## Packages

| Package | File |
|---------|------|
| Full stack | `NTShield-Setup-1.1.0.exe` |
| Agent only | `NTShield-Agent-Setup-1.1.0.exe` |
| Central only | `NTShield-Central-Setup-1.1.0.exe` |
| Linux Agent | `NTShield-Linux-Agent-1.1.0-linux-x64.tar.gz` |

Build artifacts (local): `artifacts/setup/` (not committed; build with `installer/rebuild-all-setups.ps1`).

## Highlights

### HTTPS / Central
- Self-signed cert SANs include **all local NIC IPs** + optional **PublicHost** (e.g. NAT/public IP).
- Installer wizard field: Public Host/IP; silent: `/PublicHost=203.0.113.10`.
- Auto-regenerate cert when SANs are incomplete (old localhost-only certs).
- Export `central.cer`; optional trust into LocalMachine\Root.
- Helper: `Installer/regenerate-central-cert.ps1 -PublicHost <ip>`.

### Agent install / upgrade reliability
- Stop-for-upgrade **no longer wipes both Full-stack and Agent-only trees** (fixed missing exe / service start failure).
- Service refuses to register when binary is missing; falls back to known install paths.
- Post-install **verify-agent-install.ps1** + `VERSION.txt`.
- Setup version always matches product version from `Directory.Build.props`.
- Agent Production defaults: `AllowUntrustedServerCertificate=true`, `EnableMtls=false` (lab).

### Agent tray
- Install / repair service path when binary missing (UAC).
- Start/Stop/Restart + service control form.
- Edit Central IP/Port with self-signed option.

### Metrics & ops
- Windows host metrics: CPU, memory, disk I/O, Net RX/TX.
- Dashboard fleet detail + metrics history.
- Remote service control (allowlisted) from Dashboard and tray.

### Separate installs
- Shared `connection.json` / enrollment helpers.
- Docs: `docs/separate-install.md`, `docs/security-auth-policy.md`.

## Upgrade notes

1. Upgrade **Central first** (open TCP **7443** firewall; set PublicHost if agents use public IP).
2. Upgrade Agents; set `Server.Url=https://<central-ip>:7443` and `AllowUntrustedServerCertificate=true`.
3. If Agent service fails to start after dual Full+Agent-only installs: re-run Agent Setup 1.1.0 as Admin, or use tray **Start Agent** (offers repair).

## Verify Central

```powershell
curl.exe -k https://<central-ip>:7443/api/v1/health
Test-NetConnection <central-ip> -Port 7443
```
