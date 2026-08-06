# Separate installers (why they “don’t work” + how to fix)

## Architecture (always)

```
Agent  →→→  Central (:7443 HTTPS)  ←←←  Dashboard
```

Agent **never** talks to Dashboard. Both must use the **same Central URL**.

## Common mistakes

| Mistake | Symptom |
|---------|---------|
| Agent `Server.Url = https://localhost:7443` on a remote PC | Agent heartbeats only itself; Central on another machine never sees it |
| Self-signed Central cert + `AllowUntrustedServerCertificate=false` | Heartbeat/TLS fails |
| `RequireAuth=true` without `EnrollmentToken` on Agent | Register 403; inventory empty |
| Dashboard URL ≠ Agent URL | Empty Endpoints |
| Install Agent-only, expect Dashboard UI | Dashboard is a **separate** app (Full setup or build Dashboard) |

## Recommended order

1. **Central** on the server: `NTShield-Central-Setup-*.exe`
2. Note LAN IP from desktop **CONNECTION.txt** / `C:\ProgramData\NTShield\connection.json`
3. **Agent** on each endpoint: use **LAN IP**, not localhost
4. **Dashboard** (from Full stack or `artifacts\dashboard-win-x64`): Settings → same URL + Operator API key if required

## Shared connection file (v1.0.14+)

After Central install:

`C:\ProgramData\NTShield\connection.json`

Contains:

- `CentralUrl` / `RemoteUrl` (LAN)
- `EnrollmentToken` / `OperatorApiKey` (when generated)

Agent installer / `set-agent-central-url.ps1` will auto-read this when present.

## Fix Agent pointing at wrong Central

```powershell
# Admin
cd "C:\Program Files\NT Shield Agent\Installer"
.\set-agent-central-url.ps1 -ServerHost 10.0.0.5 -Port 7443
# or
.\set-agent-central-url.ps1 -CentralUrl https://10.0.0.5:7443 -EnrollmentToken <from secrets.json>
```

## Tray (Agent machine)

- **Edit Central IP / Port**
- **Service Control** — start/stop any Windows service + Agent service
- Mini dashboard: Start/Stop Agent, **More…** for full list

## Firewall

Central install can open TCP 7443. On server:

```powershell
New-NetFirewallRule -DisplayName 'NT Shield Central' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 7443
```
