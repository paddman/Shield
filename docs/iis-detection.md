# IIS detection (Windows Agent)

NT Shield can monitor **IIS / ASP.NET** hosts using Event Log channels + process/network rules.

## What is covered

| Signal | How | Rule / channel |
|--------|-----|----------------|
| **w3wp spawns cmd/powershell** | Security 4688 + parent in XML | `IIS_W3WP_SPAWN_SHELL` |
| **Webshell cmdline tokens** | 4688 under web paths | `IIS_WEBSHELL_CMDLINE` |
| **ASP.NET app errors burst** | Application 1309/1310/1325 | `IIS_ASPNET_APP_ERRORS` |
| **Worker process failure** | Application / WAS | `IIS_WORKER_PROCESS_FAILURE` |
| **W3SVC/WAS service crash** | System 7031/7034 | `IIS_SERVICE_CRASH` |
| **IIS config change** | `Microsoft-Windows-IIS-Configuration/Operational` | `IIS_CONFIG_CHANGE` |
| **w3wp outbound fan-out** | Network connections by process | `IIS_W3WP_OUTBOUND_FANOUT` |
| **Web port scan-like** | Many dests on 80/443/8080… | `IIS_WEB_PORTS_SCAN_LIKE` |
| **Syslog keywords** | Central UDP syslog pack | `OS-WEBSHELL`, `OS-IIS-W3WP`, `OS-IIS-AUTH` |

Channels that are **not installed** (no IIS role) are **skipped** — agent still starts.

## Requirements on the IIS host

1. **NT Shield Agent** installed and pointed at Central.
2. **Process Creation Auditing** (4688) for shell-spawn / webshell rules — enable via audit policy / Sysmon optional.
3. Optional: IIS failed-request tracing / HTTP.sys logs are **not** parsed yet (roadmap: W3C log tail).

## Enable / verify

```powershell
# Agent loads config\rules.json — ensure IIS rules present (shipped in 1.0.11+)
Get-Content "C:\Program Files\NT Shield Agent\config\rules.json" | Select-String "IIS_"

# Restart agent after rule update
Restart-Service NTShieldAgent

# Logs
Get-Content C:\ProgramData\NTShield\Agent\logs\agent-*.log -Tail 50 |
  Select-String "IIS|w3wp|EventLogWatcher"
```

Dashboard → **Incidents** / alerts with RuleId starting with `IIS_`.

## Limitations

- Does **not** replace WAF (ModSecurity / Azure WAF).
- Does **not** parse full IIS W3C access logs yet.
- Noisy ASP.NET 1309 may need allowlist / threshold tune per app.
- Configuration channel only if IIS logging provider enabled.
