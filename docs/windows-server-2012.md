# Windows Server 2012 / 2012 R2 Compatibility

## Support matrix

| OS | Supported |
|----|-----------|
| Windows Server 2012 x64 | Target (minimum) |
| Windows Server 2012 R2 x64 | Target |
| Windows Server 2016–2025 | Target |

## Design rules enforced in code

1. **No newer-only Windows APIs** as hard dependencies.
2. Preferred APIs:
   - `EventLogWatcher` / `EventLogQuery` / `EventLogReader` (Event Log)
   - `GetExtendedTcpTable` / `GetExtendedUdpTable` (iphlpapi)
   - `QueryFullProcessImageName` (kernel32)
   - `Win32_Process` / `Win32_Service` (WMI)
   - Task Scheduler 2.0 COM (`Schedule.Service`)
   - DPAPI `ProtectedData`
3. **Runtime compatibility report** via `WindowsCompatibility.BuildReport()`:
   - Agent refuses to start collectors if OS &lt; 6.2 (Server 2012).
   - Features such as advanced network isolation require Server 2016+ and remain disabled otherwise.
4. **No Docker / Python / Node** on the endpoint.
5. **Self-contained `win-x64`** publish embeds runtime native dependencies.

## .NET 10 note

This solution targets **`net10.0-windows`** / **`net10.0`** with **.NET 10 LTS** as specified.

Microsoft’s official OS support matrix for each .NET release may list different minimum Windows versions than the *API surface* this agent uses. Operational guidance:

- Always publish **self-contained win-x64**.
- Validate on a golden image of Server 2012 / 2012 R2 before broad rollout.
- Install **VC++ Redistributable x64**.
- Prefer testing with the same CU/security updates used in production.

If a future .NET 10 runtime build drops loader support for 6.2/6.3 kernels, pin to a known-good runtime pack or introduce a dual-target agent build. The collector code itself stays on 2012-era Win32 APIs.

## Explicitly avoided

| Avoid | Why |
|-------|-----|
| `netstat` as primary network source | Slow, lossy, parsing fragile |
| ETW providers requiring newer manifests only | Not assumed present |
| Windows 10+ only firewall / isolation APIs without gates | Fail closed with runtime check |
| CIM session APIs that need newer PowerShell | Use classic WMI `ManagementObjectSearcher` |

## Service account

Default service runs as `LocalSystem` (via `New-Service`) which can read Security log and open process handles for enrichment. Tighten with gMSA only after validating log and process permissions.
