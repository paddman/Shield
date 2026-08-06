# Windows Server 2012 Compatibility Report

**Product:** NT Shield Agent 1.0.0
**Date:** 2026-07-26
**Minimum OS:** Windows Server 2012 x64 (NT 6.2)

## API inventory

| Capability | API | Server 2012 |
|------------|-----|-------------|
| Real-time events | `EventLogWatcher` / `EventLogQuery` | Yes |
| TCP/UDP table | `GetExtendedTcpTable` / `GetExtendedUdpTable` | Yes |
| Process path | `QueryFullProcessImageName` | Yes |
| Services | `Win32_Service` WMI | Yes |
| Processes | `Win32_Process` WMI | Yes |
| Tasks | Task Scheduler 2.0 COM | Yes |
| Secrets | DPAPI `ProtectedData` | Yes |
| Firewall response | `netsh advfirewall` | Yes |
| Service control | WMI / SCM | Yes |

## Runtime gates

`WindowsCompatibility.BuildReport()` enforces OS ≥ 6.2 before collectors start.
Advanced network isolation features require Server 2016+ and remain disabled on 2012.

## Installer checks

- x64 OS
- Version ≥ 6.2
- Administrator
- Visual C++ Redistributable x64
- Service recovery restart via `sc.exe failure`

## Test recommendations

1. Deploy self-contained `win-x64` build
2. Confirm Security log read access under LocalSystem
3. Generate 4625 noise and verify SQLite + alerts
4. Disconnect Central and confirm offline queue growth/flush
5. Verify DetectOnly refuses TerminateProcess without approval

## Result

**Code-level compatibility: PASS** for Win32 surface used.
**Runtime packaging: VALIDATE** on target 2012 images before production.
