# Release Notes — NT Shield 1.0.0

## Highlights

- Endpoint agent for Windows Server **2012–2025** (x64, self-contained .NET 10)
- Real-time Security Event collection with restart-safe bookmarks
- Network attribution via IP Helper (not netstat primary)
- Service mapping for shared PIDs (svchost multi-service)
- Configuration-driven detection (password spray, brute force, lateral patterns)
- Central API with cross-host correlation and incident display model
- **Detect-only default** response engine with allowlisted actions + approval gate
- Evidence ZIP export with per-file SHA-256 manifest
- Offline queue, exponential backoff, heartbeat + clock-skew reporting

## Incident display (example)

```
Incident: Internal Password Spray
Source: 10.0.105.35
Destination: 10.0.105.190
Destination port: 80
Process: svchost.exe
PID: 1684
Services:
  - IPTVManagementService
Service account: LocalSystem
Logon process: Advapi
Logon type: 8
Failed attempts: 880
Distinct usernames: 11
Successful login detected: false
First seen: ...
Last seen: ...
Evidence events:
  - ...
```

## Breaking / policy notes

- Destructive response actions require explicit Central approval
- Agent will not clear Security Event Log or change audit policy automatically

## Build

```bash
dotnet publish src/NTShield.Agent/NTShield.Agent.csproj \
  -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -o artifacts/agent-win-x64
```
