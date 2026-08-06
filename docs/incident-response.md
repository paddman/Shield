# Incident Response

## What an incident contains

Cross-host incidents produced by the Central Server include:

| Field | Meaning |
|-------|---------|
| `SourceIp` / `SourcePort` | Client observed on destination auth events and/or source network table |
| `SourceHost` / `SourceAgentId` | Agent that observed the outbound connection |
| `SourceProcessId` | PID on the source host |
| `SourceProcessName` / `SourceProcessPath` | Executable |
| `SourceServiceNames` | All Windows services sharing that PID (never just `svchost.exe`) |
| `SourceCommandLine` | Command line when available |
| `DestinationHost` / `DestinationIp` / `DestinationPort` | Targeted endpoint |
| `Username` / `Domain` / `LogonType` | Identity under attack or used |
| `FailedLogonCount` / `SuccessfulLogonCount` | Auth outcome |
| `PrivilegedLogon` | 4672 observed |
| `EvidenceJson` | Compact timeline for analysts |

## Example narrative

> Host **10.0.105.35** process **PID 4280** (`C:\Windows\System32\svchost.exe`) hosting services **LanmanWorkstation, ...** opened an outbound connection to **10.0.105.190:445**. Destination agent recorded **24× 4625** then **1× 4624** for user **CORP\admin** (logon type 3). Incident severity **Critical** (`SPRAY_THEN_SUCCESS` / cross-host correlation).

## Operator workflow

1. Open `GET /api/v1/incidents` (newest first).
2. Confirm source process/service — if missing, deploy agent to the source subnet/host.
3. Validate whether account is service account vs. interactive admin.
4. Check allowlists for scanners / jump hosts if false positive.
5. Containment (manual unless response policy enabled):
   - Disable account / reset password
   - Block source IP at firewall
   - Isolate host via existing EDR/NAC
6. Agent local response defaults to **log-only** (`Response:LogOnlyMode=true`).

## Local agent artifacts

| Path | Content |
|------|---------|
| `%ProgramData%\NTShield\Agent\agent.db` | SQLite evidence + queue |
| `%ProgramData%\NTShield\Agent\logs\` | Serilog rolling files |

## Safety

- Do not enable `AllowProcessTerminate` or `AllowNetworkIsolation` without change control.
- Advanced isolation is gated to Server 2016+ at runtime.
