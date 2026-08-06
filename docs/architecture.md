# Architecture

```mermaid
sequenceDiagram
  participant S as Source Host Agent<br/>10.0.105.35
  participant D as Dest Host Agent<br/>10.0.105.190
  participant C as Central API
  participant P as PostgreSQL

  S->>S: GetExtendedTcpTable diff
  S->>S: PID 1684 svchost + services
  S->>C: connections/batch
  D->>D: Event 4625 x N (spray)
  D->>C: events/batch
  C->>P: persist
  C->>C: correlate IP/time/user/process
  C->>P: incident
  Note over C: FormatDisplay() analyst view
```

## Agent modules

1. Event Log Collector — real-time + bookmark
2. Network Collector — IP Helper snapshot diff
3. Process / Service / Scheduled Task collectors
4. SQLite storage + offline queue + DPAPI
5. Detection engine (JSON rules)
6. Response engine (detect-only default, allowlist, approval)
7. Evidence packager (ZIP + SHA-256 manifest)
8. HTTPS transport (mTLS optional, backoff, idempotency)

## Incident output fields

Source / Destination / Port / Process / PID / Services / Service account /
Logon process / Logon type / Failed attempts / Distinct usernames /
Successful login detected / First-Last seen / Evidence events
