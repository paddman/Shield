# Threat Model — NT Shield

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Security Event Log data | High |
| Process/cmdline evidence | High |
| Agent identity certificate | Critical |
| Offline queue SQLite | High |
| Central PostgreSQL incidents | High |
| Response action capability | Critical |

## Trust boundaries

```
[Windows Host] --mTLS/HTTPS--> [Central API] --> [PostgreSQL]
      |                              |
   LocalSystem                  Operators
   (limited collectors)         (approve actions)
```

## Adversary goals

1. Disable or blind the agent
2. Inject false incidents / noise
3. Abuse response actions for DoS (kill services, block IPs)
4. Steal credentials from agent logs/queue
5. Pivot using agent as remote shell

## Mitigations

| Threat | Control |
|--------|---------|
| Remote shell via central | **Forbidden** — allowlisted response commands only; no arbitrary shell |
| Auto-destructive response | Default **DetectOnly**; destructive actions need explicit Central approval |
| Credential leakage | `EventDataSanitizer`; never log passwords; DPAPI for secrets |
| Path traversal | `EventDataSanitizer.SafePath` |
| Supply-chain update | SHA-256 + digital signature validation helpers |
| Spoofed agent | mTLS client certificates |
| Config tampering | Signed configuration verification API |
| Queue flooding | Offline queue limit + retention |
| Log wiping Security channel | Agent **never** clears Security Event Log or changes audit policy without authorization |
| Replay uploads | Idempotency keys on ingest |

## Residual risks

- Local admin can stop the service or delete SQLite
- netsh firewall rules can be removed by local admin
- Server 2012 lacks some modern isolation primitives
- Clock skew may affect cross-host correlation windows

## STRIDE summary

| Category | Notes |
|----------|-------|
| Spoofing | mTLS agent identity |
| Tampering | Signed updates/config; SQLite ACLs |
| Repudiation | Structured audit log on actions |
| Information disclosure | Sanitization, DPAPI |
| Denial of service | Queue caps, detect-only default |
| Elevation of privilege | Approval gate for kill/disable |
