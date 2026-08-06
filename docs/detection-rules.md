# Detection Rules

Rules are configuration-driven JSON (`rules/default-rules.json`).

## Engine capabilities

- Sliding time window
- Event count thresholds
- Distinct username / source / destination counts
- Source & destination grouping
- Allowlist (usernames, source IPs)
- Severity
- Cooldown / suppression
- Evidence attachment (JSON sample of contributing events)

## Default rules

### INTERNAL_PASSWORD_SPRAY — High

Within **5 minutes**: same source, same destination, ≥**20** failed logons (4625), ≥**5** distinct usernames.

### DISTRIBUTED_PASSWORD_SPRAY — Critical

Within **10 minutes**: same destination, ≥**3** distinct sources, ≥**50** total failed logons.

### BRUTE_FORCE_SINGLE_ACCOUNT — High

Within **5 minutes**: same source, same destination, same username, ≥**20** failed logons.

### SPRAY_THEN_SUCCESS — Critical

Within **15 minutes**: ≥**5** failures then a **4624** matching source IP + username.

### PRIVILEGED_LOGON_AFTER_FAILURES — Critical

Failures from a source, then **4624** + **4672** special privileges in the same window.

### SUSPICIOUS_ACCOUNT_NAMES — Medium

Usernames in:
`123, admin, admin1, administrator, guest, root, www, wwwroot, db, web, data, test, oracle, postgres`

**Name alone never alerts** — requires volume in window (`minEventCount`).

### MULTIPLE_INTERNAL_TARGETS — High

Within **10 minutes**, one host opens connections to ≥**5** distinct destinations on auth-related ports:
`22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 5986`.

## Customizing

Edit JSON, restart agent (or hot-reload path can be pointed via `Detection:RulesPath`).

```json
{
  "id": "CUSTOM_RULE",
  "enabled": true,
  "severity": "High",
  "eventIds": [4625],
  "windowMinutes": 5,
  "minEventCount": 10
}
```
