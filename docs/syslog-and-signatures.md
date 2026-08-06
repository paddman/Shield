# Syslog + Open Source Signatures

## Can Agent send syslog to Central?

**Yes.**

| Path | Protocol | Port | Content |
|------|----------|------|---------|
| HTTPS ingest (default) | HTTPS | 7443 | JSON batches / heartbeats |
| **Syslog forward** | **UDP** | **5514** | Alerts as RFC5424 text |

### Agent config

```json
"Server": {
  "Url": "https://10.0.0.5:7443",
  "SyslogEnabled": true,
  "SyslogHost": "10.0.0.5",
  "SyslogPort": 5514,
  "SyslogAppName": "NTShield"
}
```

On each detection alert the agent also emits:

```text
<134>1 2026-... HOST NTShield - - - NTShield-ALERT RuleId=... Severity=High ...
```

Any device (Linux, firewall, app) can also send syslog UDP to Central:5514.

---

## Does Central have open-source signatures?

**Yes — community keyword pack** (Sigma/Snort-*inspired*, not a full Suricata binary engine).

File:

```text
C:\ProgramData\NTShield\Server\signatures\opensource-signatures.json
config/signatures/opensource-signatures.json  (source)
```

Examples: SSH brute, RDP failures, SMB lateral, SQL login fail, webshell patterns, mimikatz, encoded PowerShell, port scan noise.

API:

```text
GET /api/v1/signatures
GET /api/v1/health   → includes syslog.udpPort + signatures count
```

Hits become **Incidents** visible in Dashboard (live).

### Add your own signatures

Edit JSON:

```json
{
  "id": "OS-CUSTOM-1",
  "name": "My pattern",
  "enabled": true,
  "severity": "High",
  "matchAny": ["failed login", "auth fail"],
  "keywords": ["sshd"]
}
```

Restart `NTShieldCentral` (or wait for file reload on next match cycle).

### Firewall for syslog

```powershell
New-NetFirewallRule -DisplayName "NT Shield Syslog UDP 5514" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
```

### Test

```powershell
# From any host
$msg = "<134>1 $(Get-Date -Format o) TESTHOST sshd - - - Failed password for invalid user admin from 1.2.3.4"
$udp = New-Object System.Net.Sockets.UdpClient
$bytes = [Text.Encoding]::UTF8.GetBytes($msg)
$udp.Send($bytes, $bytes.Length, "127.0.0.1", 5514) | Out-Null
$udp.Close()

# Then Dashboard → Incidents / GET /api/v1/incidents
```
