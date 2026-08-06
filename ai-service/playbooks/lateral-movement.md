# Lateral Movement Response

## Trigger
One internal host connects to multiple internal targets on authentication or administration ports, especially after a credential attack or successful network logon.

## Validate
1. Build an ordered host-to-host timeline.
2. Attribute each connection to process, PID, executable hash, service, account, and command line.
3. Check SMB, RDP, WinRM, WMI, PsExec, scheduled task, and new service activity.
4. Compare against the normal server role and maintenance window.
5. Preserve endpoint telemetry and PCAP references.

## Contain
- Collect diagnostics and forensic snapshot.
- Revoke sessions and disable compromised credentials.
- Isolate the host only through the human approval gate.
- Block malicious peers at the closest enforcement point.

## Eradicate
Remove persistence, verify service configuration, inspect neighboring hosts, and hunt for matching hashes, users, domains, and destination patterns.
