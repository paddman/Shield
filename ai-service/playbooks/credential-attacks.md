# Credential Attack Response

## Trigger
Password spray, brute force, successful logon after repeated failures, privileged logon after failures, or explicit-credential events.

## Validate
1. Confirm source IP, destination host, usernames, logon type, and time window.
2. Correlate Windows events 4625, 4624, 4648, and 4672.
3. Identify the source process and Windows services sharing the PID.
4. Check whether the source is an approved scanner, jump host, monitoring system, or service account.
5. Review Suricata and Zeek evidence for SMB, RDP, WinRM, LDAP, Kerberos, or unusual fan-out.

## Contain
- Capture or preserve evidence first.
- Block or rate-limit the source only after operator approval.
- Lock the affected account and revoke active sessions when compromise is supported by evidence.
- Isolate the source host when successful access is followed by lateral movement.

## Recover and prevent
Reset credentials, rotate service secrets, enforce MFA where supported, restrict management ports, and tune service-account allowlists.
