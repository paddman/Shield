# Web Server Compromise Response

## Trigger
IIS w3wp or a web runtime spawns a shell, a web process contacts many external destinations, webshell tokens appear in command lines, or network sensors detect exploit traffic.

## Validate
1. Correlate Suricata signatures with Zeek HTTP, TLS, DNS, notice, and weird logs.
2. Inspect parent-child process relationships, command line, executable hash, and service account.
3. Review application, IIS/WAS, reverse-proxy, PHP, container, and operating-system logs.
4. Identify recent configuration or file changes under web roots.
5. Check ASM findings for the exposed service and relevant CVEs.

## Contain
- Capture PCAP and export evidence.
- Remove the asset from service or isolate it after approval.
- Block confirmed malicious sources and domains.
- Rotate application secrets and invalidate sessions.

## Recover
Rebuild from a trusted image where practical, patch the root cause, validate integrity, and monitor for recurrence.
