# Tunneling and Remote Access Response

## Trigger
AnyDesk, TeamViewer, RustDesk, Cloudflare Tunnel, ngrok, unusual STUN/WebRTC, or another remote access channel appears on a server where it is not approved.

## Validate
1. Resolve DNS, TLS SNI, HTTP host, ASN, destination IP, and process attribution.
2. Check installed software inventory and change approvals.
3. Determine whether the channel was user-initiated, service-based, or spawned by another process.
4. Review authentication and data-transfer activity around first use.

## Contain
- Preserve endpoint and network evidence.
- Terminate the process or isolate the host only after operator approval.
- Block domains/IPs at DNS, proxy, firewall, or endpoint layers when confirmed unauthorized.
- Rotate credentials exposed during the session.
