# Roadmap: Trellix-class Server EDR (Windows + Linux)

See session plan for full strategy. Summary:

## Positioning
**NT Shield** = Server-first EDR + Central SOC (on-prem / hybrid / air-gap first), Windows + Linux.

## Phase 0 (now)
- Durable pending actions + threat campaigns
- Fleet inventory (online/offline, central URL, last error)
- Tray: Test Central connection
- Linux agent skeleton (heartbeat only)

## Phase 1 (P0 org trust — implemented v1.0.13)
- Enrollment token + agent/operator API keys (`X-NTShield-Api-Key`)
- Policy pull on heartbeat + `GET/PUT /api/v1/policy`
- Durable `audit_log` + `GET /api/v1/audit`
- Agent binary SHA-256 / signed report on heartbeat
- Docs: `docs/security-auth-policy.md`

## Phase 2
- Host timeline, process tree, hunt
- True isolate + evidence download

## Phase 3
- Light EPP: hash IOC + quarantine

## Phase 4
- Full Linux collectors (journald, ss, /proc)

## Phase 5–6
- Scale, reports, XDR connectors
