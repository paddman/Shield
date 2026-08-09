# NT Shield 1.3.1 — P0 Control-Plane Hardening

Version `1.3.1` changes NT Shield from permissive lab defaults to an authenticated, target-bound defensive control plane. This release is security-sensitive and requires a controlled Central/Agent credential migration.

## Security fixes

### Central authentication now fails closed

- `Security:RequireAuth=true` is the default.
- Operator APIs always require `OperatorApiKey`, even if legacy compatibility mode is explicitly selected.
- Agent API keys are accepted only on enrollment/heartbeat/ingest-related paths.
- Agent keys cannot list incidents, change policy, read audit records, administer LLM tokens or enqueue response actions.
- Anonymous Agent ingest requires both `RequireAuth=false` and the explicit lab-only `AllowLegacyAnonymousAgentIngest=true` switch.
- Authentication and scope failures are audited when persistence is available.

### Secure enrollment and secret storage

- Central generates a random 256-bit enrollment token and Operator API key on first boot.
- Central generates a 3072-bit RSA action-signing key pair.
- Private action-signing material remains in Central `secrets.json` and is never delivered through policy or public connection metadata.
- Windows installers restrict `secrets.json` and `central.pfx` to LocalSystem and built-in Administrators.
- Unix-like secret/config files use mode `0600` where supported.
- `connection.json` now contains public URL/port/CA metadata only.

### Trusted HTTPS by default

- Windows and Linux Agents validate Central through the OS trust store or an explicit CA/certificate file.
- Certificate hostname/SAN mismatch is rejected.
- Agent installers no longer enable trust-all behavior automatically.
- Plain HTTP is rejected by the Windows/Linux secure installers unless an explicit migration-lab escape is selected.
- CentOS 6 compatibility transport now requires HTTPS/TLS 1.2.

### Signed, target-bound response actions

A client-provided `Approved=true` value no longer grants authority.

For every destructive response, Central now:

1. authenticates the Operator;
2. validates the action allowlist;
3. requires one concrete `TargetAgentId`;
4. rejects destructive broadcast requests;
5. requires a response reason;
6. adds issue/expiry timestamps and a random nonce;
7. hashes the complete canonical execution payload;
8. signs the hash with RSA-PSS.

The Agent verifies key id, signature, target identity, payload hash and expiry before execution. Modifying an IP, port, process, service, path, reason or other signed field invalidates the action.

### Persistent replay protection

- Windows Agent ledger: `C:\ProgramData\NTShield\Agent\action-replay.log`
- Linux Agent ledger: `/var/lib/ntshield/action-replay.log`

A signed response nonce is reserved before execution and cannot be used by another request, including after Agent service restart. The ledger stores random nonces and expiry timestamps only.

### Installer hardening

- Full, Central and Agent installers now default to product version `1.3.1`.
- The full installer provisions Central first, then enrolls the bundled Agent with the generated token and trusted public certificate.
- Central installer no longer writes authentication secrets into `appsettings.json` or `connection.json`.
- The historic shared PFX password is migrated by certificate rotation during secure installer provisioning.
- Linux systemd service adds `NoNewPrivileges`, filesystem protections, kernel/control-group protections and restrictive `UMask`.

## Tests added

- valid signed action acceptance;
- plain `Approved=true` bypass rejection;
- payload tamper rejection;
- target-Agent mismatch rejection;
- expiry rejection;
- replay rejection before restart;
- replay rejection after persistent ledger reload.

## Upgrade procedure

1. Back up Central data, `secrets.json`, certificates and current installers.
2. Upgrade Central first.
3. Confirm `C:\ProgramData\NTShield\Server\secrets.json` contains:
   - `EnrollmentToken`
   - `OperatorApiKey`
   - `ActionSigningPrivateKeyPem`
   - `ActionSigningPublicKeyPem`
   - `ActionSigningKeyId`
4. Confirm unauthenticated `GET /api/v1/agents` and `POST /api/v1/actions` return `401`.
5. Distribute the public Central certificate/CA and enrollment token through a protected provisioning channel.
6. Upgrade Agents and confirm each receives a per-Agent API key.
7. Verify heartbeat, ingest and policy delivery.
8. Run one approved non-production response scenario and test replay/tamper rejection.
9. Remove any temporary `AllowLegacyAnonymousAgentIngest` or trust-all migration setting.
10. Retain the previous signed installer and tested rollback procedure until acceptance completes.

## Remaining production boundaries

This release hardens the P0 control plane; it does not complete every MDR requirement. Named users/MFA/RBAC, end-to-end Central action-result acknowledgement, database-enforced tenant isolation, complete durable multi-batch attack state machines and release code-signing enforcement remain documented in [`docs/known-limitations.md`](docs/known-limitations.md).
