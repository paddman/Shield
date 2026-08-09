# Release Notes — NT Shield 1.3.1

## P0 control-plane hardening

Version `1.3.1` makes Central authentication, trusted HTTPS and cryptographically approved response actions the default rather than optional post-install configuration.

Highlights:

- Central `RequireAuth=true` by default;
- Operator and Agent credentials have separate scopes;
- first enrollment issues a per-Agent API key;
- Central secrets and private action-signing material stay in protected server storage;
- Windows/Linux Agents validate Central certificates by default;
- destructive actions require one concrete target Agent;
- Central signs complete response payloads with RSA-PSS;
- Agents reject modified, expired, wrong-target and unsigned envelopes;
- persistent nonce ledgers reject replay, including after Agent restart;
- public `connection.json` metadata no longer contains credentials;
- Full, Central and Agent installers are aligned to version `1.3.1` and hardened provisioning.

Read the complete security changes and migration procedure:

- [`RELEASE_NOTES_v1.3.1.md`](RELEASE_NOTES_v1.3.1.md)
- [`docs/security-auth-policy.md`](docs/security-auth-policy.md)
- [`docs/known-limitations.md`](docs/known-limitations.md)

## Upgrade order

1. Back up Central data, secrets, certificates and current installers.
2. Upgrade Central first and verify protected secret/bootstrap material.
3. Distribute the public Central certificate/CA and enrollment token through a protected channel.
4. Upgrade Agents and verify per-Agent key, heartbeat, ingest and policy delivery.
5. Run tamper, expiry and replay acceptance checks.
6. Remove any temporary legacy anonymous-ingest or trust-all migration setting.

## Security boundary

This release hardens authentication and response authority. It does not yet provide named Operator users, MFA/RBAC, complete end-to-end action-result acknowledgement, database-enforced tenant isolation or a durable state machine for every delayed multi-batch attack chain. Those boundaries remain explicit in [`docs/known-limitations.md`](docs/known-limitations.md).
