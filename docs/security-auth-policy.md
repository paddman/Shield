# Security: Authentication, Trusted Transport, Signed Actions and Audit (P0)

## Security boundary

| Principal | Credential | Allowed surface |
|-----------|------------|-----------------|
| **Enrollment** | Random `EnrollmentToken` | First-time `POST /api/v1/agents/register` only |
| **Agent** | Per-agent API key issued at registration | Heartbeat, ingest, event and connection batches only |
| **Operator** | Protected `OperatorApiKey` | Fleet, incidents, policy, audit, LLM administration and response actions |
| **LLM client** | Expiring LLM token | Constrained OpenAI-compatible proxy only |

Central defaults to **`Security:RequireAuth=true`**. Operator APIs never become anonymous. Setting `RequireAuth=false` enables only a narrow migration mode; anonymous telemetry additionally requires `AllowLegacyAnonymousAgentIngest=true` and must be confined to an isolated lab.

Public without a key:

- `GET /health`
- `GET /api/v1/health`

The static Control Center shell may load, but every protected data and mutation API still requires the correct principal.

## Trusted HTTPS

Windows and Linux Agents validate Central with the operating-system trust store by default. A private/self-signed Central certificate must be supplied through `Server:CaCertificatePath` or installed into the OS trust store. Hostname/SAN mismatch is rejected.

`AllowUntrustedServerCertificate=true` and Linux `--allow-untrusted` are explicit migration-lab escapes. The installers no longer enable them automatically.

The CentOS 6 compatibility Agent also requires an HTTPS Central URL, TLS 1.2 and either system trust or a configured CA file.

## Central bootstrap and secret storage

First boot creates:

`C:\ProgramData\NTShield\Server\secrets.json`

```json
{
  "EnrollmentToken": "<random-256-bit-hex>",
  "OperatorApiKey": "<random-256-bit-hex>",
  "ActionSigningPrivateKeyPem": "<Central-only RSA private key>",
  "ActionSigningPublicKeyPem": "<public key delivered to agents>",
  "ActionSigningKeyId": "<public-key fingerprint>"
}
```

The Windows installer restricts `secrets.json` and `central.pfx` to LocalSystem and built-in Administrators. Unix-like deployment attempts file mode `0600`. Custom/container deployment must provide equivalent controls.

**Never copy `ActionSigningPrivateKeyPem` to an Agent, dashboard or public connection file.** `C:\ProgramData\NTShield\connection.json` contains only public URL/port/CA metadata.

Example Central configuration:

```json
"Security": {
  "RequireAuth": true,
  "AllowLegacyAnonymousAgentIngest": false,
  "EnrollmentToken": "",
  "OperatorApiKey": "",
  "AutoGenerateSecretsOnBoot": true,
  "SecretsFilePath": "C:\\ProgramData\\NTShield\\Server\\secrets.json",
  "RequireSignedAgent": false,
  "ActionLifetimeMinutes": 5,
  "MaxActionLifetimeMinutes": 15
}
```

Blank bootstrap credentials and action-signing keys are generated with a cryptographically secure random source. Invalid or mismatched signing keys stop Central rather than degrading to unsigned actions.

## Agent enrollment

### Windows

1. Configure an HTTPS Central URL and trusted `central.cer`/CA certificate.
2. Put the Central `EnrollmentToken` under `Server:EnrollmentToken` or pass it to the installer.
3. Central validates the token and issues a per-agent API key.
4. The Agent persists the issued key in protected Agent storage and uses `X-NTShield-Api-Key` for later calls.
5. A remote Agent must use the DNS/IP present in the Central certificate SAN, never another machine's `localhost`.

### Linux

```bash
sudo ./install-agent.sh \
  --url https://shield.example.go.th:7443 \
  --ca-cert ./central-ca.crt \
  --enrollment-token '<EnrollmentToken>'
```

The Linux installer stores `appsettings.json` with mode `0600`; after successful registration the Agent persists its per-agent key and clears the enrollment token.

## Operator authorization

The current Control Center uses `OperatorApiKey`. An Agent key cannot list incidents, read audit data, change policy, administer LLM tokens or enqueue response actions. Missing, invalid and out-of-scope credentials return `401` and produce an `auth.fail` audit event when storage is available.

A shared operator key is still below production SOC identity requirements. Named users, MFA and RBAC remain an explicit next boundary in [`known-limitations.md`](known-limitations.md).

## Signed one-time response actions

A client-supplied boolean `Approved=true` has no authority. For each destructive action Central creates an RSA-PSS signed envelope containing:

- request and approval identifiers
- exact `TargetAgentId`
- action type and every execution parameter
- operator principal and reason
- issue and expiry timestamps
- random nonce
- canonical payload SHA-256
- action-signing key id
- RSA-PSS signature

Central refuses:

- non-allowlisted action types
- destructive requests without approval intent or reason
- requests without one concrete target Agent
- broadcast destructive actions
- payloads it cannot sign and verify with its configured key pair

Agents receive only the public verification key through versioned policy. Before execution an Agent verifies:

1. signature and key id
2. exact target Agent identity
3. canonical payload hash
4. issue/expiry window
5. one-time nonce reservation

Windows stores the replay ledger at `C:\ProgramData\NTShield\Agent\action-replay.log`; Linux uses `/var/lib/ntshield/action-replay.log`. A new request with an already consumed nonce is rejected even after service restart. The ledger contains random nonces and expiry timestamps only.

Default destructive-action lifetime is five minutes and is clamped to the configured maximum. Tampered, expired, unsigned, replayed or target-mismatched actions are rejected. Assigning `Approved=true` in client or Agent code does not bypass verification.

Read-only `LogOnly`, `ExportEvidence`, `ScanFile` and `ScanPath` do not require a destructive approval signature, but still require authenticated Operator access and one concrete target Agent.

## Policy

- Endpoint default is IDS / DetectOnly.
- `GET /api/v1/policy` and `PUT /api/v1/policy` require Operator authentication.
- Agents pull versioned policy on heartbeat.
- Policy carries the active action-signing public key and key id, never the private key.
- Invalid public-key material causes policy application to fail closed.

## Audit

Central records security-relevant decisions including:

- enrollment success/failure
- authentication failure and scope violation
- action enqueue and target
- policy update
- LLM token creation/revocation

Read with `GET /api/v1/audit?take=100` using the Operator key. End-to-end action result acknowledgement is a remaining production requirement.

## Agent integrity

Heartbeat reports `BinarySha256` and `IsBinarySigned`. Enable `RequireSignedAgent` only after release code signing, approved hash/signing policy distribution, golden-image validation and rollback testing.

## P0 acceptance checks

1. Start Central and verify protected `secrets.json` contains enrollment, operator and RSA action-signing material.
2. Verify unauthenticated `GET /api/v1/agents` and `POST /api/v1/actions` return `401`.
3. Verify an Agent API key cannot call `/api/v1/actions`, `/api/v1/policy` or `/api/v1/audit`.
4. Verify an Agent rejects an untrusted Central certificate and hostname/SAN mismatch.
5. Enroll one Agent with `EnrollmentToken`; confirm later heartbeat/ingest use its issued per-agent key.
6. Enqueue an approved, target-bound action and verify its RSA envelope on the intended Agent.
7. Modify any signed execution field; verify approval becomes invalid.
8. Deliver the same signed envelope to another Agent; verify target binding rejects it.
9. Replay the same signed envelope before expiry and after Agent restart; verify the nonce ledger rejects it.
10. Replay after expiry; verify it is rejected.
11. Confirm no destructive broadcast action can be enqueued.
12. Confirm `connection.json`, installer logs and `appsettings.json` do not contain Central private signing material or Operator credentials.
