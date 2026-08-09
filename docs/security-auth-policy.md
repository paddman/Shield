# Security: Authentication, Signed Actions, Policy and Audit (P0)

## Security boundary

| Principal | Credential | Allowed surface |
|-----------|------------|-----------------|
| **Enrollment** | `EnrollmentToken` | First-time `POST /api/v1/agents/register` only |
| **Agent** | Per-agent API key issued at registration | Heartbeat, ingest, event and connection batches only |
| **Operator** | `OperatorApiKey` | Fleet, incidents, policy, audit, LLM administration and response actions |
| **LLM client** | Expiring LLM token | Constrained OpenAI-compatible proxy only |

Default: **`Security:RequireAuth: true`**. Central fails closed on first boot and generates credentials in protected server-side secrets storage.

Setting `RequireAuth=false` does **not** expose operator APIs. It enables only a narrow compatibility mode. Anonymous telemetry additionally requires the explicit dangerous switch `AllowLegacyAnonymousAgentIngest=true`; it should never be used outside an isolated migration lab.

Public without a key:

- `GET /health`
- `GET /api/v1/health`

The static Control Center shell may load without a key, but its protected data APIs do not.

## Central bootstrap

On first start, Central writes:

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

**Never copy `ActionSigningPrivateKeyPem` to an agent or dashboard.** Back up `secrets.json` as a production secret. On Unix-like Central deployments the bootstrapper attempts to set file mode `0600`; Windows deployments should ACL the directory to SYSTEM and Administrators during installation.

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

Blank bootstrap credentials are generated with a cryptographically secure random source. If automatic generation is disabled and credentials are absent, Central remains inaccessible rather than silently opening its APIs.

## Agent enrollment

### Windows

1. Put `EnrollmentToken` in agent `appsettings.json` under `Server:EnrollmentToken`.
2. Start the agent service.
3. Central validates the enrollment token and issues a per-agent API key.
4. The agent stores the issued key in `C:\ProgramData\NTShield\Agent\agent.credential` and in writable configuration when supported.
5. Subsequent heartbeat and ingest calls use `X-NTShield-Api-Key`.

### Linux

```bash
sudo ./install-agent.sh --host 10.0.0.5 --port 7443 \
  --enrollment-token '<EnrollmentToken>'
```

The Linux agent persists its issued per-agent key after registration.

## Operator login

The Control Center requires the `OperatorApiKey` from Central `secrets.json`. An agent key cannot list incidents, read audit data, change policy or enqueue response actions. A missing, invalid or out-of-scope key returns `401` and creates an `auth.fail` audit entry when persistence is available.

## Signed response actions

A boolean `Approved=true` is not an approval boundary. Every destructive Central action is converted into a target-bound cryptographic envelope containing:

- request and approval identifiers
- exact `TargetAgentId`
- action type and every execution parameter
- operator identity and reason
- issue and expiry timestamps
- random nonce
- canonical payload SHA-256
- action-signing key id
- RSA-PSS signature

Central refuses to enqueue:

- non-allowlisted actions
- destructive actions without explicit approval intent
- actions without a concrete target agent
- broadcast actions
- destructive actions without a reason

Agents receive the Central action-signing **public** key through versioned policy. `ResponseActionRequest.Approved` evaluates to true only while the complete envelope is untampered, unexpired and valid under that pinned public key. Assigning `Approved=true` inside a client or agent does not bypass verification.

Default destructive-action lifetime is five minutes and is clamped to the configured maximum. Expired, modified, unsigned or target-mismatched actions are removed from delivery and logged as critical security failures.

Read-only `LogOnly`, `ExportEvidence`, `ScanFile` and `ScanPath` actions do not require destructive approval signatures, but they still require an authenticated operator and one concrete target agent.

## Policy

- Default policy remains IDS / DetectOnly.
- `GET /api/v1/policy` reads current policy with operator authentication.
- `PUT /api/v1/policy` updates policy and increments its version.
- Agents pull policy on heartbeat.
- The policy carries the active action-signing public key and key id, never the private key.

## Audit

Central records security-relevant activity such as:

- enrollment success or failure
- authentication failure and scope violation
- action enqueue
- policy update
- LLM token creation and revocation

Read with `GET /api/v1/audit?take=100` using the operator key.

## Agent integrity

Heartbeat reports `BinarySha256` and `IsBinarySigned`. Production deployments should enable `RequireSignedAgent` after code-signing and validating the release packages, optionally with `ApprovedAgentSha256[]` during controlled rollout.

## Production acceptance checks

1. Start Central and confirm `secrets.json` contains generated enrollment, operator and action-signing material.
2. Verify unauthenticated `GET /api/v1/agents` returns `401`.
3. Verify unauthenticated `POST /api/v1/actions` returns `401`.
4. Verify an agent API key cannot call `/api/v1/actions`, `/api/v1/policy` or `/api/v1/audit`.
5. Enroll one agent using `EnrollmentToken`; verify heartbeat and ingest succeed with the issued per-agent key.
6. Enqueue an approved target-bound action and verify its RSA envelope on the agent.
7. Modify one signed field in a captured test payload; verify `Approved` becomes false and execution is rejected.
8. Replay the payload after expiry; verify it is rejected.
9. Confirm no destructive `broadcast` action can be enqueued.
10. Enable signed-agent enforcement only after the release binaries are code-signed and the rollback path is tested.
