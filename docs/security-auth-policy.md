# Security: Auth + Policy + Audit (P0)

## Overview

| Principal | Secret | Header / field |
|-----------|--------|----------------|
| **Enrollment** | `EnrollmentToken` | Body on `POST /api/v1/agents/register` |
| **Agent** | Per-agent `ApiKey` (issued on register) | `X-NTShield-Api-Key` on heartbeat/ingest |
| **Operator** (Dashboard) | `OperatorApiKey` | `X-NTShield-Api-Key` on fleet/actions/policy |

Default: **`Security:RequireAuth: false`** (lab). Turn **on** for production after distributing keys.

## Central bootstrap

On first start, Central writes:

`C:\ProgramData\NTShield\Server\secrets.json`

```json
{
  "EnrollmentToken": "<hex>",
  "OperatorApiKey": "<hex>"
}
```

Or set explicitly in Central `appsettings.json`:

```json
"Security": {
  "RequireAuth": true,
  "EnrollmentToken": "...",
  "OperatorApiKey": "...",
  "AutoGenerateSecretsOnBoot": true,
  "SecretsFilePath": "C:\\ProgramData\\NTShield\\Server\\secrets.json",
  "RequireSignedAgent": false
}
```

Public without key: health/readiness plus the session bootstrap endpoints:
`GET /health`, `GET /api/v1/health`, `GET /api/v2/readiness`,
`GET /api/v2/session`, `POST /api/v2/session/exchange`,
`POST /api/v2/session/local`, and `GET /api/v2/session/login`.
The session probe returns authentication state and never returns a credential.

## Enroll Windows agent

1. Put `EnrollmentToken` in agent `appsettings.json` → `Server:EnrollmentToken`
2. Start agent service — it registers, receives `AgentApiKey`, stores:
   - `C:\ProgramData\NTShield\Agent\agent.credential`
   - and `Server:ApiKey` in appsettings when writable
3. Heartbeat/ingest use `X-NTShield-Api-Key`

## Enroll Linux agent

```bash
sudo ./install-agent.sh --host 10.0.0.5 --port 7443 \
  --enrollment-token '<EnrollmentToken>'
```

Agent persists `Server:ApiKey` after register.

## Dashboard

Settings → **Operator API Key** = `OperatorApiKey` from secrets.json.
Required when `RequireAuth=true` for listing agents, incidents, and enqueueing actions.

### Interactive dashboard sessions (v2)

The browser now exchanges the legacy operator key once at
`POST /api/v2/session/exchange` and receives an encrypted `HttpOnly`,
`Secure`, `SameSite=Strict` session cookie. It does not persist or attach the
operator key to every dashboard API request. `GET /api/v2/session` is the cheap
authentication probe used before progressive dashboard hydration.

Production deployments should enable `DashboardAuth:Oidc` and use an OIDC
confidential code-flow client with PKCE. `Authority`, `ClientId`, and a
server-side `ClientSecret` are mandatory when OIDC is enabled. Claims use these
exact role names:

| Role | Access |
|------|--------|
| `Executive` | Dashboard posture and reports; no packet payload |
| `SocOperator` | Threat/incident investigation and packet view/export |
| `SocAdmin` | SOC access plus capture policy, tenant and storage administration |

`DashboardAuth:Oidc:TenantClaim` defaults to `ntshield_tenants`; each claim is
an allowed tenant ID, while `*` is an explicit cross-tenant administrator
assignment. The tenant header is rejected when it is outside those claims.
Missing tenant claims grant no tenant access. If an identity provider cannot
emit tenant claims, configure an explicit, least-privilege
`DashboardAuth:Oidc:DefaultTenantIds` list; Central never substitutes `*`.

The optional local account is break-glass only. It remains disabled unless all
of `Enabled`, `Username`, a PBKDF2-SHA256 hash with at least 210,000 iterations,
and an RFC 6238 Base32 TOTP secret are configured. There is no default local
password and MFA cannot be disabled for this account.

Cookie-authenticated mutating requests must echo the session response's
`csrfToken` in `X-NTShield-CSRF`. Agent keys and LLM gateway tokens remain
separate machine credentials.

## Policy

- Default policy id `default` version 1 (IDS / DetectOnly)
- `GET /api/v1/policy` — read
- `PUT /api/v1/policy` — update (operator key); bumps version if needed
- Agents pull newer policy on **heartbeat** (`HeartbeatResponse.Policy`)

## Audit

- Table `audit_log` (register, action.enqueue, policy.update, auth.fail)
- `GET /api/v1/audit?take=100` (operator when RequireAuth)

## Agent integrity

Heartbeat reports `BinarySha256` + `IsBinarySigned`.
Optional: `RequireSignedAgent`, `ApprovedAgentSha256[]` on Central.

## Production checklist

1. Confirm `secrets.json` exists; back it up securely
2. Configure agents with EnrollmentToken; restart → get ApiKey
3. Set Dashboard Operator API key
4. Set `Security:RequireAuth: true` and restart Central
5. Verify unauthenticated `POST /api/v1/actions` → 401
6. Verify enrolled agent still heartbeats

## APIs added

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/v1/audit` | operator |
| GET | `/api/v1/policy` | operator (or open when RequireAuth=false) |
| PUT | `/api/v1/policy` | operator |
