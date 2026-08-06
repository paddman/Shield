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

Public without key: `GET /health`, `GET /api/v1/health` only (when RequireAuth=true).

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
