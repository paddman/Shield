# Packet capture and TLS visibility control plane

This phase adds an integration-ready **control plane**. NT Shield Central does not open an interface, redirect traffic, terminate TLS, or manufacture PCAP. Arkime, MinIO, Squid, or another approved data-plane service performs those operations. Central owns tenant-scoped policy, capacity admission, bounded session metadata, short-lived access grants, export jobs, retention coordination, health/gap reporting, and audit.

That boundary is intentional:

- packet bytes and decrypted HTTP bodies do not enter Central's control database;
- an AI request may receive only `CaptureAiEvidenceReference` metadata, never PCAP bytes or signed download URLs;
- provider object keys are opaque, persisted separately, and excluded from JSON serialization;
- access is purpose-bound, short-lived, and audited;
- an inline TLS provider must be fail-open. Loss of inspection creates a visibility gap; it must not interrupt customer traffic.

> **Deployment status:** the checked-in capture control store is `sqlite-lab`. It is suitable for a lab or a single-node pilot only. The production example keeps CaptureControl disabled. A multi-replica production rollout still requires an `ICaptureControlStore` PostgreSQL implementation using database transactions, row/advisory locks, and `SKIP LOCKED` claims. The provider bridge, Arkime/MinIO/Squid data planes, KMS, and 1 Gbps replay are external integrations and are not simulated by this control plane.

## Central integration hooks

The implementation lives under `src/NTShield.Server/Capture` and is isolated from the existing `ICentralStore`. Add these two hooks to `Program.cs`:

```csharp
using NTShield.Server.Capture;

// Before builder.Build()
builder.Services.AddCaptureControlPlane(builder.Configuration);

// With the other endpoint mappings, after authentication/authorization middleware
app.MapCaptureControlPlane();
```

Do not initialize the store manually. `CaptureControlInitializer` yields immediately and retries initialization in the background, so a slow or unavailable capture database cannot delay the cheap dashboard session route or Kestrel startup. Every store operation also has a race-safe initialization guard; capture endpoints remain unavailable until their own store call can initialize.

The endpoint extension uses the existing interactive authorization policies:

| Operation | Authorization |
|---|---|
| list policy/session metadata, health, visibility gaps | existing Central operator middleware |
| create/simulate/update/delete capture policy | `SocAdmin` |
| create/list/read export jobs and session/export access grants | `SocPacketAccess` (`SocOperator` or `SocAdmin`) |
| capture audit | `SocAdmin` |

Every route resolves the tenant through `TopologyService.ResolveTenantId`. OIDC tenant claims therefore override an untrusted browser header as enforced by the existing identity layer.

## API surface

All routes are under `/api/v2` and honor `X-NTShield-Tenant` through the claim-aware resolver.

```text
GET    /api/v2/capture-policies
GET    /api/v2/capture-policies/{id}
POST   /api/v2/capture-policies/simulate
POST   /api/v2/capture-policies
PUT    /api/v2/capture-policies/{id}             If-Match: "<version>"
DELETE /api/v2/capture-policies/{id}?version=N    (If-Match is preferred)

GET    /api/v2/packet-sessions?campaignId=&edgeId=&fromUtc=&toUtc=&address=&port=&protocol=&payloadAvailable=&providerId=&cursor=&take=
GET    /api/v2/packet-sessions/{id}
POST   /api/v2/packet-sessions/{id}/access
POST   /api/v2/packet-sessions/{id}/tls-artifact/access
POST   /api/v2/packet-sessions/{id}/tls-preview
POST   /api/v2/packet-sessions/{id}/exports

GET    /api/v2/packet-exports?take=50
POST   /api/v2/packet-exports
GET    /api/v2/packet-exports/{id}
POST   /api/v2/packet-exports/{id}/access

GET    /api/v2/capture-health
GET    /api/v2/capture-health/visibility-gaps?openOnly=true&take=100
GET    /api/v2/capture-audit?take=100
```

Session pages are capped (200 by default) and use an opaque cursor. Export jobs are capped to 100 sessions. Provider responses are capped to 4 MiB. Access grants default to five minutes and cannot exceed fifteen minutes.

Policy mutation uses an atomic `(tenant_id, policy_id, version)` compare-and-swap. The desired state, immutable success audit row, and durable provider-dispatch record commit in one SQLite transaction. Provider apply/delete happens only after that commit and is retried from the dispatch queue; a stale dispatch is discarded rather than applying an older version. A stale editor receives `409 capture_policy_version_conflict` with the current version. A tenant may reference only providers whose server-side `TenantIds` assignment includes that tenant, including a separate decrypted-artifact provider.

Enabled policies are admitted only when their estimated retained bytes fit both the tenant limit and the shared provider limit; ingress and provider retention are summed across every tenant assigned to that provider. The SQLite lab store uses cooperative, expiring database leases for the tenant and provider while admission and CAS run, so separate Central processes sharing the same database do not independently oversubscribe it. This is a pilot hardening measure, not a substitute for the PostgreSQL transaction/advisory-lock backend required for multi-replica production.

The retention estimate is deliberately conservative:

```text
retained bytes = estimated Mbps × sampling % × 125,000 × 86,400 × (hot days + cold days)
```

The default lifecycle is hot for 7 days plus cold for 83 days, with hard expiry at day 90. Central rejects any policy or metadata-retention configuration above 90 days. `RetentionDays` must equal `StorageLifecycle.HotDays + ColdDays`, which prevents a UI from showing one expiry while the provider receives another. Central admits at most `CapacityAdmissionPercent` of the smallest positive tenant, configured-provider, or live-provider capacity. A packet-bearing policy also requires a positive ingress estimate and known tenant/provider capacity; zero or missing capacity cannot act as an unlimited plan. Live ingest limits are also enforced. With `RequireFreshProviderHealthForActivation=true`, an operator cannot activate policy against stale capacity data. A provider outage never blocks production traffic; it records an open visibility gap and policy reconciliation retries the desired version.

When a provider reports critical storage pressure, it sets `storagePressure=Critical` and `storageCriticalMetadataOnly=true`. Central rejects new packet-bearing policy activation while still accepting bounded flow/TLS metadata. The normalized `storage_critical_metadata_only` gap remains open until the provider reports recovery.

## Provider bridge contract

Each provider `BaseUrl` is server-configured; no API caller may supply a URL. TLS certificate verification is enabled. HTTP is accepted only for loopback development endpoints. Every enabled provider requires an `ApiKey`; it is sent only as `X-NTShield-Provider-Key` and must come from a server secret source in production.

Central expects the following bounded bridge operations. Vendor credentials, MinIO credentials, and TLS private keys stay in the bridge/provider, not Central.

### Health

```http
GET /v1/health
X-NTShield-Provider-Key: ...
```

```json
{
  "state": "Healthy",
  "capacityBytes": 10995116277760,
  "usedBytes": 2147483648,
  "hotCapacityBytes": 2199023255552,
  "hotUsedBytes": 1073741824,
  "coldCapacityBytes": 8796093022208,
  "coldUsedBytes": 1073741824,
  "storagePressure": "Normal",
  "storageCriticalMetadataOnly": false,
  "ingestMbps": 410.5,
  "maxSustainableIngressMbps": 10000,
  "queueDepth": 0,
  "statusCode": "ok",
  "activeVisibilityGapReasonCodes": []
}
```

### Metadata synchronization

```http
GET /v1/sessions?cursor=<opaque>&take=200
```

The response is `{ "items": [...], "nextCursor": "..." }`. Each item contains tenant/session/sensor IDs, a canonical `flowId`, optional correlation/campaign/edge/incident IDs, timestamps, flow tuple, optional endpoint host/agent/process/user attribution, counters, bounded TLS metadata, retention times, and an opaque `payloadReference`. It must not contain packet bytes, HTTP bodies, credentials, cookies, or a download URL. Configure explicit `TenantIds`; Central rejects a bridge record outside that allowlist.

Payload-bearing metadata also requires `payloadSha256`, `encryptionKeyVersion`, `storageTier` (`Hot`, `Cold`, or `Archive`), and a logical `storagePoolId`. Only the checksum and logical key/tier identifiers are returned by Central. The opaque object reference remains `[JsonIgnore]`; bucket names, object keys, KMS material, and signed URLs never appear in session/export DTOs or AI evidence.

### Desired policy

```http
PUT /v1/policies
Content-Type: application/json

{ ...CapturePolicy... }
```

Delete uses `DELETE /v1/policies/{policyId}?tenantId=<tenant>`. A provider should treat policy ID plus version idempotently. If application fails, traffic remains fail-open and Central reports a gap rather than claiming capture succeeded.

### Access and exports

```http
POST /v1/access-grants
POST /v1/access-grants/revoke
POST /v1/tls/previews
POST /v1/exports
POST /v1/exports/access
POST /v1/payloads/delete
```

The access response contains `grantId`, an HTTPS `accessUrl`, and `expiresAtUtc`. The provider must bind the grant to the requested tenant, resource, purpose, actor, and TTL. Before asking the provider, Central durably appends an `attempt` audit row. It validates the URL/lifetime, then appends `success`. If the completion audit fails, Central calls `/v1/access-grants/revoke`, returns no URL, and fails closed. The provider must make revocation idempotent and immediate. Central never persists the URL.

When an approved TLS policy sets `RetainDecryptedArtifactsInProvider=true`, the proxy may retain an encrypted decoded artifact in its own data plane. Session metadata exposes only availability, SHA-256, provider ID, KMS key version, tier, and logical pool ID. The opaque artifact reference is persisted in a separate ignored column and is never serialized. `/tls-artifact/access` uses the same pre-audit/grant/revoke sequence as PCAP access.

`/tls-preview` is also purpose-audited and capped (20 transactions by default). The provider returns normalized transaction metadata only: timestamp, HTTP protocol/method, authority, a query-free redacted path template, status, content types, body-size counters, and header **names**. The DTO has no body-content or header-value field. An oversized/unredacted provider response is rejected, and Central withholds the preview if completion audit persistence fails.

An export request contains one tenant, job ID, format (`pcap` or `pcapng`), expiry, and at most the configured number of opaque payload references. Export creation and its success audit commit atomically; the job cannot be claimed before that transaction commits. Workers claim jobs with an owner and expiry lease, and a different worker can reclaim stale `Running` work after a crash. Providers must treat the job ID idempotently because a crash after the provider accepts a request but before Central commits the result can cause a retry. The worker rechecks every source session's retention immediately before dispatch, so an expired payload is never exported. It returns an opaque `outputReference` plus the safe SHA-256, KMS key version, storage tier, and logical storage-pool ID. A separate audited access call mints the short-lived URL.

Metadata synchronization rejects malformed records item-by-item. It stores only a SHA-256 fingerprint, safe tenant/session hints, and a bounded reason code in quarantine; raw metadata and opaque provider references are not copied there. Quarantine/audit and the page cursor commit together so a poison record cannot pin synchronization on the same page, while valid records on that page remain idempotent.

Providers report active fail-open visibility using only these normalized codes: `storage_critical_metadata_only`, `tls_quic_bypass`, `tls_certificate_pinning_bypass`, `tls_mtls_bypass`, `tls_policy_exclusion`, and `tls_inspection_failed`. Central also creates `provider_unavailable`, `policy_apply_failed`, and `policy_delete_failed` locally. Unknown provider strings are discarded rather than becoming unbounded labels.

## Arkime + MinIO hybrid

Use Arkime for packet/session indexing and MinIO for durable evidence objects when a site needs independent retention tiers. Deploy an authenticated bridge beside those services:

1. Arkime or the sensor performs physical capture and produces session metadata.
2. The bridge maps Arkime session IDs to tenant IDs from a server-side sensor assignment; never accept a tenant from a browser.
3. PCAP evidence is copied to a private MinIO bucket with object lock/versioning if required by policy.
4. The bridge returns only an opaque handle such as a database ID, not a bucket/key or permanent URL.
5. A Central access/export request causes the bridge to verify tenant ownership and mint a short-lived MinIO URL.
6. Retention deletion removes provider payload first. Central deletes its metadata only after provider acknowledgement, avoiding silent orphaning.

The example `arkime-hybrid` provider in `deploy/central-linux/appsettings.CaptureControl.example.json` represents that bridge. It is not an Arkime emulator and Central does not claim a capture is present until real provider metadata arrives.

## Squid TLS visibility

Both supported layouts use the same adapter contract:

- **External Squid**: customer-managed Squid and bridge. Central distributes desired metadata/inspection policy and receives normalized TLS session metadata.
- **Native Squid provider**: an NT Shield-managed sidecar on the Central site. It remains a separate least-privilege process and data plane; Central still does not terminate TLS itself.

For either layout:

- keep the signing CA/private key in an HSM or the proxy host; never put it in Central configuration;
- deploy client trust and traffic redirection through an approved change process;
- do not create automatic category bypasses. Every domain/CIDR exclusion must be an explicit `SocAdmin` policy change with optimistic concurrency and audit; certificate pinning, mTLS, and QUIC observations become visibility-gap reason codes rather than silently mutating policy;
- set `Tls.FailOpen=true`; this is validated for inline proxy modes;
- keep `Tls.AttemptQuicTcpFallback=true`. The provider contract must try to make QUIC/HTTP3 clients retry over inspectable TCP/TLS; when fallback cannot be enforced it passes traffic fail-open and reports `tls_quic_bypass`;
- set the policy `ProviderId` to that TLS provider. Central rejects a policy that names a different inline `Tls.ProviderId`, preventing a policy from appearing active when its desired state was delivered only to another capture bridge; use a separate policy for a separate TAP/Arkime provider;
- provider-owned decoded artifacts require declared `tls-artifact-access`, `tls-preview`, and `retention` capabilities. Central stores no decrypted body and returns only the bounded normalized preview described above;
- provider health loss opens a visible gap and traffic continues without inspection.

The external/native examples expose only `metadata` and `policy` capabilities. Add `payload-access`, `export`, or `retention` only when the approved Squid bridge actually implements those operations.

## Deployment

Copy the `CaptureControl` section from:

```text
deploy/central-linux/appsettings.CaptureControl.example.json
```

into the protected production configuration or inject equivalent environment/secrets configuration. Do not commit real provider keys. Ensure `/var/lib/ntshield/central` is writable only by the Central service account and backed up with the existing control database.

Before enabling:

1. establish HTTPS trust from Central to every bridge;
2. set unique provider keys in a server secret source;
3. configure explicit `TenantIds`, capacities, ingest limits, and provider capabilities;
4. verify provider health and capacity snapshots;
5. create a disabled policy, simulate it, then activate it with `If-Match`;
6. confirm a real session appears, a purpose-bound access grant is audited, and provider outage produces a fail-open visibility gap;
7. verify expired payload is deleted at the provider before Central metadata disappears.

Physical interface selection, packet fan-out, Arkime/OpenSearch sizing, MinIO replication/object-lock policy, Squid CA lifecycle, and network redirection remain deployment-specific data-plane work. This control plane does not silently substitute placeholders for them.
