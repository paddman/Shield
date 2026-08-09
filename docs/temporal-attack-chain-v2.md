# Temporal Attack Chain v2

NT Shield now keeps attack-chain evidence as tenant-scoped normalized records instead of treating the legacy campaign JSON as the source of truth. The v1 campaign/path endpoints remain available for one transition release; v2 is designed for shadow comparison before cutover.

## Time and evidence model

- `ThreatObservation` is append-only and idempotent. It retains raw observed time, corrected event time, collected/ingested time, timestamp quality, lifecycle, endpoints, protocol/ports, agent/host, process/user/service, and bounded evidence references.
- Campaign membership is stored separately, so one immutable observation can be re-correlated without rewriting its evidence.
- Episodes close after 60 minutes of inactivity. A late observation may deterministically bridge two episodes.
- Contacts retain first/last observed time, occurrence and reconnect counts, duration, chronological median/P95 gaps, periodicity score, metric quality, and bounded samples.
- Graph edges always name explicit source and destination node IDs. Branches and cycles are preserved; the API never infers an edge from display order.
- Event ordering uses corrected event time only when a recent Central-measured clock offset exists. Collector send delay is not treated as clock skew, and late events cannot move durable `LastObservedAtUtc` backwards.

Periodicity is supporting evidence, not a verdict. Fewer than five recurrence observations do not create a beacon candidate. A periodic-only candidate is `Candidate`/inferred and does not count as active; automatic promotion requires independent corroboration and confidence of at least `0.80`. Shared NAT/proxy IP alone never joins a campaign.

## Durable processing and retention

Ingest writes a durable temporal outbox item. Workers claim one item with an owner lease, retry failures, and never use fire-and-forget projection writes. Legacy backfill is bounded, cursor-resumable, and converts each collapsed hop to exactly one `legacy_collapsed` observation; it does not invent lost contact counts.

The default retention worker:

- redacts raw payload/incident detail after 30 days while preserving minimal event facts and memberships required by aggregates;
- retains campaign/contact/timeline aggregates for 180 days;
- removes all remaining temporal rows after the aggregate cutoff.

The campaign list uses immutable summary history and protected tenant/filter-bound cursors, so an update between pages cannot make an unreturned campaign disappear. Detail cursors are also campaign-revision bound and return `409 cursor_revision_stale` after a concurrent revision.

## API

All routes are tenant-scoped through the authenticated identity and `TopologyService.ResolveTenantId`:

```text
GET /api/v2/threats?from=&to=&status=&severity=&cursor=&limit=
GET /api/v2/threats/{campaignId}
GET /api/v2/threats/{campaignId}/graph?from=&to=&limit=
GET /api/v2/threats/{campaignId}/timeline?from=&to=&resolution=raw|1m|5m|1h&cursor=&limit=
GET /api/v2/threats/{campaignId}/contacts?from=&to=&cursor=&limit=
GET /api/v2/threats/stream
POST /api/v2/threats/{campaignId}/ai/explain
```

List responses are bounded to 500 rows (100 by default). Graph responses contain explicit `nodes[]` and `edges[]`; raw timeline and contact responses use opaque cursors. SSE publishes revision notifications and tells clients to retry after 15 seconds; the Dashboard also polls every 15 seconds when SSE is unavailable.

AI explanation receives bounded structured observations, contacts, totals, truncation state, citations, and explicit unknowns. Raw event payloads, PCAP bytes, provider object references, and signed URLs are not sent to the model.

## Storage and production status

- SQLite is the lab/single-node implementation.
- PostgreSQL implements the authoritative transactional control/campaign projections and atomic claims.
- With `Database:Provider=ClickHouse`, `ClickHouse:ControlProvider=Postgres` selects PostgreSQL for authoritative state while append-oriented observation/telemetry copies are written to ClickHouse. Keep `FailWrites=false`: the authoritative ingest transaction must not be retried after PostgreSQL commits merely because a secondary analytics write failed. API projections currently read from PostgreSQL; durable ClickHouse delivery and direct aggregate query offload remain future production work.
- The durable database outbox is implemented. A Kafka-compatible transport adapter and an external Kafka deployment are not included in this repository and must be completed before claiming the requested production event-bus topology.

Do not claim the 15-second event-to-chain SLO from unit/integration tests alone. Validate it with representative ingest volume, live PostgreSQL/ClickHouse, network latency, and the target browser during the shadow rollout.
