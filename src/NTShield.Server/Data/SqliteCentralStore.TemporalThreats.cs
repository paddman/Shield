using System.Text.Json;
using Microsoft.Data.Sqlite;
using NTShield.Shared.Models;

namespace NTShield.Server.Data;

public sealed partial class SqliteCentralStore
{
    private int _temporalThreatSchemaReady;

    private async Task EnsureTemporalThreatSchemaAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _temporalThreatSchemaReady) == 1) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_temporalThreatSchemaReady == 1) return;
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                CREATE TABLE IF NOT EXISTS threat_campaigns_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    first_observed_utc TEXT NOT NULL,
                    last_observed_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 0,
                    episode_count INTEGER NOT NULL DEFAULT 0,
                    edge_count INTEGER NOT NULL DEFAULT 0,
                    contact_count INTEGER NOT NULL DEFAULT 0,
                    recurrence_count INTEGER NOT NULL DEFAULT 0,
                    affected_asset_count INTEGER NOT NULL DEFAULT 0,
                    related_incident_count INTEGER NOT NULL DEFAULT 0,
                    related_incident_ids_json TEXT NOT NULL DEFAULT '[]',
                    merged_into_campaign_id TEXT,
                    tombstoned_at_utc TEXT,
                    involved_hosts_json TEXT NOT NULL DEFAULT '[]',
                    involved_ips_json TEXT NOT NULL DEFAULT '[]',
                    title TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, campaign_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_campaigns_v2_tenant_last
                    ON threat_campaigns_v2(tenant_id, last_observed_utc DESC, campaign_id);
                CREATE INDEX IF NOT EXISTS ix_threat_campaigns_v2_tenant_updated
                    ON threat_campaigns_v2(tenant_id, updated_at_utc);

                CREATE TABLE IF NOT EXISTS threat_campaign_summary_history_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    snapshot_at_utc TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    first_observed_utc TEXT NOT NULL,
                    last_observed_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    observation_count INTEGER NOT NULL,
                    episode_count INTEGER NOT NULL,
                    edge_count INTEGER NOT NULL,
                    contact_count INTEGER NOT NULL,
                    recurrence_count INTEGER NOT NULL,
                    affected_asset_count INTEGER NOT NULL,
                    related_incident_count INTEGER NOT NULL,
                    related_incident_ids_json TEXT NOT NULL,
                    merged_into_campaign_id TEXT,
                    tombstoned_at_utc TEXT,
                    involved_hosts_json TEXT NOT NULL,
                    involved_ips_json TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id, revision)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_campaign_history_v2_snapshot
                    ON threat_campaign_summary_history_v2(tenant_id, snapshot_at_utc DESC, campaign_id);
                INSERT OR IGNORE INTO threat_campaign_summary_history_v2(
                    tenant_id, campaign_id, revision, snapshot_at_utc, status, severity, confidence,
                    first_observed_utc, last_observed_utc, updated_at_utc,
                    observation_count, episode_count, edge_count, contact_count, recurrence_count,
                    affected_asset_count, related_incident_count, related_incident_ids_json,
                    merged_into_campaign_id, tombstoned_at_utc,
                    involved_hosts_json, involved_ips_json, title, summary)
                SELECT tenant_id, campaign_id, revision, updated_at_utc, status, severity, confidence,
                    first_observed_utc, last_observed_utc, updated_at_utc,
                    observation_count, episode_count, edge_count, contact_count, recurrence_count,
                    affected_asset_count, related_incident_count, related_incident_ids_json,
                    merged_into_campaign_id, tombstoned_at_utc,
                    involved_hosts_json, involved_ips_json, title, summary
                FROM threat_campaigns_v2;
                DROP TRIGGER IF EXISTS trg_threat_campaign_history_v2_insert;
                CREATE TRIGGER trg_threat_campaign_history_v2_insert
                AFTER INSERT ON threat_campaigns_v2 BEGIN
                    INSERT OR IGNORE INTO threat_campaign_summary_history_v2(
                        tenant_id, campaign_id, revision, snapshot_at_utc, status, severity, confidence,
                        first_observed_utc, last_observed_utc, updated_at_utc,
                        observation_count, episode_count, edge_count, contact_count, recurrence_count,
                        affected_asset_count, related_incident_count, related_incident_ids_json,
                        merged_into_campaign_id, tombstoned_at_utc,
                        involved_hosts_json, involved_ips_json, title, summary)
                    VALUES (NEW.tenant_id, NEW.campaign_id, NEW.revision,
                        strftime('%Y-%m-%dT%H:%M:%f','now') || '0000+00:00',
                        NEW.status, NEW.severity, NEW.confidence,
                        NEW.first_observed_utc, NEW.last_observed_utc, NEW.updated_at_utc,
                        NEW.observation_count, NEW.episode_count, NEW.edge_count,
                        NEW.contact_count, NEW.recurrence_count, NEW.affected_asset_count,
                        NEW.related_incident_count, NEW.related_incident_ids_json,
                        NEW.merged_into_campaign_id, NEW.tombstoned_at_utc,
                        NEW.involved_hosts_json, NEW.involved_ips_json, NEW.title, NEW.summary);
                END;
                DROP TRIGGER IF EXISTS trg_threat_campaign_history_v2_update;
                CREATE TRIGGER trg_threat_campaign_history_v2_update
                AFTER UPDATE ON threat_campaigns_v2 BEGIN
                    INSERT OR IGNORE INTO threat_campaign_summary_history_v2(
                        tenant_id, campaign_id, revision, snapshot_at_utc, status, severity, confidence,
                        first_observed_utc, last_observed_utc, updated_at_utc,
                        observation_count, episode_count, edge_count, contact_count, recurrence_count,
                        affected_asset_count, related_incident_count, related_incident_ids_json,
                        merged_into_campaign_id, tombstoned_at_utc,
                        involved_hosts_json, involved_ips_json, title, summary)
                    VALUES (NEW.tenant_id, NEW.campaign_id, NEW.revision,
                        strftime('%Y-%m-%dT%H:%M:%f','now') || '0000+00:00',
                        NEW.status, NEW.severity, NEW.confidence,
                        NEW.first_observed_utc, NEW.last_observed_utc, NEW.updated_at_utc,
                        NEW.observation_count, NEW.episode_count, NEW.edge_count,
                        NEW.contact_count, NEW.recurrence_count, NEW.affected_asset_count,
                        NEW.related_incident_count, NEW.related_incident_ids_json,
                        NEW.merged_into_campaign_id, NEW.tombstoned_at_utc,
                        NEW.involved_hosts_json, NEW.involved_ips_json, NEW.title, NEW.summary);
                END;

                CREATE TABLE IF NOT EXISTS threat_observations_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    episode_id TEXT,
                    contact_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    observed_at_utc TEXT NOT NULL,
                    collected_at_utc TEXT,
                    ingested_at_utc TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    incident_id TEXT,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, observation_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_observations_v2_campaign_time
                    ON threat_observations_v2(tenant_id, campaign_id, observed_at_utc, observation_id);
                CREATE INDEX IF NOT EXISTS ix_threat_observations_v2_campaign_ingested
                    ON threat_observations_v2(tenant_id, campaign_id, ingested_at_utc);
                CREATE INDEX IF NOT EXISTS ix_threat_observations_v2_contact
                    ON threat_observations_v2(tenant_id, campaign_id, contact_id, observed_at_utc);

                CREATE TABLE IF NOT EXISTS threat_observation_memberships_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    assigned_at_utc TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    provenance TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (tenant_id, campaign_id, observation_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_memberships_v2_observation
                    ON threat_observation_memberships_v2(tenant_id, observation_id, active);

                CREATE TABLE IF NOT EXISTS threat_contacts_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    contact_id TEXT NOT NULL,
                    source_node_id TEXT NOT NULL,
                    destination_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    technique TEXT,
                    protocol TEXT,
                    local_port INTEGER,
                    remote_port INTEGER,
                    first_observed_utc TEXT NOT NULL,
                    last_observed_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    observation_count INTEGER NOT NULL,
                    observation_record_count INTEGER NOT NULL,
                    recurrence_count INTEGER NOT NULL,
                    auth_failure_count INTEGER NOT NULL,
                    auth_success_count INTEGER NOT NULL,
                    open_count INTEGER NOT NULL,
                    close_count INTEGER NOT NULL,
                    inferred INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    last_observation_id TEXT NOT NULL,
                    median_gap_seconds REAL,
                    p95_gap_seconds REAL,
                    beacon_score REAL NOT NULL DEFAULT 0,
                    gap_samples_json TEXT NOT NULL DEFAULT '[]',
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    sample_payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id, contact_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_contacts_v2_campaign_last
                    ON threat_contacts_v2(tenant_id, campaign_id, last_observed_utc DESC, contact_id);
                CREATE INDEX IF NOT EXISTS ix_threat_contacts_v2_campaign_updated
                    ON threat_contacts_v2(tenant_id, campaign_id, updated_at_utc);

                CREATE TABLE IF NOT EXISTS threat_episodes_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    first_observed_utc TEXT NOT NULL,
                    last_observed_utc TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id, episode_id)
                );
                CREATE TABLE IF NOT EXISTS threat_episode_memberships_v2 (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    assigned_at_utc TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id, observation_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_episode_memberships_v2_episode
                    ON threat_episode_memberships_v2(tenant_id, campaign_id, episode_id);

                CREATE TABLE IF NOT EXISTS temporal_correlation_outbox_v2 (
                    work_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    enqueued_at_utc TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_utc TEXT NOT NULL,
                    lease_until_utc TEXT,
                    lease_owner TEXT,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_temporal_outbox_v2_due
                    ON temporal_correlation_outbox_v2(next_attempt_utc, lease_until_utc, enqueued_at_utc);

                CREATE TABLE IF NOT EXISTS threat_candidate_observations_v2 (
                    tenant_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    contact_id TEXT NOT NULL,
                    context_key TEXT NOT NULL,
                    observed_at_utc TEXT NOT NULL,
                    ingested_at_utc TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, observation_id)
                );
                CREATE INDEX IF NOT EXISTS ix_threat_candidates_v2_contact_time
                    ON threat_candidate_observations_v2(tenant_id, contact_id, observed_at_utc, observation_id);
                CREATE INDEX IF NOT EXISTS ix_threat_candidates_v2_context_time
                    ON threat_candidate_observations_v2(tenant_id, context_key, observed_at_utc DESC, observation_id);
                CREATE TABLE IF NOT EXISTS temporal_backfill_state_v2 (
                    state_key TEXT PRIMARY KEY,
                    cursor_value TEXT,
                    updated_at_utc TEXT NOT NULL
                );
                """;
            await cmd.ExecuteNonQueryAsync(cancellationToken);
            Volatile.Write(ref _temporalThreatSchemaReady, 1);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpsertThreatCampaignV2SummaryAsync(
        ThreatCampaignV2Summary summary,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        var tenantId = NormalizeTenantId(summary.TenantId);
        summary.TenantId = tenantId;
        var first = NormalizeTemporalDate(summary.FirstObservedAtUtc, summary.UpdatedAtUtc);
        var last = NormalizeTemporalDate(summary.LastObservedAtUtc, first);
        var updated = NormalizeTemporalDate(summary.UpdatedAtUtc, DateTimeOffset.UtcNow);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO threat_campaigns_v2(
                    tenant_id, campaign_id, revision, status, severity, confidence,
                    first_observed_utc, last_observed_utc, updated_at_utc,
                    observation_count, episode_count, edge_count, contact_count, recurrence_count,
                    affected_asset_count, related_incident_count, related_incident_ids_json,
                    merged_into_campaign_id, tombstoned_at_utc,
                    involved_hosts_json, involved_ips_json, title, summary)
                VALUES ($tenant, $campaign, $revision, $status, $severity, $confidence,
                    $first, $last, $updated, $observations, $episodes, $edges, $contacts, $recurrences,
                    $assets, $incident_count, $incident_ids, $merged_into, $tombstoned,
                    $hosts, $ips, $title, $summary)
                ON CONFLICT(tenant_id, campaign_id) DO UPDATE SET
                    revision=threat_campaigns_v2.revision + 1,
                    status=CASE WHEN threat_campaigns_v2.tombstoned_at_utc IS NOT NULL
                        THEN threat_campaigns_v2.status ELSE excluded.status END,
                    severity=excluded.severity,
                    confidence=COALESCE(excluded.confidence, threat_campaigns_v2.confidence),
                    first_observed_utc=MIN(threat_campaigns_v2.first_observed_utc, excluded.first_observed_utc),
                    last_observed_utc=MAX(threat_campaigns_v2.last_observed_utc, excluded.last_observed_utc),
                    updated_at_utc=MAX(threat_campaigns_v2.updated_at_utc, excluded.updated_at_utc),
                    affected_asset_count=excluded.affected_asset_count,
                    related_incident_count=excluded.related_incident_count,
                    related_incident_ids_json=excluded.related_incident_ids_json,
                    merged_into_campaign_id=COALESCE(
                        threat_campaigns_v2.merged_into_campaign_id, excluded.merged_into_campaign_id),
                    tombstoned_at_utc=COALESCE(
                        threat_campaigns_v2.tombstoned_at_utc, excluded.tombstoned_at_utc),
                    involved_hosts_json=excluded.involved_hosts_json,
                    involved_ips_json=excluded.involved_ips_json,
                    title=excluded.title,
                    summary=excluded.summary;
                """;
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$campaign", summary.CampaignId);
            cmd.Parameters.AddWithValue("$revision", Math.Max(1, summary.Revision));
            cmd.Parameters.AddWithValue("$status", BoundTemporal(summary.Status, 32));
            cmd.Parameters.AddWithValue("$severity", BoundTemporal(summary.Severity, 32));
            cmd.Parameters.AddWithValue("$confidence", (object?)summary.Confidence ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$first", TemporalText(first));
            cmd.Parameters.AddWithValue("$last", TemporalText(last));
            cmd.Parameters.AddWithValue("$updated", TemporalText(updated));
            cmd.Parameters.AddWithValue("$observations", Math.Max(0, summary.ObservationCount));
            cmd.Parameters.AddWithValue("$episodes", Math.Max(0, summary.EpisodeCount));
            cmd.Parameters.AddWithValue("$edges", Math.Max(0, summary.EdgeCount));
            cmd.Parameters.AddWithValue("$contacts", Math.Max(0, summary.ContactCount));
            cmd.Parameters.AddWithValue("$recurrences", Math.Max(0, summary.RecurrenceCount));
            cmd.Parameters.AddWithValue("$assets", Math.Max(0, summary.AffectedAssetCount));
            cmd.Parameters.AddWithValue("$incident_count", Math.Max(0, summary.RelatedIncidentCount));
            cmd.Parameters.AddWithValue("$incident_ids", JsonSerializer.Serialize(summary.RelatedIncidentIds.Take(50), JsonOptions));
            cmd.Parameters.AddWithValue("$merged_into", (object?)summary.MergedIntoCampaignId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$tombstoned", summary.TombstonedAtUtc.HasValue
                ? TemporalText(summary.TombstonedAtUtc.Value)
                : DBNull.Value);
            cmd.Parameters.AddWithValue("$hosts", JsonSerializer.Serialize(summary.InvolvedHosts.Take(32), JsonOptions));
            cmd.Parameters.AddWithValue("$ips", JsonSerializer.Serialize(summary.InvolvedIps.Take(64), JsonOptions));
            cmd.Parameters.AddWithValue("$title", BoundTemporal(summary.Title, 300));
            cmd.Parameters.AddWithValue("$summary", BoundTemporal(summary.Summary, 2_000));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<ThreatCampaignV2Summary?> GetThreatCampaignV2SummaryAsync(
        string tenantId,
        string campaignId,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = TemporalSummarySelect +
                          " WHERE tenant_id=$tenant AND campaign_id=$campaign LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$campaign", campaignId);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadTemporalSummary(reader) : null;
    }

    public async Task<IReadOnlyList<ThreatCampaignV2Summary>> ListThreatCampaignV2SummariesAsync(
        string tenantId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        string? status,
        string? severity,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterCampaignId,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            WITH ranked AS (
                SELECT tenant_id, campaign_id, revision, status, severity, confidence,
                       first_observed_utc, last_observed_utc, updated_at_utc,
                       observation_count, episode_count, edge_count, contact_count, recurrence_count,
                       affected_asset_count, related_incident_count, related_incident_ids_json,
                       merged_into_campaign_id, tombstoned_at_utc,
                       involved_hosts_json, involved_ips_json, title, summary, snapshot_at_utc,
                       ROW_NUMBER() OVER (
                           PARTITION BY tenant_id, campaign_id
                           ORDER BY snapshot_at_utc DESC, revision DESC) AS row_number
                FROM threat_campaign_summary_history_v2
                WHERE tenant_id=$tenant AND snapshot_at_utc <= $watermark
            )
            SELECT tenant_id, campaign_id, revision, status, severity, confidence,
                   first_observed_utc, last_observed_utc, updated_at_utc,
                   observation_count, episode_count, edge_count, contact_count, recurrence_count,
                   affected_asset_count, related_incident_count, related_incident_ids_json,
                   merged_into_campaign_id, tombstoned_at_utc,
                   involved_hosts_json, involved_ips_json, title, summary, snapshot_at_utc
            FROM ranked
            WHERE row_number=1
              AND ($from IS NULL OR last_observed_utc >= $from)
              AND ($to IS NULL OR first_observed_utc <= $to)
              AND ($status = '' OR lower(status) = lower($status))
              AND ($severity = '' OR lower(severity) = lower($severity))
              AND ($after_last IS NULL OR snapshot_at_utc < $after_last
                   OR (snapshot_at_utc = $after_last AND campaign_id > $after_id))
            ORDER BY snapshot_at_utc DESC, campaign_id ASC
            LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$watermark", TemporalText(watermarkUtc));
        cmd.Parameters.AddWithValue("$from", fromObservedAtUtc.HasValue
            ? TemporalText(fromObservedAtUtc.Value)
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", toObservedAtUtc.HasValue
            ? TemporalText(toObservedAtUtc.Value)
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$status", status?.Trim() ?? string.Empty);
        cmd.Parameters.AddWithValue("$severity", severity?.Trim() ?? string.Empty);
        cmd.Parameters.AddWithValue("$after_last", afterLastObservedAtUtc.HasValue
            ? TemporalText(afterLastObservedAtUtc.Value)
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_id", afterCampaignId ?? string.Empty);
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
        var items = new List<ThreatCampaignV2Summary>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) items.Add(ReadTemporalSummary(reader));
        return items;
    }

    public async Task<long> CountActiveThreatCampaignsAsync(
        string tenantId,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT COUNT(*) FROM threat_campaigns_v2
            WHERE tenant_id=$tenant AND tombstoned_at_utc IS NULL
              AND lower(status) NOT IN ('closed', 'resolved', 'merged', 'tombstoned', 'candidate', 'inferred')
              AND ($from IS NULL OR last_observed_utc >= $from)
              AND ($to IS NULL OR first_observed_utc <= $to);
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$from", fromObservedAtUtc.HasValue
            ? TemporalText(fromObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", toObservedAtUtc.HasValue
            ? TemporalText(toObservedAtUtc.Value) : DBNull.Value);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0);
    }

    public async Task<bool> TryAppendThreatObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        NormalizeObservation(observation);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var tx = conn.BeginTransaction();

            await using (var insert = conn.CreateCommand())
            {
                insert.Transaction = tx;
                insert.CommandText =
                    """
                    INSERT OR IGNORE INTO threat_observations_v2(
                        tenant_id, campaign_id, observation_id, episode_id, contact_id, kind,
                        observed_at_utc, collected_at_utc, ingested_at_utc, occurrence_count,
                        incident_id, payload)
                    VALUES ($tenant, $campaign, $id, $episode, $contact, $kind,
                        $observed, $collected, $ingested, $occurrences, $incident, $payload);
                    """;
                AddObservationParameters(insert, observation);
                if (await insert.ExecuteNonQueryAsync(cancellationToken) == 0)
                {
                    await tx.RollbackAsync(cancellationToken);
                    return false;
                }
            }

            await InsertMembershipAsync(conn, tx, new ThreatObservationMembership
            {
                TenantId = observation.TenantId,
                CampaignId = observation.CampaignId,
                ObservationId = observation.ObservationId,
                AssignedAtUtc = observation.IngestedAtUtc,
                Confidence = observation.Confidence,
                Provenance = observation.TimestampQuality == "legacy_collapsed"
                    ? "legacy_campaign_backfill"
                    : "temporal_correlator_v2",
                Active = true
            }, cancellationToken);

            var contactInserted = await InsertContactAsync(conn, tx, observation, cancellationToken);
            if (!contactInserted)
                await UpdateContactAsync(conn, tx, observation, cancellationToken);

            var episodeDelta = await AssignEpisodeAsync(conn, tx, observation, cancellationToken);
            await UpdateTemporalStatsAsync(conn, tx, observation, contactInserted, episodeDelta, cancellationToken);
            await tx.CommitAsync(cancellationToken);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> TryAppendThreatCandidateObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        NormalizeObservation(observation);
        observation.CampaignId = string.Empty;
        observation.EpisodeId = null;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT OR IGNORE INTO threat_candidate_observations_v2(
                    tenant_id, observation_id, contact_id, context_key,
                    observed_at_utc, ingested_at_utc, payload)
                VALUES ($tenant, $id, $contact, $context, $observed, $ingested, $payload);
                """;
            cmd.Parameters.AddWithValue("$tenant", observation.TenantId);
            cmd.Parameters.AddWithValue("$id", observation.ObservationId);
            cmd.Parameters.AddWithValue("$contact", observation.ContactId);
            cmd.Parameters.AddWithValue("$context", TemporalContextKey(
                observation.SourceNodeId, observation.DestinationNodeId));
            cmd.Parameters.AddWithValue("$observed", TemporalText(observation.ObservedAtUtc));
            cmd.Parameters.AddWithValue("$ingested", TemporalText(observation.IngestedAtUtc));
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(observation, JsonOptions));
            return await cmd.ExecuteNonQueryAsync(cancellationToken) == 1;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateObservationsAsync(
        string tenantId,
        string contactId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT payload FROM threat_candidate_observations_v2
            WHERE tenant_id=$tenant AND ($contact='' OR contact_id=$contact)
              AND observed_at_utc >= $from AND observed_at_utc <= $to
            ORDER BY observed_at_utc ASC, observation_id ASC LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$contact", contactId);
        cmd.Parameters.AddWithValue("$from", TemporalText(fromObservedAtUtc));
        cmd.Parameters.AddWithValue("$to", TemporalText(toObservedAtUtc));
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
        var items = new List<ThreatObservation>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var item = JsonSerializer.Deserialize<ThreatObservation>(reader.GetString(0), JsonOptions);
            if (item is not null) items.Add(item);
        }
        return items;
    }

    public async Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateContextObservationsAsync(
        string tenantId,
        string firstNodeId,
        string secondNodeId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT payload FROM threat_candidate_observations_v2
            WHERE tenant_id=$tenant AND context_key=$context
              AND observed_at_utc >= $from AND observed_at_utc <= $to
            ORDER BY observed_at_utc DESC, observation_id ASC LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$context", TemporalContextKey(firstNodeId, secondNodeId));
        cmd.Parameters.AddWithValue("$from", TemporalText(fromObservedAtUtc));
        cmd.Parameters.AddWithValue("$to", TemporalText(toObservedAtUtc));
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
        var items = new List<ThreatObservation>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var item = JsonSerializer.Deserialize<ThreatObservation>(reader.GetString(0), JsonOptions);
            if (item is not null) items.Add(item);
        }
        return items;
    }

    public async Task UpsertThreatObservationMembershipAsync(
        ThreatObservationMembership membership,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        membership.TenantId = NormalizeTenantId(membership.TenantId);
        membership.AssignedAtUtc = NormalizeTemporalDate(membership.AssignedAtUtc, DateTimeOffset.UtcNow);
        membership.Confidence = Math.Clamp(membership.Confidence, 0, 1);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var tx = conn.BeginTransaction();
            var wasActive = false;
            await using (var existing = conn.CreateCommand())
            {
                existing.Transaction = tx;
                existing.CommandText =
                    """
                    SELECT active FROM threat_observation_memberships_v2
                    WHERE tenant_id=$tenant AND campaign_id=$campaign AND observation_id=$observation;
                    """;
                existing.Parameters.AddWithValue("$tenant", membership.TenantId);
                existing.Parameters.AddWithValue("$campaign", membership.CampaignId);
                existing.Parameters.AddWithValue("$observation", membership.ObservationId);
                var value = await existing.ExecuteScalarAsync(cancellationToken);
                wasActive = value is not null && value != DBNull.Value && Convert.ToInt32(value) == 1;
            }
            await InsertMembershipAsync(conn, tx, membership, cancellationToken);
            if (membership.Active && !wasActive)
            {
                await using var read = conn.CreateCommand();
                read.Transaction = tx;
                read.CommandText =
                    """
                    SELECT payload FROM threat_observations_v2
                    WHERE tenant_id=$tenant AND observation_id=$observation
                      AND payload <> '{}' LIMIT 1;
                    """;
                read.Parameters.AddWithValue("$tenant", membership.TenantId);
                read.Parameters.AddWithValue("$observation", membership.ObservationId);
                var payload = await read.ExecuteScalarAsync(cancellationToken) as string;
                var observation = payload is null
                    ? null
                    : JsonSerializer.Deserialize<ThreatObservation>(payload, JsonOptions);
                if (observation is not null)
                {
                    observation.TenantId = membership.TenantId;
                    observation.CampaignId = membership.CampaignId;
                    var contactInserted = await InsertContactAsync(conn, tx, observation, cancellationToken);
                    if (!contactInserted)
                        await UpdateContactAsync(conn, tx, observation, cancellationToken);
                    var episodeDelta = await AssignEpisodeAsync(conn, tx, observation, cancellationToken);
                    await UpdateTemporalStatsAsync(
                        conn, tx, observation, contactInserted, episodeDelta, cancellationToken);
                }
            }
            await tx.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkThreatCampaignMergedAsync(
        string tenantId,
        string campaignId,
        string mergedIntoCampaignId,
        DateTimeOffset tombstonedAtUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                UPDATE threat_campaigns_v2 SET
                    status='Merged', merged_into_campaign_id=$merged_into,
                    tombstoned_at_utc=$tombstoned, updated_at_utc=MAX(updated_at_utc, $tombstoned),
                    revision=revision + 1
                WHERE tenant_id=$tenant AND campaign_id=$campaign;
                """;
            cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
            cmd.Parameters.AddWithValue("$campaign", campaignId);
            cmd.Parameters.AddWithValue("$merged_into", mergedIntoCampaignId);
            cmd.Parameters.AddWithValue("$tombstoned", TemporalText(tombstonedAtUtc));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ThreatObservation>> ListThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterObservedAtUtc,
        string? afterObservationId,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT o.payload, em.episode_id FROM threat_observations_v2 o
            INNER JOIN threat_observation_memberships_v2 m
              ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
             AND m.campaign_id=$campaign AND m.active=1
            LEFT JOIN threat_episode_memberships_v2 em
              ON em.tenant_id=o.tenant_id AND em.observation_id=o.observation_id
             AND em.campaign_id=$campaign
            WHERE o.tenant_id=$tenant AND o.ingested_at_utc <= $watermark
              AND o.payload <> '{}'
              AND ($from IS NULL OR o.observed_at_utc >= $from)
              AND ($to IS NULL OR o.observed_at_utc <= $to)
              AND ($after_time IS NULL OR o.observed_at_utc > $after_time
                   OR (o.observed_at_utc = $after_time AND o.observation_id > $after_id))
            ORDER BY o.observed_at_utc ASC, o.observation_id ASC
            LIMIT $take;
            """;
        AddTimelineParameters(cmd, tenantId, campaignId, watermarkUtc, fromObservedAtUtc,
            toObservedAtUtc, afterObservedAtUtc, afterObservationId, take);
        var items = new List<ThreatObservation>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var item = JsonSerializer.Deserialize<ThreatObservation>(reader.GetString(0), JsonOptions);
            if (item is not null)
            {
                item.TenantId = NormalizeTenantId(tenantId);
                item.CampaignId = campaignId;
                item.EpisodeId = reader.IsDBNull(1) ? null : reader.GetString(1);
                items.Add(item);
            }
        }
        return items;
    }

    public Task<long> CountThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        CountThreatObservationsCoreAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc,
            detailsOnly: false, cancellationToken);

    public Task<long> CountThreatObservationDetailsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        CountThreatObservationsCoreAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc,
            detailsOnly: true, cancellationToken);

    private async Task<long> CountThreatObservationsCoreAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        bool detailsOnly,
        CancellationToken cancellationToken)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT COALESCE(SUM(o.occurrence_count), 0) FROM threat_observations_v2 o
            INNER JOIN threat_observation_memberships_v2 m
              ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
             AND m.campaign_id=$campaign AND m.active=1
            WHERE o.tenant_id=$tenant AND o.ingested_at_utc <= $watermark
              AND ($details_only=0 OR o.payload <> '{}')
              AND ($from IS NULL OR o.observed_at_utc >= $from)
              AND ($to IS NULL OR o.observed_at_utc <= $to);
            """;
        AddTimelineParameters(cmd, tenantId, campaignId, watermarkUtc, fromObservedAtUtc,
            toObservedAtUtc, null, null, 1);
        cmd.Parameters.AddWithValue("$details_only", detailsOnly ? 1 : 0);
        var value = await cmd.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(value ?? 0);
    }

    public async Task<IReadOnlyList<ThreatTimelineBucket>> ListThreatTimelineBucketsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        int resolutionSeconds,
        DateTimeOffset? afterBucketStartUtc,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        var seconds = resolutionSeconds is 60 or 300 or 3600 ? resolutionSeconds : 60;
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            WITH bucketed AS (
                SELECT (CAST(strftime('%s', observed_at_utc) AS INTEGER) / $seconds) * $seconds AS bucket_epoch,
                       o.kind, SUM(o.occurrence_count) AS occurrence_count
                FROM threat_observations_v2 o
                INNER JOIN threat_observation_memberships_v2 m
                  ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
                 AND m.campaign_id=$campaign AND m.active=1
                WHERE o.tenant_id=$tenant AND o.ingested_at_utc <= $watermark
                  AND ($from IS NULL OR o.observed_at_utc >= $from)
                  AND ($to IS NULL OR o.observed_at_utc <= $to)
                GROUP BY bucket_epoch, kind
            ), selected AS (
                SELECT bucket_epoch FROM bucketed
                WHERE ($after_epoch IS NULL OR bucket_epoch > $after_epoch)
                GROUP BY bucket_epoch ORDER BY bucket_epoch ASC LIMIT $take
            )
            SELECT bucketed.bucket_epoch, bucketed.kind, bucketed.occurrence_count
            FROM bucketed INNER JOIN selected USING(bucket_epoch)
            ORDER BY bucketed.bucket_epoch ASC, bucketed.kind ASC;
            """;
        cmd.Parameters.AddWithValue("$seconds", seconds);
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$campaign", campaignId);
        cmd.Parameters.AddWithValue("$watermark", TemporalText(watermarkUtc));
        cmd.Parameters.AddWithValue("$from", fromObservedAtUtc.HasValue ? TemporalText(fromObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", toObservedAtUtc.HasValue ? TemporalText(toObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_epoch", afterBucketStartUtc.HasValue
            ? afterBucketStartUtc.Value.ToUniversalTime().ToUnixTimeSeconds()
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
        var buckets = new SortedDictionary<long, ThreatTimelineBucket>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var epoch = reader.GetInt64(0);
            if (!buckets.TryGetValue(epoch, out var bucket))
            {
                var start = DateTimeOffset.FromUnixTimeSeconds(epoch);
                bucket = new ThreatTimelineBucket { StartUtc = start, EndUtc = start.AddSeconds(seconds) };
                buckets[epoch] = bucket;
            }
            var count = reader.GetInt64(2);
            bucket.Count += count;
            bucket.Kinds[reader.GetString(1)] = count;
        }
        return buckets.Values.ToList();
    }

    public async Task<IReadOnlyList<ThreatContactAggregate>> ListThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterContactId,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            WITH filtered AS (
                SELECT contact_id,
                       MIN(observed_at_utc) AS first_observed_utc,
                       MAX(observed_at_utc) AS last_observed_utc,
                       MAX(ingested_at_utc) AS updated_at_utc,
                       SUM(occurrence_count) AS observation_count,
                       COUNT(*) AS observation_record_count,
                       MAX(0, SUM(occurrence_count) - 1) AS recurrence_count,
                       SUM(CASE WHEN kind='authentication_failure' THEN occurrence_count ELSE 0 END) AS auth_failure_count,
                       SUM(CASE WHEN kind='authentication_success' THEN occurrence_count ELSE 0 END) AS auth_success_count,
                       SUM(CASE WHEN kind='network_open' THEN occurrence_count ELSE 0 END) AS open_count,
                       SUM(CASE WHEN kind='network_close' THEN occurrence_count ELSE 0 END) AS close_count,
                       CASE WHEN MIN(m.provenance)=MAX(m.provenance)
                            THEN MIN(m.provenance) ELSE 'mixed' END AS provenance
                FROM threat_observations_v2 o
                INNER JOIN threat_observation_memberships_v2 m
                  ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
                 AND m.campaign_id=$campaign AND m.active=1
                WHERE o.tenant_id=$tenant AND o.ingested_at_utc <= $watermark
                  AND ($from IS NULL OR o.observed_at_utc >= $from)
                  AND ($to IS NULL OR o.observed_at_utc <= $to)
                GROUP BY o.contact_id
            )
            SELECT c.contact_id, c.source_node_id, c.destination_node_id, c.relation, c.technique, c.protocol,
                   c.local_port, c.remote_port, f.first_observed_utc, f.last_observed_utc, f.updated_at_utc,
                   f.observation_count, f.observation_record_count, f.recurrence_count,
                   f.auth_failure_count, f.auth_success_count, f.open_count, f.close_count,
                   c.inferred, c.confidence, c.last_observation_id,
                   c.median_gap_seconds, c.p95_gap_seconds, c.beacon_score, c.evidence_refs_json,
                   c.sample_payload, c.tenant_id, c.campaign_id, f.provenance
            FROM filtered f INNER JOIN threat_contacts_v2 c
              ON c.tenant_id=$tenant AND c.campaign_id=$campaign AND c.contact_id=f.contact_id
            WHERE ($after_last IS NULL OR f.last_observed_utc < $after_last
                   OR (f.last_observed_utc = $after_last AND c.contact_id > $after_id))
            ORDER BY f.last_observed_utc DESC, c.contact_id ASC
            LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$campaign", campaignId);
        cmd.Parameters.AddWithValue("$watermark", TemporalText(watermarkUtc));
        cmd.Parameters.AddWithValue("$from", fromObservedAtUtc.HasValue ? TemporalText(fromObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", toObservedAtUtc.HasValue ? TemporalText(toObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_last", afterLastObservedAtUtc.HasValue
            ? TemporalText(afterLastObservedAtUtc.Value)
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_id", afterContactId ?? string.Empty);
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
        var items = new List<ThreatContactAggregate>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) items.Add(ReadContact(reader));
        return items;
    }

    public async Task<long> CountThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT COUNT(DISTINCT o.contact_id) FROM threat_observations_v2 o
            INNER JOIN threat_observation_memberships_v2 m
              ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
             AND m.campaign_id=$campaign AND m.active=1
            WHERE o.tenant_id=$tenant AND o.ingested_at_utc <= $watermark
              AND ($from IS NULL OR o.observed_at_utc >= $from)
              AND ($to IS NULL OR o.observed_at_utc <= $to);
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$campaign", campaignId);
        cmd.Parameters.AddWithValue("$watermark", TemporalText(watermarkUtc));
        cmd.Parameters.AddWithValue("$from", fromObservedAtUtc.HasValue ? TemporalText(fromObservedAtUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", toObservedAtUtc.HasValue ? TemporalText(toObservedAtUtc.Value) : DBNull.Value);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0);
    }

    public async Task EnqueueTemporalCorrelationWorkAsync(
        TemporalCorrelationWorkItem item,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT OR IGNORE INTO temporal_correlation_outbox_v2(
                    work_id, tenant_id, payload_json, enqueued_at_utc, attempts, next_attempt_utc)
                VALUES ($id, $tenant, $payload, $enqueued, 0, $enqueued);
                """;
            cmd.Parameters.AddWithValue("$id", BoundTemporal(item.WorkId, 128));
            cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(item.TenantId));
            cmd.Parameters.AddWithValue("$payload", item.PayloadJson);
            var enqueued = NormalizeTemporalDate(item.EnqueuedAtUtc, DateTimeOffset.UtcNow);
            cmd.Parameters.AddWithValue("$enqueued", TemporalText(enqueued));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TemporalCorrelationWorkItem>> LeaseTemporalCorrelationWorkAsync(
        string leaseOwner,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var tx = conn.BeginTransaction();
            var candidates = new List<TemporalCorrelationWorkItem>();
            await using (var select = conn.CreateCommand())
            {
                select.Transaction = tx;
                select.CommandText =
                    """
                    SELECT work_id, tenant_id, payload_json, enqueued_at_utc, attempts, last_error
                    FROM temporal_correlation_outbox_v2
                    WHERE next_attempt_utc <= $now
                      AND (lease_until_utc IS NULL OR lease_until_utc <= $now)
                    ORDER BY enqueued_at_utc ASC, work_id ASC
                    LIMIT $take;
                    """;
                select.Parameters.AddWithValue("$now", TemporalText(nowUtc));
                select.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 50));
                await using var reader = await select.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    candidates.Add(new TemporalCorrelationWorkItem
                    {
                        WorkId = reader.GetString(0),
                        TenantId = reader.GetString(1),
                        PayloadJson = reader.GetString(2),
                        EnqueuedAtUtc = DateTimeOffset.Parse(reader.GetString(3)),
                        Attempts = reader.GetInt32(4),
                        LastError = reader.IsDBNull(5) ? null : reader.GetString(5)
                    });
                }
            }

            var leased = new List<TemporalCorrelationWorkItem>(candidates.Count);
            var leaseUntil = nowUtc.Add(leaseDuration > TimeSpan.Zero ? leaseDuration : TimeSpan.FromMinutes(2));
            foreach (var item in candidates)
            {
                await using var update = conn.CreateCommand();
                update.Transaction = tx;
                update.CommandText =
                    """
                    UPDATE temporal_correlation_outbox_v2 SET
                        lease_owner=$owner, lease_until_utc=$lease_until, attempts=attempts + 1
                    WHERE work_id=$id AND (lease_until_utc IS NULL OR lease_until_utc <= $now);
                    """;
                update.Parameters.AddWithValue("$owner", BoundTemporal(leaseOwner, 128));
                update.Parameters.AddWithValue("$lease_until", TemporalText(leaseUntil));
                update.Parameters.AddWithValue("$id", item.WorkId);
                update.Parameters.AddWithValue("$now", TemporalText(nowUtc));
                if (await update.ExecuteNonQueryAsync(cancellationToken) == 1)
                {
                    item.Attempts++;
                    item.LeaseOwner = leaseOwner;
                    item.LeaseUntilUtc = leaseUntil;
                    leased.Add(item);
                }
            }
            await tx.CommitAsync(cancellationToken);
            return leased;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CompleteTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "DELETE FROM temporal_correlation_outbox_v2 WHERE work_id=$id AND lease_owner=$owner;";
        cmd.Parameters.AddWithValue("$id", workId);
        cmd.Parameters.AddWithValue("$owner", leaseOwner);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task FailTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        DateTimeOffset retryAtUtc,
        string error,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            UPDATE temporal_correlation_outbox_v2 SET
                next_attempt_utc=$retry, lease_until_utc=NULL, lease_owner=NULL, last_error=$error
            WHERE work_id=$id AND lease_owner=$owner;
            """;
        cmd.Parameters.AddWithValue("$retry", TemporalText(retryAtUtc));
        cmd.Parameters.AddWithValue("$error", BoundTemporal(error, 2_000));
        cmd.Parameters.AddWithValue("$id", workId);
        cmd.Parameters.AddWithValue("$owner", leaseOwner);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<int> SweepTemporalThreatDataAsync(
        DateTimeOffset detailBeforeUtc,
        DateTimeOffset aggregateBeforeUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var conn = Open();
            await using var tx = conn.BeginTransaction();
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                DELETE FROM threat_episode_memberships_v2
                WHERE EXISTS (
                    SELECT 1 FROM threat_observations_v2 o
                    WHERE o.tenant_id=threat_episode_memberships_v2.tenant_id
                      AND o.observation_id=threat_episode_memberships_v2.observation_id
                      AND o.observed_at_utc < $aggregate);
                DELETE FROM threat_observation_memberships_v2
                WHERE EXISTS (
                    SELECT 1 FROM threat_observations_v2 o
                    WHERE o.tenant_id=threat_observation_memberships_v2.tenant_id
                      AND o.observation_id=threat_observation_memberships_v2.observation_id
                      AND o.observed_at_utc < $aggregate);
                UPDATE threat_observations_v2
                    SET payload='{}', incident_id=NULL, campaign_id='', episode_id=NULL
                    WHERE observed_at_utc < $detail AND payload <> '{}';
                DELETE FROM threat_observations_v2 WHERE observed_at_utc < $aggregate;
                DELETE FROM threat_candidate_observations_v2 WHERE observed_at_utc < $detail;
                UPDATE threat_contacts_v2 SET sample_payload='{}', evidence_refs_json='[]'
                    WHERE last_observed_utc < $detail;
                DELETE FROM threat_contacts_v2 WHERE last_observed_utc < $aggregate;
                DELETE FROM threat_episodes_v2 WHERE last_observed_utc < $aggregate;
                DELETE FROM threat_campaign_summary_history_v2
                    WHERE snapshot_at_utc < $aggregate OR last_observed_utc < $aggregate;
                DELETE FROM threat_campaigns_v2 WHERE last_observed_utc < $aggregate;
                """;
            cmd.Parameters.AddWithValue("$detail", TemporalText(detailBeforeUtc));
            cmd.Parameters.AddWithValue("$aggregate", TemporalText(aggregateBeforeUtc));
            var changed = await cmd.ExecuteNonQueryAsync(cancellationToken);
            await tx.CommitAsync(cancellationToken);
            return changed;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string?> GetTemporalBackfillCursorAsync(
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT cursor_value FROM temporal_backfill_state_v2 WHERE state_key='legacy_campaigns';";
        return await cmd.ExecuteScalarAsync(cancellationToken) as string;
    }

    public async Task SaveTemporalBackfillCursorAsync(
        string? campaignId,
        CancellationToken cancellationToken = default)
    {
        await EnsureTemporalThreatSchemaAsync(cancellationToken);
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO temporal_backfill_state_v2(state_key, cursor_value, updated_at_utc)
            VALUES ('legacy_campaigns', $cursor, $updated)
            ON CONFLICT(state_key) DO UPDATE SET
                cursor_value=excluded.cursor_value, updated_at_utc=excluded.updated_at_utc;
            """;
        cmd.Parameters.AddWithValue("$cursor", (object?)campaignId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$updated", TemporalText(DateTimeOffset.UtcNow));
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private const string TemporalSummarySelect =
        """
        SELECT tenant_id, campaign_id, revision, status, severity, confidence,
               first_observed_utc, last_observed_utc, updated_at_utc,
               observation_count, episode_count, edge_count, contact_count, recurrence_count,
               affected_asset_count, related_incident_count, related_incident_ids_json,
               merged_into_campaign_id, tombstoned_at_utc,
               involved_hosts_json, involved_ips_json, title, summary, updated_at_utc
        FROM threat_campaigns_v2
        """;

    private static ThreatCampaignV2Summary ReadTemporalSummary(SqliteDataReader reader) => new()
    {
        TenantId = reader.GetString(0),
        CampaignId = reader.GetString(1),
        Revision = reader.GetInt64(2),
        Status = reader.GetString(3),
        Severity = reader.GetString(4),
        Confidence = reader.IsDBNull(5) ? null : reader.GetDouble(5),
        FirstObservedAtUtc = DateTimeOffset.Parse(reader.GetString(6)),
        LastObservedAtUtc = DateTimeOffset.Parse(reader.GetString(7)),
        UpdatedAtUtc = DateTimeOffset.Parse(reader.GetString(8)),
        ObservationCount = reader.GetInt64(9),
        EpisodeCount = reader.GetInt64(10),
        EdgeCount = reader.GetInt64(11),
        ContactCount = reader.GetInt64(12),
        RecurrenceCount = reader.GetInt64(13),
        AffectedAssetCount = reader.GetInt64(14),
        RelatedIncidentCount = reader.GetInt64(15),
        RelatedIncidentIds = JsonSerializer.Deserialize<List<string>>(reader.GetString(16), JsonOptions) ?? [],
        MergedIntoCampaignId = reader.IsDBNull(17) ? null : reader.GetString(17),
        TombstonedAtUtc = reader.IsDBNull(18) ? null : DateTimeOffset.Parse(reader.GetString(18)),
        InvolvedHosts = JsonSerializer.Deserialize<List<string>>(reader.GetString(19), JsonOptions) ?? [],
        InvolvedIps = JsonSerializer.Deserialize<List<string>>(reader.GetString(20), JsonOptions) ?? [],
        Title = reader.GetString(21),
        Summary = reader.GetString(22),
        SnapshotAtUtc = DateTimeOffset.Parse(reader.GetString(23))
    };

    private static ThreatContactAggregate ReadContact(SqliteDataReader reader)
    {
        var sample = JsonSerializer.Deserialize<ThreatObservation>(reader.GetString(25), JsonOptions) ?? new();
        return new ThreatContactAggregate
        {
            ContactId = reader.GetString(0),
            SourceNodeId = reader.GetString(1),
            DestinationNodeId = reader.GetString(2),
            Relation = reader.GetString(3),
            Technique = reader.IsDBNull(4) ? null : reader.GetString(4),
            Protocol = reader.IsDBNull(5) ? null : reader.GetString(5),
            LocalPort = reader.IsDBNull(6) ? null : reader.GetInt32(6),
            RemotePort = reader.IsDBNull(7) ? null : reader.GetInt32(7),
            FirstObservedAtUtc = DateTimeOffset.Parse(reader.GetString(8)),
            LastObservedAtUtc = DateTimeOffset.Parse(reader.GetString(9)),
            UpdatedAtUtc = DateTimeOffset.Parse(reader.GetString(10)),
            ObservationCount = reader.GetInt64(11),
            ObservationRecordCount = reader.GetInt64(12),
            RecurrenceCount = reader.GetInt64(13),
            AuthenticationFailureCount = reader.GetInt64(14),
            AuthenticationSuccessCount = reader.GetInt64(15),
            OpenCount = reader.GetInt64(16),
            CloseCount = reader.GetInt64(17),
            Inferred = reader.GetInt32(18) != 0,
            Confidence = reader.GetDouble(19),
            LastObservationId = reader.GetString(20),
            MedianGapSeconds = reader.IsDBNull(21) ? null : reader.GetDouble(21),
            P95GapSeconds = reader.IsDBNull(22) ? null : reader.GetDouble(22),
            BeaconScore = reader.GetDouble(23),
            EvidenceRefs = JsonSerializer.Deserialize<List<string>>(reader.GetString(24), JsonOptions) ?? [],
            TenantId = reader.GetString(26),
            CampaignId = reader.GetString(27),
            SourceIp = sample.SourceIp,
            SourceHost = sample.SourceHost,
            SourceAgentId = sample.SourceAgentId,
            DestinationIp = sample.DestinationIp,
            DestinationHost = sample.DestinationHost,
            DestinationAgentId = sample.DestinationAgentId,
            Provenance = reader.GetString(28)
        };
    }

    private static void NormalizeObservation(ThreatObservation observation)
    {
        observation.TenantId = NormalizeTenantId(observation.TenantId);
        observation.ObservedAtUtc = NormalizeTemporalDate(observation.ObservedAtUtc, DateTimeOffset.UtcNow);
        observation.IngestedAtUtc = NormalizeTemporalDate(observation.IngestedAtUtc, DateTimeOffset.UtcNow);
        observation.OccurrenceCount = Math.Clamp(observation.OccurrenceCount, 1, 1_000_000);
        observation.Confidence = Math.Clamp(observation.Confidence, 0, 1);
        observation.Kind = BoundTemporal(observation.Kind, 64);
        observation.Relation = BoundTemporal(observation.Relation, 64);
    }

    private static void AddObservationParameters(SqliteCommand cmd, ThreatObservation observation)
    {
        cmd.Parameters.AddWithValue("$tenant", observation.TenantId);
        cmd.Parameters.AddWithValue("$campaign", observation.CampaignId);
        cmd.Parameters.AddWithValue("$id", observation.ObservationId);
        cmd.Parameters.AddWithValue("$episode", (object?)observation.EpisodeId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$contact", observation.ContactId);
        cmd.Parameters.AddWithValue("$kind", observation.Kind);
        cmd.Parameters.AddWithValue("$observed", TemporalText(observation.ObservedAtUtc));
        cmd.Parameters.AddWithValue("$collected", observation.CollectedAtUtc.HasValue
            ? TemporalText(observation.CollectedAtUtc.Value)
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$ingested", TemporalText(observation.IngestedAtUtc));
        cmd.Parameters.AddWithValue("$occurrences", observation.OccurrenceCount);
        cmd.Parameters.AddWithValue("$incident", (object?)observation.IncidentId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(observation, JsonOptions));
    }

    private static async Task InsertMembershipAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservationMembership membership,
        CancellationToken cancellationToken)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            """
            INSERT INTO threat_observation_memberships_v2(
                tenant_id, campaign_id, observation_id, assigned_at_utc, confidence, provenance, active)
            VALUES ($tenant, $campaign, $observation, $assigned, $confidence, $provenance, $active)
            ON CONFLICT(tenant_id, campaign_id, observation_id) DO UPDATE SET
                assigned_at_utc=excluded.assigned_at_utc,
                confidence=excluded.confidence,
                provenance=excluded.provenance,
                active=excluded.active;
            """;
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(membership.TenantId));
        cmd.Parameters.AddWithValue("$campaign", membership.CampaignId);
        cmd.Parameters.AddWithValue("$observation", membership.ObservationId);
        cmd.Parameters.AddWithValue("$assigned", TemporalText(membership.AssignedAtUtc));
        cmd.Parameters.AddWithValue("$confidence", Math.Clamp(membership.Confidence, 0, 1));
        cmd.Parameters.AddWithValue("$provenance", BoundTemporal(membership.Provenance, 128));
        cmd.Parameters.AddWithValue("$active", membership.Active ? 1 : 0);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> AssignEpisodeAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        CancellationToken cancellationToken)
    {
        const double inactivitySeconds = 60 * 60;
        var previous = await ReadAdjacentEpisodeAsync(conn, tx, observation, previous: true, cancellationToken);
        var next = await ReadAdjacentEpisodeAsync(conn, tx, observation, previous: false, cancellationToken);
        var previousActive = previous is not null &&
            (observation.ObservedAtUtc - previous.Value.ObservedAtUtc).TotalSeconds <= inactivitySeconds;
        var nextActive = next is not null &&
            (next.Value.ObservedAtUtc - observation.ObservedAtUtc).TotalSeconds <= inactivitySeconds;

        var episodeId = previousActive
            ? previous!.Value.EpisodeId
            : nextActive
                ? next!.Value.EpisodeId
                : NewEpisodeId(observation.ObservationId);
        var delta = previousActive || nextActive ? 0 : 1;

        if (previousActive && nextActive &&
            !string.Equals(previous!.Value.EpisodeId, next!.Value.EpisodeId, StringComparison.Ordinal))
        {
            await using var merge = conn.CreateCommand();
            merge.Transaction = tx;
            merge.CommandText =
                """
                UPDATE threat_episode_memberships_v2 SET episode_id=$target
                WHERE tenant_id=$tenant AND campaign_id=$campaign AND episode_id=$source;
                DELETE FROM threat_episodes_v2
                WHERE tenant_id=$tenant AND campaign_id=$campaign AND episode_id=$source;
                """;
            merge.Parameters.AddWithValue("$tenant", observation.TenantId);
            merge.Parameters.AddWithValue("$campaign", observation.CampaignId);
            merge.Parameters.AddWithValue("$target", episodeId);
            merge.Parameters.AddWithValue("$source", next.Value.EpisodeId);
            await merge.ExecuteNonQueryAsync(cancellationToken);
            delta = -1;
        }

        await using (var membership = conn.CreateCommand())
        {
            membership.Transaction = tx;
            membership.CommandText =
                """
                INSERT INTO threat_episode_memberships_v2(
                    tenant_id, campaign_id, observation_id, episode_id, assigned_at_utc)
                VALUES ($tenant, $campaign, $observation, $episode, $assigned)
                ON CONFLICT(tenant_id, campaign_id, observation_id) DO UPDATE SET
                    episode_id=excluded.episode_id, assigned_at_utc=excluded.assigned_at_utc;
                """;
            membership.Parameters.AddWithValue("$tenant", observation.TenantId);
            membership.Parameters.AddWithValue("$campaign", observation.CampaignId);
            membership.Parameters.AddWithValue("$observation", observation.ObservationId);
            membership.Parameters.AddWithValue("$episode", episodeId);
            membership.Parameters.AddWithValue("$assigned", TemporalText(observation.IngestedAtUtc));
            await membership.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var episode = conn.CreateCommand())
        {
            episode.Transaction = tx;
            episode.CommandText =
                """
                INSERT INTO threat_episodes_v2(
                    tenant_id, campaign_id, episode_id, first_observed_utc, last_observed_utc)
                SELECT $tenant, $campaign, $episode, MIN(o.observed_at_utc), MAX(o.observed_at_utc)
                FROM threat_episode_memberships_v2 em
                INNER JOIN threat_observations_v2 o
                  ON o.tenant_id=em.tenant_id AND o.observation_id=em.observation_id
                WHERE em.tenant_id=$tenant AND em.campaign_id=$campaign AND em.episode_id=$episode
                ON CONFLICT(tenant_id, campaign_id, episode_id) DO UPDATE SET
                    first_observed_utc=excluded.first_observed_utc,
                    last_observed_utc=excluded.last_observed_utc;
                """;
            episode.Parameters.AddWithValue("$tenant", observation.TenantId);
            episode.Parameters.AddWithValue("$campaign", observation.CampaignId);
            episode.Parameters.AddWithValue("$episode", episodeId);
            await episode.ExecuteNonQueryAsync(cancellationToken);
        }

        observation.EpisodeId = episodeId;
        return delta;
    }

    private static async Task<(DateTimeOffset ObservedAtUtc, string EpisodeId)?> ReadAdjacentEpisodeAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        bool previous,
        CancellationToken cancellationToken)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        var comparison = previous
            ? "(o.observed_at_utc < $observed OR (o.observed_at_utc = $observed AND o.observation_id < $observation))"
            : "(o.observed_at_utc > $observed OR (o.observed_at_utc = $observed AND o.observation_id > $observation))";
        var order = previous ? "DESC" : "ASC";
        cmd.CommandText =
            $"""
            SELECT o.observed_at_utc, em.episode_id
            FROM threat_observations_v2 o
            INNER JOIN threat_observation_memberships_v2 m
              ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
             AND m.campaign_id=$campaign AND m.active=1
            INNER JOIN threat_episode_memberships_v2 em
              ON em.tenant_id=o.tenant_id AND em.observation_id=o.observation_id
             AND em.campaign_id=$campaign
            WHERE o.tenant_id=$tenant AND {comparison}
            ORDER BY o.observed_at_utc {order}, o.observation_id {order}
            LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$tenant", observation.TenantId);
        cmd.Parameters.AddWithValue("$campaign", observation.CampaignId);
        cmd.Parameters.AddWithValue("$observed", TemporalText(observation.ObservedAtUtc));
        cmd.Parameters.AddWithValue("$observation", observation.ObservationId);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (DateTimeOffset.Parse(reader.GetString(0)), reader.GetString(1))
            : null;
    }

    private static string NewEpisodeId(string observationId)
    {
        var suffix = observationId.StartsWith("observation-", StringComparison.Ordinal)
            ? observationId["observation-".Length..]
            : observationId;
        return "episode-" + BoundTemporal(suffix, 56);
    }

    private static string TemporalContextKey(string firstNodeId, string secondNodeId) =>
        string.Compare(firstNodeId, secondNodeId, StringComparison.Ordinal) <= 0
            ? $"{firstNodeId}|{secondNodeId}"
            : $"{secondNodeId}|{firstNodeId}";

    private static async Task<bool> InsertContactAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        CancellationToken cancellationToken)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            """
            INSERT OR IGNORE INTO threat_contacts_v2(
                tenant_id, campaign_id, contact_id, source_node_id, destination_node_id,
                relation, technique, protocol, local_port, remote_port,
                first_observed_utc, last_observed_utc, updated_at_utc,
                observation_count, observation_record_count, recurrence_count,
                auth_failure_count, auth_success_count, open_count, close_count,
                inferred, confidence, last_observation_id,
                median_gap_seconds, p95_gap_seconds, beacon_score, gap_samples_json, evidence_refs_json,
                sample_payload)
            VALUES ($tenant, $campaign, $contact, $source, $destination,
                $relation, $technique, $protocol, $local_port, $remote_port,
                $observed, $observed, $updated, $count, 1, $recurrences,
                $auth_fail, $auth_success, $opened, $closed,
                $inferred, $confidence, $observation,
                NULL, NULL, 0, '[]', $evidence_refs, $payload);
            """;
        AddContactParameters(cmd, observation);
        return await cmd.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private static async Task UpdateContactAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        CancellationToken cancellationToken)
    {
        var metrics = await ReadAndExtendContactMetricsAsync(conn, tx, observation, cancellationToken);
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            """
            UPDATE threat_contacts_v2 SET
                first_observed_utc=MIN(first_observed_utc, $observed),
                last_observed_utc=MAX(last_observed_utc, $observed),
                updated_at_utc=MAX(updated_at_utc, $updated),
                observation_count=observation_count + $count,
                observation_record_count=observation_record_count + 1,
                recurrence_count=recurrence_count + $count,
                auth_failure_count=auth_failure_count + $auth_fail,
                auth_success_count=auth_success_count + $auth_success,
                open_count=open_count + $opened,
                close_count=close_count + $closed,
                inferred=CASE WHEN inferred=1 AND $inferred=1 THEN 1 ELSE 0 END,
                confidence=MAX(confidence, $confidence),
                last_observation_id=CASE WHEN $observed >= last_observed_utc
                    THEN $observation ELSE last_observation_id END,
                median_gap_seconds=$median_gap,
                p95_gap_seconds=$p95_gap,
                beacon_score=$beacon_score,
                gap_samples_json=$gap_samples,
                evidence_refs_json=$evidence_refs,
                sample_payload=CASE WHEN $observed >= last_observed_utc
                    THEN $payload ELSE sample_payload END
            WHERE tenant_id=$tenant AND campaign_id=$campaign AND contact_id=$contact;
            """;
        AddContactParameters(cmd, observation);
        cmd.Parameters.AddWithValue("$median_gap", (object?)metrics.MedianGapSeconds ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$p95_gap", (object?)metrics.P95GapSeconds ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$beacon_score", metrics.BeaconScore);
        cmd.Parameters.AddWithValue("$gap_samples", JsonSerializer.Serialize(metrics.Gaps, JsonOptions));
        cmd.Parameters["$evidence_refs"].Value = JsonSerializer.Serialize(metrics.EvidenceRefs, JsonOptions);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddContactParameters(SqliteCommand cmd, ThreatObservation observation)
    {
        var kind = observation.Kind.ToLowerInvariant();
        cmd.Parameters.AddWithValue("$tenant", observation.TenantId);
        cmd.Parameters.AddWithValue("$campaign", observation.CampaignId);
        cmd.Parameters.AddWithValue("$contact", observation.ContactId);
        cmd.Parameters.AddWithValue("$source", observation.SourceNodeId);
        cmd.Parameters.AddWithValue("$destination", observation.DestinationNodeId);
        cmd.Parameters.AddWithValue("$relation", observation.Relation);
        cmd.Parameters.AddWithValue("$technique", (object?)observation.Technique ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$protocol", (object?)observation.Protocol ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$local_port", (object?)observation.LocalPort ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$remote_port", (object?)observation.RemotePort ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$observed", TemporalText(observation.ObservedAtUtc));
        cmd.Parameters.AddWithValue("$updated", TemporalText(observation.IngestedAtUtc));
        cmd.Parameters.AddWithValue("$count", observation.OccurrenceCount);
        cmd.Parameters.AddWithValue("$recurrences", Math.Max(0, observation.OccurrenceCount - 1));
        cmd.Parameters.AddWithValue("$auth_fail", kind == "authentication_failure" ? observation.OccurrenceCount : 0);
        cmd.Parameters.AddWithValue("$auth_success", kind == "authentication_success" ? observation.OccurrenceCount : 0);
        cmd.Parameters.AddWithValue("$opened", kind == "network_open" ? observation.OccurrenceCount : 0);
        cmd.Parameters.AddWithValue("$closed", kind == "network_close" ? observation.OccurrenceCount : 0);
        cmd.Parameters.AddWithValue("$inferred", observation.Inferred ? 1 : 0);
        cmd.Parameters.AddWithValue("$confidence", observation.Confidence);
        cmd.Parameters.AddWithValue("$observation", observation.ObservationId);
        cmd.Parameters.AddWithValue("$evidence_refs", JsonSerializer.Serialize(
            string.IsNullOrWhiteSpace(observation.EvidenceId) ? Array.Empty<string>() : [observation.EvidenceId],
            JsonOptions));
        cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(observation, JsonOptions));
    }

    private static async Task<TemporalContactMetrics> ReadAndExtendContactMetricsAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        CancellationToken cancellationToken)
    {
        var evidenceRefs = new List<string>();
        await using (var read = conn.CreateCommand())
        {
            read.Transaction = tx;
            read.CommandText =
                """
                SELECT evidence_refs_json
                FROM threat_contacts_v2
                WHERE tenant_id=$tenant AND campaign_id=$campaign AND contact_id=$contact
                LIMIT 1;
                """;
            read.Parameters.AddWithValue("$tenant", observation.TenantId);
            read.Parameters.AddWithValue("$campaign", observation.CampaignId);
            read.Parameters.AddWithValue("$contact", observation.ContactId);
            await using var reader = await read.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
                evidenceRefs = JsonSerializer.Deserialize<List<string>>(reader.GetString(0), JsonOptions) ?? [];
        }

        var timestamps = new List<DateTimeOffset>(65);
        await using (var chronological = conn.CreateCommand())
        {
            chronological.Transaction = tx;
            chronological.CommandText =
                """
                SELECT o.observed_at_utc FROM threat_observations_v2 o
                INNER JOIN threat_observation_memberships_v2 m
                  ON m.tenant_id=o.tenant_id AND m.observation_id=o.observation_id
                 AND m.campaign_id=$campaign AND m.active=1
                WHERE o.tenant_id=$tenant AND o.contact_id=$contact
                ORDER BY o.observed_at_utc DESC, o.observation_id DESC LIMIT 65;
                """;
            chronological.Parameters.AddWithValue("$tenant", observation.TenantId);
            chronological.Parameters.AddWithValue("$campaign", observation.CampaignId);
            chronological.Parameters.AddWithValue("$contact", observation.ContactId);
            await using var reader = await chronological.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                timestamps.Add(DateTimeOffset.Parse(reader.GetString(0)));
        }
        timestamps.Sort();
        var gaps = timestamps.Zip(timestamps.Skip(1), (left, right) =>
                Math.Round((right - left).TotalSeconds, 3))
            .Where(value => value > 0 && double.IsFinite(value)).TakeLast(64).ToList();
        if (!string.IsNullOrWhiteSpace(observation.EvidenceId)) evidenceRefs.Add(observation.EvidenceId);
        evidenceRefs = evidenceRefs.Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase).TakeLast(32).ToList();

        if (gaps.Count == 0) return new TemporalContactMetrics(gaps, evidenceRefs, null, null, 0);
        var ordered = gaps.Order().ToList();
        var median = ordered.Count % 2 == 0
            ? (ordered[ordered.Count / 2 - 1] + ordered[ordered.Count / 2]) / 2
            : ordered[ordered.Count / 2];
        var p95 = ordered[Math.Clamp((int)Math.Ceiling(ordered.Count * .95) - 1, 0, ordered.Count - 1)];
        var mean = ordered.Average();
        var variance = ordered.Sum(value => Math.Pow(value - mean, 2)) / ordered.Count;
        var periodicity = mean <= 0 ? 0 : Math.Clamp(1 - Math.Sqrt(variance) / mean, 0, 1);
        var beaconScore = Math.Round(periodicity * Math.Min(1, ordered.Count / 5d), 4);
        return new TemporalContactMetrics(gaps, evidenceRefs, median, p95, beaconScore);
    }

    private static async Task UpdateTemporalStatsAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        ThreatObservation observation,
        bool contactInserted,
        int episodeDelta,
        CancellationToken cancellationToken)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            """
            INSERT INTO threat_campaigns_v2(
                tenant_id, campaign_id, revision, status, severity,
                first_observed_utc, last_observed_utc, updated_at_utc,
                observation_count, episode_count, edge_count, contact_count, recurrence_count,
                involved_hosts_json, involved_ips_json, title, summary)
            VALUES ($tenant, $campaign, 1, 'Open', 'Informational',
                $observed, $observed, $updated, $count, $episode_delta,
                $contact_delta, $contact_delta, $recurrences, '[]', '[]', '', '')
            ON CONFLICT(tenant_id, campaign_id) DO UPDATE SET
                revision=threat_campaigns_v2.revision + 1,
                first_observed_utc=MIN(threat_campaigns_v2.first_observed_utc, excluded.first_observed_utc),
                last_observed_utc=MAX(threat_campaigns_v2.last_observed_utc, excluded.last_observed_utc),
                updated_at_utc=MAX(threat_campaigns_v2.updated_at_utc, excluded.updated_at_utc),
                observation_count=threat_campaigns_v2.observation_count + excluded.observation_count,
                episode_count=threat_campaigns_v2.episode_count + excluded.episode_count,
                edge_count=threat_campaigns_v2.edge_count + excluded.edge_count,
                contact_count=threat_campaigns_v2.contact_count + excluded.contact_count,
                recurrence_count=threat_campaigns_v2.recurrence_count + excluded.recurrence_count;
            """;
        cmd.Parameters.AddWithValue("$tenant", observation.TenantId);
        cmd.Parameters.AddWithValue("$campaign", observation.CampaignId);
        cmd.Parameters.AddWithValue("$observed", TemporalText(observation.ObservedAtUtc));
        cmd.Parameters.AddWithValue("$updated", TemporalText(observation.IngestedAtUtc));
        cmd.Parameters.AddWithValue("$count", observation.OccurrenceCount);
        cmd.Parameters.AddWithValue("$episode_delta", episodeDelta);
        cmd.Parameters.AddWithValue("$contact_delta", contactInserted ? 1 : 0);
        cmd.Parameters.AddWithValue("$recurrences", contactInserted
            ? Math.Max(0, observation.OccurrenceCount - 1)
            : observation.OccurrenceCount);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddTimelineParameters(
        SqliteCommand cmd,
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? from,
        DateTimeOffset? to,
        DateTimeOffset? after,
        string? afterId,
        int take)
    {
        cmd.Parameters.AddWithValue("$tenant", NormalizeTenantId(tenantId));
        cmd.Parameters.AddWithValue("$campaign", campaignId);
        cmd.Parameters.AddWithValue("$watermark", TemporalText(watermarkUtc));
        cmd.Parameters.AddWithValue("$from", from.HasValue ? TemporalText(from.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$to", to.HasValue ? TemporalText(to.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_time", after.HasValue ? TemporalText(after.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$after_id", afterId ?? string.Empty);
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 501));
    }

    private static DateTimeOffset NormalizeTemporalDate(DateTimeOffset value, DateTimeOffset fallback) =>
        value == default || value == DateTimeOffset.MinValue ? fallback.ToUniversalTime() : value.ToUniversalTime();

    private static string TemporalText(DateTimeOffset value) => value.ToUniversalTime().ToString("O");

    private static string BoundTemporal(string? value, int maxLength)
    {
        var clean = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    private sealed record TemporalContactMetrics(
        List<double> Gaps,
        List<string> EvidenceRefs,
        double? MedianGapSeconds,
        double? P95GapSeconds,
        double BeaconScore);
}
