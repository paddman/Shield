using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Capture;

/// <summary>
/// Durable, provider-neutral capture control-plane state. Packet bytes never enter
/// this database; only opaque provider references are persisted for audited access.
/// </summary>
public sealed class SqliteCaptureControlStore : ICaptureControlStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly CaptureControlOptions _options;
    private readonly ILogger<SqliteCaptureControlStore> _logger;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private volatile bool _initialized;

    public SqliteCaptureControlStore(
        IOptions<CaptureControlOptions> options,
        ILogger<SqliteCaptureControlStore> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized) return;
        await _initializeLock.WaitAsync(cancellationToken);
        try
        {
            if (_initialized) return;
            var fullPath = Path.GetFullPath(_options.DatabasePath);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);

            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);
            await ExecuteNonQueryAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
            await ExecuteNonQueryAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken);
            await ExecuteNonQueryAsync(connection, Schema, cancellationToken);
            await EnsureColumnAsync(connection, "capture_sessions", "campaign_id", "TEXT", cancellationToken);
            await EnsureColumnAsync(connection, "capture_sessions", "edge_id", "TEXT", cancellationToken);
            await EnsureColumnAsync(connection, "capture_sessions", "tls_artifact_reference", "TEXT", cancellationToken);
            await EnsureColumnAsync(connection, "capture_audit", "purpose", "TEXT", cancellationToken);
            await EnsureColumnAsync(connection, "capture_export_jobs", "claim_owner", "TEXT", cancellationToken);
            await EnsureColumnAsync(connection, "capture_export_jobs", "claim_expires_at_utc", "TEXT", cancellationToken);
            await ExecuteNonQueryAsync(connection, """
                CREATE INDEX IF NOT EXISTS idx_capture_sessions_campaign
                    ON capture_sessions(tenant_id, campaign_id, started_at_utc DESC);
                CREATE INDEX IF NOT EXISTS idx_capture_sessions_edge
                    ON capture_sessions(tenant_id, edge_id, started_at_utc DESC);
                """, cancellationToken);
            await ExecuteNonQueryAsync(connection, "PRAGMA user_version=2;", cancellationToken);
            _initialized = true;
            _logger.LogInformation("Capture control-plane database initialized at {Path}", fullPath);
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task<IReadOnlyList<CapturePolicy>> ListPoliciesAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json FROM capture_policies WHERE tenant_id=$tenant ORDER BY name, policy_id;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        return await ReadJsonListAsync<CapturePolicy>(command, cancellationToken);
    }

    public async Task<CapturePolicy?> GetPolicyAsync(
        string tenantId,
        string policyId,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json FROM capture_policies WHERE tenant_id=$tenant AND policy_id=$id;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$id", policyId);
        return await ReadJsonSingleAsync<CapturePolicy>(command, cancellationToken);
    }

    public async Task<bool> CreatePolicyMutationAsync(
        CapturePolicy policy,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO capture_policies
                (tenant_id, policy_id, version, name, enabled, provider_id, policy_json, created_at_utc, updated_at_utc)
            VALUES ($tenant, $id, $version, $name, $enabled, $provider, $json, $created, $updated);
        """;
        BindPolicy(command, policy);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }
        await InsertAuditAsync(connection, transaction, audit, cancellationToken);
        await InsertPolicyDispatchAsync(connection, transaction, dispatch, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<bool> TryUpdatePolicyMutationAsync(
        CapturePolicy policy,
        int expectedVersion,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE capture_policies
            SET version=$version, name=$name, enabled=$enabled, provider_id=$provider,
                policy_json=$json, updated_at_utc=$updated
            WHERE tenant_id=$tenant AND policy_id=$id AND version=$expected;
            """;
        BindPolicy(command, policy);
        command.Parameters.AddWithValue("$expected", expectedVersion);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }
        await InsertAuditAsync(connection, transaction, audit, cancellationToken);
        await InsertPolicyDispatchAsync(connection, transaction, dispatch, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<bool> TryDeletePolicyMutationAsync(
        string tenantId,
        string policyId,
        int expectedVersion,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM capture_policies WHERE tenant_id=$tenant AND policy_id=$id AND version=$version;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$id", policyId);
        command.Parameters.AddWithValue("$version", expectedVersion);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }
        await InsertAuditAsync(connection, transaction, audit, cancellationToken);
        await InsertPolicyDispatchAsync(connection, transaction, dispatch, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<bool> TryAcquireProviderMutationLeaseAsync(
        string providerId,
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_provider_mutation_leases(provider_id, owner, expires_at_utc)
            VALUES ($provider, $owner, $expires)
            ON CONFLICT(provider_id) DO UPDATE SET owner=excluded.owner, expires_at_utc=excluded.expires_at_utc
            WHERE capture_provider_mutation_leases.expires_at_utc <= $now
               OR capture_provider_mutation_leases.owner = $owner;
            """;
        command.Parameters.AddWithValue("$provider", providerId);
        command.Parameters.AddWithValue("$owner", owner);
        command.Parameters.AddWithValue("$now", Format(nowUtc));
        command.Parameters.AddWithValue("$expires", Format(expiresAtUtc));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task ReleaseProviderMutationLeaseAsync(
        string providerId,
        string owner,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM capture_provider_mutation_leases WHERE provider_id=$provider AND owner=$owner;";
        command.Parameters.AddWithValue("$provider", providerId);
        command.Parameters.AddWithValue("$owner", owner);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<CapturePolicyDispatch?> TryClaimNextPolicyDispatchAsync(
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseExpiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        CapturePolicyDispatch? dispatch;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT dispatch_json, claim_owner, claim_expires_at_utc
                FROM capture_policy_dispatch
                WHERE available_at_utc <= $now
                  AND (claim_owner IS NULL OR claim_expires_at_utc <= $now)
                ORDER BY created_at_utc, dispatch_id LIMIT 1;
                """;
            select.Parameters.AddWithValue("$now", Format(nowUtc));
            dispatch = await ReadPolicyDispatchAsync(select, cancellationToken);
        }
        if (dispatch is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }

        dispatch.AttemptCount++;
        dispatch.ClaimOwner = owner;
        dispatch.ClaimExpiresAtUtc = leaseExpiresAtUtc;
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE capture_policy_dispatch
                SET attempt_count=$attempts, claim_owner=$owner, claim_expires_at_utc=$lease, dispatch_json=$json
                WHERE dispatch_id=$id AND (claim_owner IS NULL OR claim_expires_at_utc <= $now);
                """;
            update.Parameters.AddWithValue("$attempts", dispatch.AttemptCount);
            update.Parameters.AddWithValue("$owner", owner);
            update.Parameters.AddWithValue("$lease", Format(leaseExpiresAtUtc));
            update.Parameters.AddWithValue("$json", Serialize(dispatch));
            update.Parameters.AddWithValue("$id", dispatch.DispatchId);
            update.Parameters.AddWithValue("$now", Format(nowUtc));
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) dispatch = null;
        }
        await transaction.CommitAsync(cancellationToken);
        return dispatch;
    }

    public async Task<bool> CompletePolicyDispatchAsync(
        string dispatchId,
        string owner,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM capture_policy_dispatch WHERE dispatch_id=$id AND claim_owner=$owner;";
        command.Parameters.AddWithValue("$id", dispatchId);
        command.Parameters.AddWithValue("$owner", owner);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<bool> ReleasePolicyDispatchAsync(
        CapturePolicyDispatch dispatch,
        string owner,
        DateTimeOffset availableAtUtc,
        string errorCode,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        dispatch.AvailableAtUtc = availableAtUtc;
        dispatch.LastErrorCode = errorCode;
        dispatch.ClaimOwner = null;
        dispatch.ClaimExpiresAtUtc = null;
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE capture_policy_dispatch
            SET available_at_utc=$available, attempt_count=$attempts, last_error_code=$error,
                claim_owner=NULL, claim_expires_at_utc=NULL, dispatch_json=$json
            WHERE dispatch_id=$id AND claim_owner=$owner;
            """;
        command.Parameters.AddWithValue("$available", Format(availableAtUtc));
        command.Parameters.AddWithValue("$attempts", dispatch.AttemptCount);
        command.Parameters.AddWithValue("$error", errorCode);
        command.Parameters.AddWithValue("$json", Serialize(dispatch));
        command.Parameters.AddWithValue("$id", dispatch.DispatchId);
        command.Parameters.AddWithValue("$owner", owner);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<bool> UpsertSessionAsync(CaptureSessionMetadata session, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_sessions
                (tenant_id, session_id, campaign_id, edge_id, provider_id, sensor_id, started_at_utc, ended_at_utc,
                 source_ip, source_port, destination_ip, destination_port, protocol, payload_available,
                 retain_until_utc, payload_reference, tls_artifact_reference, session_json)
            VALUES
                ($tenant, $id, $campaign, $edge, $provider, $sensor, $started, $ended, $sourceIp, $sourcePort,
                 $destinationIp, $destinationPort, $protocol, $payload, $retainUntil, $reference, $tlsReference, $json)
            ON CONFLICT(tenant_id, session_id) DO UPDATE SET
                campaign_id=excluded.campaign_id, edge_id=excluded.edge_id,
                provider_id=excluded.provider_id, sensor_id=excluded.sensor_id,
                started_at_utc=excluded.started_at_utc, ended_at_utc=excluded.ended_at_utc,
                source_ip=excluded.source_ip, source_port=excluded.source_port,
                destination_ip=excluded.destination_ip, destination_port=excluded.destination_port,
                protocol=excluded.protocol, payload_available=excluded.payload_available,
                retain_until_utc=excluded.retain_until_utc, payload_reference=excluded.payload_reference,
                tls_artifact_reference=excluded.tls_artifact_reference,
                session_json=excluded.session_json
            WHERE capture_sessions.provider_id=excluded.provider_id;
            """;
        command.Parameters.AddWithValue("$tenant", session.TenantId);
        command.Parameters.AddWithValue("$id", session.SessionId);
        command.Parameters.AddWithValue("$campaign", DbValue(session.CampaignId));
        command.Parameters.AddWithValue("$edge", DbValue(session.EdgeId));
        command.Parameters.AddWithValue("$provider", session.ProviderId);
        command.Parameters.AddWithValue("$sensor", session.SensorId);
        command.Parameters.AddWithValue("$started", Format(session.StartedAtUtc));
        command.Parameters.AddWithValue("$ended", DbValue(session.EndedAtUtc));
        command.Parameters.AddWithValue("$sourceIp", session.SourceIp);
        command.Parameters.AddWithValue("$sourcePort", DbValue(session.SourcePort));
        command.Parameters.AddWithValue("$destinationIp", session.DestinationIp);
        command.Parameters.AddWithValue("$destinationPort", DbValue(session.DestinationPort));
        command.Parameters.AddWithValue("$protocol", session.Protocol);
        command.Parameters.AddWithValue("$payload", session.PayloadAvailable ? 1 : 0);
        command.Parameters.AddWithValue("$retainUntil", DbValue(session.RetainUntilUtc));
        command.Parameters.AddWithValue("$reference", DbValue(session.PayloadReference));
        command.Parameters.AddWithValue("$tlsReference", DbValue(session.Tls?.DecryptedArtifactReference));
        command.Parameters.AddWithValue("$json", Serialize(session));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<CaptureSessionMetadata?> GetSessionAsync(
        string tenantId,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT session_json, payload_reference, tls_artifact_reference FROM capture_sessions WHERE tenant_id=$tenant AND session_id=$id;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$id", sessionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var value = Deserialize<CaptureSessionMetadata>(reader.GetString(0));
        value.PayloadReference = reader.IsDBNull(1) ? null : reader.GetString(1);
        if (value.Tls is not null) value.Tls.DecryptedArtifactReference = reader.IsDBNull(2) ? null : reader.GetString(2);
        return value;
    }

    public async Task<IReadOnlyList<CaptureSessionMetadata>> QuerySessionsAsync(
        string tenantId,
        CaptureSessionQuery query,
        CaptureSessionCursor? cursor,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var where = new List<string> { "tenant_id=$tenant" };
        command.Parameters.AddWithValue("$tenant", tenantId);
        AddDateFilter(where, command, "started_at_utc", ">=", "$from", query.FromUtc);
        AddDateFilter(where, command, "started_at_utc", "<=", "$to", query.ToUtc);
        if (!string.IsNullOrWhiteSpace(query.Address))
        {
            where.Add("(source_ip=$address OR destination_ip=$address)");
            command.Parameters.AddWithValue("$address", query.Address);
        }
        if (query.Port is not null)
        {
            where.Add("(source_port=$port OR destination_port=$port)");
            command.Parameters.AddWithValue("$port", query.Port.Value);
        }
        if (!string.IsNullOrWhiteSpace(query.Protocol))
        {
            where.Add("protocol=$protocol");
            command.Parameters.AddWithValue("$protocol", query.Protocol);
        }
        if (query.PayloadAvailable is not null)
        {
            where.Add("payload_available=$payload");
            command.Parameters.AddWithValue("$payload", query.PayloadAvailable.Value ? 1 : 0);
        }
        if (!string.IsNullOrWhiteSpace(query.ProviderId))
        {
            where.Add("provider_id=$provider");
            command.Parameters.AddWithValue("$provider", query.ProviderId);
        }
        if (!string.IsNullOrWhiteSpace(query.CampaignId))
        {
            where.Add("campaign_id=$campaign");
            command.Parameters.AddWithValue("$campaign", query.CampaignId);
        }
        if (!string.IsNullOrWhiteSpace(query.EdgeId))
        {
            where.Add("edge_id=$edge");
            command.Parameters.AddWithValue("$edge", query.EdgeId);
        }
        if (cursor is not null)
        {
            where.Add("(started_at_utc < $cursorTime OR (started_at_utc = $cursorTime AND session_id < $cursorId))");
            command.Parameters.AddWithValue("$cursorTime", Format(cursor.Value.StartedAtUtc));
            command.Parameters.AddWithValue("$cursorId", cursor.Value.SessionId);
        }

        command.CommandText = $"""
            SELECT session_json, payload_reference, tls_artifact_reference
            FROM capture_sessions
            WHERE {string.Join(" AND ", where)}
            ORDER BY started_at_utc DESC, session_id DESC
            LIMIT $take;
            """;
        command.Parameters.AddWithValue("$take", take);
        var items = new List<CaptureSessionMetadata>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var item = Deserialize<CaptureSessionMetadata>(reader.GetString(0));
            item.PayloadReference = reader.IsDBNull(1) ? null : reader.GetString(1);
            if (item.Tls is not null) item.Tls.DecryptedArtifactReference = reader.IsDBNull(2) ? null : reader.GetString(2);
            items.Add(item);
        }
        return items;
    }

    public async Task<IReadOnlyList<CaptureSessionMetadata>> ListExpiredSessionsAsync(
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT session_json, payload_reference, tls_artifact_reference
            FROM capture_sessions
            WHERE retain_until_utc IS NOT NULL AND retain_until_utc <= $now
            ORDER BY retain_until_utc
            LIMIT $take;
            """;
        command.Parameters.AddWithValue("$now", Format(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$take", take);
        var items = new List<CaptureSessionMetadata>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var item = Deserialize<CaptureSessionMetadata>(reader.GetString(0));
            item.PayloadReference = reader.IsDBNull(1) ? null : reader.GetString(1);
            if (item.Tls is not null) item.Tls.DecryptedArtifactReference = reader.IsDBNull(2) ? null : reader.GetString(2);
            items.Add(item);
        }
        return items;
    }

    public async Task DeleteSessionAsync(string tenantId, string sessionId, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM capture_sessions WHERE tenant_id=$tenant AND session_id=$id;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$id", sessionId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task CreateExportJobWithAuditAsync(
        CaptureExportJob job,
        CaptureAuditEntry audit,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO capture_export_jobs
                (tenant_id, job_id, provider_id, status, created_at_utc, updated_at_utc, expires_at_utc,
                 output_reference, claim_owner, claim_expires_at_utc, job_json)
            VALUES ($tenant, $id, $provider, $status, $created, $updated, $expires,
                    $reference, NULL, NULL, $json);
            """;
        BindJob(command, job);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await InsertAuditAsync(connection, transaction, audit, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<CaptureExportJob>> ListExportJobsAsync(
        string tenantId,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT job_json, output_reference, claim_owner, claim_expires_at_utc FROM capture_export_jobs
            WHERE tenant_id=$tenant ORDER BY created_at_utc DESC LIMIT $take;
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$take", take);
        return await ReadJobsAsync(command, cancellationToken);
    }

    public async Task<CaptureExportJob?> GetExportJobAsync(
        string tenantId,
        string jobId,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT job_json, output_reference, claim_owner, claim_expires_at_utc FROM capture_export_jobs WHERE tenant_id=$tenant AND job_id=$id;";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$id", jobId);
        var jobs = await ReadJobsAsync(command, cancellationToken);
        return jobs.FirstOrDefault();
    }

    public async Task<CaptureExportJob?> TryClaimNextExportJobAsync(
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseExpiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        CaptureExportJob? job;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT job_json, output_reference, claim_owner, claim_expires_at_utc FROM capture_export_jobs
                WHERE status=$queued OR (status=$running AND claim_expires_at_utc <= $now)
                ORDER BY created_at_utc LIMIT 1;
                """;
            select.Parameters.AddWithValue("$queued", CaptureJobStatus.Queued.ToString());
            select.Parameters.AddWithValue("$running", CaptureJobStatus.Running.ToString());
            select.Parameters.AddWithValue("$now", Format(nowUtc));
            job = (await ReadJobsAsync(select, cancellationToken)).FirstOrDefault();
        }
        if (job is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }

        job.Status = CaptureJobStatus.Running;
        job.AttemptCount++;
        job.UpdatedAtUtc = nowUtc;
        job.ClaimOwner = owner;
        job.ClaimExpiresAtUtc = leaseExpiresAtUtc;
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE capture_export_jobs
                SET status=$running, updated_at_utc=$updated, claim_owner=$owner,
                    claim_expires_at_utc=$lease, job_json=$json
                WHERE tenant_id=$tenant AND job_id=$id AND
                      (status=$queued OR (status=$running AND claim_expires_at_utc <= $now));
                """;
            update.Parameters.AddWithValue("$running", CaptureJobStatus.Running.ToString());
            update.Parameters.AddWithValue("$updated", Format(job.UpdatedAtUtc));
            update.Parameters.AddWithValue("$owner", owner);
            update.Parameters.AddWithValue("$lease", Format(leaseExpiresAtUtc));
            update.Parameters.AddWithValue("$now", Format(nowUtc));
            update.Parameters.AddWithValue("$json", Serialize(job));
            update.Parameters.AddWithValue("$tenant", job.TenantId);
            update.Parameters.AddWithValue("$id", job.JobId);
            update.Parameters.AddWithValue("$queued", CaptureJobStatus.Queued.ToString());
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) job = null;
        }
        await transaction.CommitAsync(cancellationToken);
        return job;
    }

    public async Task<bool> TryUpdateClaimedExportJobAsync(
        CaptureExportJob job,
        string owner,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE capture_export_jobs
            SET status=$status, updated_at_utc=$updated, expires_at_utc=$expires,
                output_reference=$reference, claim_owner=NULL, claim_expires_at_utc=NULL, job_json=$json
            WHERE tenant_id=$tenant AND job_id=$id AND status=$running AND claim_owner=$owner;
            """;
        BindJob(command, job);
        command.Parameters.AddWithValue("$running", CaptureJobStatus.Running.ToString());
        command.Parameters.AddWithValue("$owner", owner);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task UpsertProviderHealthAsync(CaptureProviderHealth health, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_provider_health(provider_id, checked_at_utc, health_json)
            VALUES ($id, $checked, $json)
            ON CONFLICT(provider_id) DO UPDATE SET checked_at_utc=excluded.checked_at_utc, health_json=excluded.health_json;
            """;
        command.Parameters.AddWithValue("$id", health.ProviderId);
        command.Parameters.AddWithValue("$checked", Format(health.CheckedAtUtc));
        command.Parameters.AddWithValue("$json", Serialize(health));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<CaptureProviderHealth>> ListProviderHealthAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT health_json FROM capture_provider_health ORDER BY provider_id;";
        return await ReadJsonListAsync<CaptureProviderHealth>(command, cancellationToken);
    }

    public async Task<string?> GetProviderCursorAsync(string providerId, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT cursor FROM capture_provider_state WHERE provider_id=$id;";
        command.Parameters.AddWithValue("$id", providerId);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    public async Task SetProviderCursorAsync(string providerId, string? cursor, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_provider_state(provider_id, cursor, updated_at_utc)
            VALUES ($id, $cursor, $updated)
            ON CONFLICT(provider_id) DO UPDATE SET cursor=excluded.cursor, updated_at_utc=excluded.updated_at_utc;
            """;
        command.Parameters.AddWithValue("$id", providerId);
        command.Parameters.AddWithValue("$cursor", DbValue(cursor));
        command.Parameters.AddWithValue("$updated", Format(DateTimeOffset.UtcNow));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task CommitProviderSyncPageAsync(
        string providerId,
        string? cursor,
        IReadOnlyList<CaptureProviderQuarantineEntry> quarantined,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        foreach (var item in quarantined)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO capture_provider_quarantine
                    (quarantine_id, provider_id, tenant_id, session_id_hint, item_sha256,
                     reason_code, received_at_utc)
                VALUES ($id, $provider, $tenant, $session, $sha, $reason, $received);
                """;
            insert.Parameters.AddWithValue("$id", item.QuarantineId);
            insert.Parameters.AddWithValue("$provider", item.ProviderId);
            insert.Parameters.AddWithValue("$tenant", item.TenantId);
            insert.Parameters.AddWithValue("$session", DbValue(item.SessionIdHint));
            insert.Parameters.AddWithValue("$sha", item.ItemSha256);
            insert.Parameters.AddWithValue("$reason", item.ReasonCode);
            insert.Parameters.AddWithValue("$received", Format(item.ReceivedAtUtc));
            if (await insert.ExecuteNonQueryAsync(cancellationToken) == 1)
            {
                await InsertAuditAsync(connection, transaction, new CaptureAuditEntry
                {
                    TenantId = item.TenantId,
                    TimestampUtc = item.ReceivedAtUtc,
                    Actor = $"system:capture-provider:{providerId}",
                    Action = "capture.provider.session.quarantine",
                    Target = item.SessionIdHint ?? item.QuarantineId,
                    Result = "rejected",
                    DetailCode = item.ReasonCode
                }, cancellationToken);
            }
        }

        await using (var progress = connection.CreateCommand())
        {
            progress.Transaction = transaction;
            progress.CommandText = """
                INSERT INTO capture_provider_state(provider_id, cursor, updated_at_utc)
                VALUES ($id, $cursor, $updated)
                ON CONFLICT(provider_id) DO UPDATE SET cursor=excluded.cursor, updated_at_utc=excluded.updated_at_utc;
                """;
            progress.Parameters.AddWithValue("$id", providerId);
            progress.Parameters.AddWithValue("$cursor", DbValue(cursor));
            progress.Parameters.AddWithValue("$updated", Format(DateTimeOffset.UtcNow));
            await progress.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<VisibilityGap?> GetOpenVisibilityGapAsync(
        string tenantId,
        string providerId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT gap_json FROM capture_visibility_gaps
            WHERE tenant_id=$tenant AND provider_id=$provider AND reason=$reason AND ended_at_utc IS NULL
            ORDER BY started_at_utc DESC LIMIT 1;
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$provider", providerId);
        command.Parameters.AddWithValue("$reason", reason);
        return await ReadJsonSingleAsync<VisibilityGap>(command, cancellationToken);
    }

    public async Task CreateVisibilityGapAsync(VisibilityGap gap, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_visibility_gaps
                (tenant_id, gap_id, provider_id, reason, started_at_utc, ended_at_utc, gap_json)
            VALUES ($tenant, $id, $provider, $reason, $started, $ended, $json);
            """;
        command.Parameters.AddWithValue("$tenant", gap.TenantId);
        command.Parameters.AddWithValue("$id", gap.GapId);
        command.Parameters.AddWithValue("$provider", gap.ProviderId);
        command.Parameters.AddWithValue("$reason", gap.Reason);
        command.Parameters.AddWithValue("$started", Format(gap.StartedAtUtc));
        command.Parameters.AddWithValue("$ended", DbValue(gap.EndedAtUtc));
        command.Parameters.AddWithValue("$json", Serialize(gap));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task CloseVisibilityGapsAsync(
        string tenantId,
        string providerId,
        string reason,
        DateTimeOffset endedAtUtc,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        var open = new List<VisibilityGap>();
        await using (var select = connection.CreateCommand())
        {
            select.CommandText = """
                SELECT gap_json FROM capture_visibility_gaps
                WHERE tenant_id=$tenant AND provider_id=$provider AND reason=$reason AND ended_at_utc IS NULL;
                """;
            select.Parameters.AddWithValue("$tenant", tenantId);
            select.Parameters.AddWithValue("$provider", providerId);
            select.Parameters.AddWithValue("$reason", reason);
            open.AddRange(await ReadJsonListAsync<VisibilityGap>(select, cancellationToken));
        }
        foreach (var gap in open)
        {
            gap.EndedAtUtc = endedAtUtc;
            await using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE capture_visibility_gaps SET ended_at_utc=$ended, gap_json=$json
                WHERE tenant_id=$tenant AND gap_id=$id AND ended_at_utc IS NULL;
                """;
            update.Parameters.AddWithValue("$ended", Format(endedAtUtc));
            update.Parameters.AddWithValue("$json", Serialize(gap));
            update.Parameters.AddWithValue("$tenant", gap.TenantId);
            update.Parameters.AddWithValue("$id", gap.GapId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task<IReadOnlyList<VisibilityGap>> ListVisibilityGapsAsync(
        string tenantId,
        bool openOnly,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT gap_json FROM capture_visibility_gaps
            WHERE tenant_id=$tenant {(openOnly ? "AND ended_at_utc IS NULL" : "")}
            ORDER BY started_at_utc DESC LIMIT $take;
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$take", take);
        return await ReadJsonListAsync<VisibilityGap>(command, cancellationToken);
    }

    public async Task AppendAuditAsync(CaptureAuditEntry entry, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO capture_audit
                (tenant_id, timestamp_utc, actor, action, target, result, detail_code, purpose, source_ip)
            VALUES ($tenant, $timestamp, $actor, $action, $target, $result, $detail, $purpose, $sourceIp);
            """;
        command.Parameters.AddWithValue("$tenant", entry.TenantId);
        command.Parameters.AddWithValue("$timestamp", Format(entry.TimestampUtc));
        command.Parameters.AddWithValue("$actor", entry.Actor);
        command.Parameters.AddWithValue("$action", entry.Action);
        command.Parameters.AddWithValue("$target", DbValue(entry.Target));
        command.Parameters.AddWithValue("$result", entry.Result);
        command.Parameters.AddWithValue("$detail", DbValue(entry.DetailCode));
        command.Parameters.AddWithValue("$purpose", DbValue(entry.Purpose));
        command.Parameters.AddWithValue("$sourceIp", DbValue(entry.SourceIp));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<CaptureAuditEntry>> ListAuditAsync(
        string tenantId,
        int take,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, timestamp_utc, actor, action, target, result, detail_code, purpose, source_ip
            FROM capture_audit WHERE tenant_id=$tenant ORDER BY id DESC LIMIT $take;
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$take", take);
        var items = new List<CaptureAuditEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            items.Add(new CaptureAuditEntry
            {
                Id = reader.GetInt64(0),
                TenantId = tenantId,
                TimestampUtc = Parse(reader.GetString(1)),
                Actor = reader.GetString(2),
                Action = reader.GetString(3),
                Target = reader.IsDBNull(4) ? null : reader.GetString(4),
                Result = reader.GetString(5),
                DetailCode = reader.IsDBNull(6) ? null : reader.GetString(6),
                Purpose = reader.IsDBNull(7) ? null : reader.GetString(7),
                SourceIp = reader.IsDBNull(8) ? null : reader.GetString(8)
            });
        }
        return items;
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (!_initialized) await InitializeAsync(cancellationToken);
    }

    private SqliteConnection CreateConnection()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(_options.DatabasePath),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        };
        return new SqliteConnection(builder.ToString());
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await ExecuteNonQueryAsync(connection, "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;", cancellationToken);
        return connection;
    }

    private static async Task ExecuteNonQueryAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureColumnAsync(
        SqliteConnection connection,
        string table,
        string column,
        string type,
        CancellationToken cancellationToken)
    {
        await using var inspect = connection.CreateCommand();
        inspect.CommandText = $"PRAGMA table_info({table});";
        await using var reader = await inspect.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return;
        }
        await reader.DisposeAsync();
        await ExecuteNonQueryAsync(connection, $"ALTER TABLE {table} ADD COLUMN {column} {type};", cancellationToken);
    }

    private static void BindPolicy(SqliteCommand command, CapturePolicy policy)
    {
        command.Parameters.AddWithValue("$tenant", policy.TenantId);
        command.Parameters.AddWithValue("$id", policy.PolicyId);
        command.Parameters.AddWithValue("$version", policy.Version);
        command.Parameters.AddWithValue("$name", policy.Name);
        command.Parameters.AddWithValue("$enabled", policy.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("$provider", policy.ProviderId);
        command.Parameters.AddWithValue("$json", Serialize(policy));
        command.Parameters.AddWithValue("$created", Format(policy.CreatedAtUtc));
        command.Parameters.AddWithValue("$updated", Format(policy.UpdatedAtUtc));
    }

    private static async Task InsertAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CaptureAuditEntry entry,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO capture_audit
                (tenant_id, timestamp_utc, actor, action, target, result, detail_code, purpose, source_ip)
            VALUES ($tenant, $timestamp, $actor, $action, $target, $result, $detail, $purpose, $sourceIp);
            """;
        BindAudit(command, entry);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void BindAudit(SqliteCommand command, CaptureAuditEntry entry)
    {
        command.Parameters.AddWithValue("$tenant", entry.TenantId);
        command.Parameters.AddWithValue("$timestamp", Format(entry.TimestampUtc));
        command.Parameters.AddWithValue("$actor", entry.Actor);
        command.Parameters.AddWithValue("$action", entry.Action);
        command.Parameters.AddWithValue("$target", DbValue(entry.Target));
        command.Parameters.AddWithValue("$result", entry.Result);
        command.Parameters.AddWithValue("$detail", DbValue(entry.DetailCode));
        command.Parameters.AddWithValue("$purpose", DbValue(entry.Purpose));
        command.Parameters.AddWithValue("$sourceIp", DbValue(entry.SourceIp));
    }

    private static async Task InsertPolicyDispatchAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO capture_policy_dispatch
                (dispatch_id, tenant_id, provider_id, policy_id, desired_version, kind,
                 created_at_utc, available_at_utc, attempt_count, last_error_code,
                 claim_owner, claim_expires_at_utc, dispatch_json)
            VALUES ($id, $tenant, $provider, $policy, $version, $kind,
                    $created, $available, $attempts, $error, NULL, NULL, $json);
            """;
        command.Parameters.AddWithValue("$id", dispatch.DispatchId);
        command.Parameters.AddWithValue("$tenant", dispatch.TenantId);
        command.Parameters.AddWithValue("$provider", dispatch.ProviderId);
        command.Parameters.AddWithValue("$policy", dispatch.PolicyId);
        command.Parameters.AddWithValue("$version", dispatch.DesiredVersion);
        command.Parameters.AddWithValue("$kind", dispatch.Kind.ToString());
        command.Parameters.AddWithValue("$created", Format(dispatch.CreatedAtUtc));
        command.Parameters.AddWithValue("$available", Format(dispatch.AvailableAtUtc));
        command.Parameters.AddWithValue("$attempts", dispatch.AttemptCount);
        command.Parameters.AddWithValue("$error", DbValue(dispatch.LastErrorCode));
        command.Parameters.AddWithValue("$json", Serialize(dispatch));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void BindJob(SqliteCommand command, CaptureExportJob job)
    {
        command.Parameters.AddWithValue("$tenant", job.TenantId);
        command.Parameters.AddWithValue("$id", job.JobId);
        command.Parameters.AddWithValue("$provider", job.ProviderId);
        command.Parameters.AddWithValue("$status", job.Status.ToString());
        command.Parameters.AddWithValue("$created", Format(job.CreatedAtUtc));
        command.Parameters.AddWithValue("$updated", Format(job.UpdatedAtUtc));
        command.Parameters.AddWithValue("$expires", Format(job.ExpiresAtUtc));
        command.Parameters.AddWithValue("$reference", DbValue(job.OutputReference));
        command.Parameters.AddWithValue("$json", Serialize(job));
    }

    private static async Task<IReadOnlyList<CaptureExportJob>> ReadJobsAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        var items = new List<CaptureExportJob>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var job = Deserialize<CaptureExportJob>(reader.GetString(0));
            job.OutputReference = reader.IsDBNull(1) ? null : reader.GetString(1);
            job.ClaimOwner = reader.IsDBNull(2) ? null : reader.GetString(2);
            job.ClaimExpiresAtUtc = reader.IsDBNull(3) ? null : Parse(reader.GetString(3));
            items.Add(job);
        }
        return items;
    }

    private static async Task<CapturePolicyDispatch?> ReadPolicyDispatchAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var dispatch = Deserialize<CapturePolicyDispatch>(reader.GetString(0));
        dispatch.ClaimOwner = reader.IsDBNull(1) ? null : reader.GetString(1);
        dispatch.ClaimExpiresAtUtc = reader.IsDBNull(2) ? null : Parse(reader.GetString(2));
        return dispatch;
    }

    private static async Task<IReadOnlyList<T>> ReadJsonListAsync<T>(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        var items = new List<T>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) items.Add(Deserialize<T>(reader.GetString(0)));
        return items;
    }

    private static async Task<T?> ReadJsonSingleAsync<T>(
        SqliteCommand command,
        CancellationToken cancellationToken) where T : class
    {
        var value = await command.ExecuteScalarAsync(cancellationToken) as string;
        return value is null ? null : Deserialize<T>(value);
    }

    private static void AddDateFilter(
        List<string> where,
        SqliteCommand command,
        string column,
        string comparison,
        string parameter,
        DateTimeOffset? value)
    {
        if (value is null) return;
        where.Add($"{column} {comparison} {parameter}");
        command.Parameters.AddWithValue(parameter, Format(value.Value));
    }

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);
    private static T Deserialize<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, JsonOptions) ?? throw new InvalidDataException($"Invalid persisted {typeof(T).Name} JSON.");
    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
    private static object DbValue(object? value) => value switch
    {
        null => DBNull.Value,
        DateTimeOffset timestamp => Format(timestamp),
        _ => value
    };

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS capture_policies (
            tenant_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            provider_id TEXT NOT NULL,
            policy_json TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            PRIMARY KEY (tenant_id, policy_id)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_policies_provider ON capture_policies(provider_id, enabled);

        CREATE TABLE IF NOT EXISTS capture_provider_mutation_leases (
            provider_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capture_policy_dispatch (
            dispatch_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            desired_version INTEGER NOT NULL,
            kind TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            available_at_utc TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            last_error_code TEXT,
            claim_owner TEXT,
            claim_expires_at_utc TEXT,
            dispatch_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_capture_policy_dispatch_ready
            ON capture_policy_dispatch(available_at_utc, claim_expires_at_utc, created_at_utc);

        CREATE TABLE IF NOT EXISTS capture_sessions (
            tenant_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            campaign_id TEXT,
            edge_id TEXT,
            provider_id TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            started_at_utc TEXT NOT NULL,
            ended_at_utc TEXT,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_ip TEXT NOT NULL,
            destination_port INTEGER,
            protocol TEXT NOT NULL,
            payload_available INTEGER NOT NULL,
            retain_until_utc TEXT,
            payload_reference TEXT,
            tls_artifact_reference TEXT,
            session_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, session_id)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_sessions_tenant_time ON capture_sessions(tenant_id, started_at_utc DESC, session_id DESC);
        CREATE INDEX IF NOT EXISTS idx_capture_sessions_expiry ON capture_sessions(retain_until_utc) WHERE retain_until_utc IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_capture_sessions_source ON capture_sessions(tenant_id, source_ip, started_at_utc DESC);
        CREATE INDEX IF NOT EXISTS idx_capture_sessions_destination ON capture_sessions(tenant_id, destination_ip, started_at_utc DESC);

        CREATE TABLE IF NOT EXISTS capture_export_jobs (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            output_reference TEXT,
            claim_owner TEXT,
            claim_expires_at_utc TEXT,
            job_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, job_id)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_exports_queue ON capture_export_jobs(status, created_at_utc);

        CREATE TABLE IF NOT EXISTS capture_provider_health (
            provider_id TEXT PRIMARY KEY,
            checked_at_utc TEXT NOT NULL,
            health_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capture_provider_state (
            provider_id TEXT PRIMARY KEY,
            cursor TEXT,
            updated_at_utc TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capture_provider_quarantine (
            quarantine_id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            session_id_hint TEXT,
            item_sha256 TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            received_at_utc TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_capture_provider_quarantine_provider
            ON capture_provider_quarantine(provider_id, received_at_utc DESC);

        CREATE TABLE IF NOT EXISTS capture_visibility_gaps (
            tenant_id TEXT NOT NULL,
            gap_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            started_at_utc TEXT NOT NULL,
            ended_at_utc TEXT,
            gap_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, gap_id)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_gaps_open ON capture_visibility_gaps(tenant_id, ended_at_utc, started_at_utc DESC);

        CREATE TABLE IF NOT EXISTS capture_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            result TEXT NOT NULL,
            detail_code TEXT,
            purpose TEXT,
            source_ip TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_capture_audit_tenant ON capture_audit(tenant_id, id DESC);
        CREATE TRIGGER IF NOT EXISTS capture_audit_immutable_update
            BEFORE UPDATE ON capture_audit BEGIN SELECT RAISE(ABORT, 'capture audit is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS capture_audit_immutable_delete
            BEFORE DELETE ON capture_audit BEGIN SELECT RAISE(ABORT, 'capture audit is immutable'); END;
        """;
}
