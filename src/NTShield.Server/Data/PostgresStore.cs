using System.Text.Json;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;
using Npgsql;

namespace NTShield.Server.Data;

public sealed class PostgresStore : ICentralStore
{
    private readonly string _cs;
    private readonly ILogger<PostgresStore> _logger;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public PostgresStore(IOptions<PostgresOptions> options, ILogger<PostgresStore> logger)
    {
        _cs = options.Value.ConnectionString;
        _logger = logger;
    }

    public async Task InitializeAsync()
    {
        try
        {
            await using var conn = new NpgsqlConnection(_cs);
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    computer_name TEXT NOT NULL,
                    agent_version TEXT,
                    os_version TEXT,
                    host_ip TEXT,
                    certificate_thumbprint TEXT,
                    last_seen_utc TIMESTAMPTZ NOT NULL,
                    queue_depth BIGINT,
                    db_size_bytes BIGINT,
                    status TEXT,
                    working_set_bytes BIGINT,
                    clock_skew_seconds DOUBLE PRECISION
                );

                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    key TEXT PRIMARY KEY,
                    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGSERIAL PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    computer_name TEXT NOT NULL,
                    event_id INT NOT NULL,
                    timestamp_utc TIMESTAMPTZ NOT NULL,
                    username TEXT,
                    domain TEXT,
                    source_ip TEXT,
                    source_port INT,
                    destination_ip TEXT,
                    destination_port INT,
                    logon_type INT,
                    process_id INT,
                    process_path TEXT,
                    status TEXT,
                    raw_xml TEXT,
                    event_record_id BIGINT,
                    payload JSONB
                );
                CREATE INDEX IF NOT EXISTS ix_sec_events_ts ON security_events(timestamp_utc);
                CREATE INDEX IF NOT EXISTS ix_sec_events_src ON security_events(source_ip);
                CREATE INDEX IF NOT EXISTS ix_sec_events_event ON security_events(event_id);

                CREATE TABLE IF NOT EXISTS network_connections (
                    id BIGSERIAL PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    computer_name TEXT NOT NULL,
                    timestamp_utc TIMESTAMPTZ NOT NULL,
                    protocol TEXT,
                    local_address TEXT,
                    local_port INT,
                    remote_address TEXT,
                    remote_port INT,
                    process_id INT,
                    process_name TEXT,
                    process_path TEXT,
                    process_command_line TEXT,
                    service_names TEXT,
                    is_new BOOLEAN,
                    is_closed BOOLEAN,
                    payload JSONB
                );
                CREATE INDEX IF NOT EXISTS ix_net_remote ON network_connections(remote_address, remote_port);
                CREATE INDEX IF NOT EXISTS ix_net_ts ON network_connections(timestamp_utc);

                CREATE TABLE IF NOT EXISTS detection_alerts (
                    id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT UNIQUE NOT NULL,
                    agent_id TEXT NOT NULL,
                    computer_name TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity INT NOT NULL,
                    timestamp_utc TIMESTAMPTZ NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    username TEXT,
                    payload JSONB
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    first_seen_utc TIMESTAMPTZ NOT NULL,
                    last_seen_utc TIMESTAMPTZ NOT NULL,
                    severity INT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    correlation_key TEXT NOT NULL,
                    source_host TEXT,
                    source_agent_id TEXT,
                    source_ip TEXT,
                    source_port INT,
                    source_process_id INT,
                    source_process_name TEXT,
                    source_process_path TEXT,
                    source_service_names TEXT,
                    source_command_line TEXT,
                    destination_host TEXT,
                    destination_agent_id TEXT,
                    destination_ip TEXT,
                    destination_port INT,
                    username TEXT,
                    domain TEXT,
                    logon_type INT,
                    failed_logon_count INT,
                    successful_logon_count INT,
                    privileged_logon BOOLEAN,
                    evidence_json TEXT,
                    status TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_incidents_key ON incidents(correlation_key);
                CREATE INDEX IF NOT EXISTS ix_incidents_last ON incidents(last_seen_utc DESC);

                CREATE TABLE IF NOT EXISTS tenant_assets (
                    asset_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    hostname TEXT,
                    address TEXT,
                    environment TEXT NOT NULL,
                    criticality TEXT NOT NULL,
                    status TEXT NOT NULL,
                    description TEXT,
                    tags_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_utc TIMESTAMPTZ NOT NULL,
                    updated_at_utc TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_tenant_assets_tenant ON tenant_assets(tenant_id, updated_at_utc DESC);

                CREATE TABLE IF NOT EXISTS topology_documents (
                    topology_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at_utc TIMESTAMPTZ NOT NULL,
                    updated_at_utc TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_topology_documents_tenant ON topology_documents(tenant_id, updated_at_utc DESC);

                CREATE TABLE IF NOT EXISTS detection_workflows (
                    workflow_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    topology_id TEXT,
                    enabled BOOLEAN NOT NULL,
                    version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at_utc TIMESTAMPTZ NOT NULL,
                    updated_at_utc TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_detection_workflows_tenant ON detection_workflows(tenant_id, updated_at_utc DESC);
                """;
            await cmd.ExecuteNonQueryAsync();
            _logger.LogInformation("PostgreSQL schema ready");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "PostgreSQL initialize failed. Server will still start; ingest will error until DB is available.");
        }
    }

    public async Task RegisterAgentAsync(AgentRegistrationRequest req)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO agents(agent_id, computer_name, agent_version, os_version, host_ip, certificate_thumbprint, last_seen_utc, status)
            VALUES (@id, @cn, @ver, @os, @ip, @thumb, NOW(), 'Registered')
            ON CONFLICT (agent_id) DO UPDATE SET
                computer_name = EXCLUDED.computer_name,
                agent_version = EXCLUDED.agent_version,
                os_version = EXCLUDED.os_version,
                host_ip = EXCLUDED.host_ip,
                certificate_thumbprint = EXCLUDED.certificate_thumbprint,
                last_seen_utc = NOW(),
                status = 'Registered';
            """;
        cmd.Parameters.AddWithValue("id", req.AgentId);
        cmd.Parameters.AddWithValue("cn", req.ComputerName);
        cmd.Parameters.AddWithValue("ver", (object?)req.AgentVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("os", (object?)req.OsVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ip", (object?)req.HostIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("thumb", (object?)req.CertificateThumbprint ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task UpsertAgentAsync(AgentHeartbeat hb)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO agents(agent_id, computer_name, agent_version, os_version, last_seen_utc, queue_depth, db_size_bytes, status, working_set_bytes, clock_skew_seconds)
            VALUES (@id, @cn, @ver, @os, @ts, @q, @db, @st, @ws, @skew)
            ON CONFLICT (agent_id) DO UPDATE SET
                computer_name = EXCLUDED.computer_name,
                agent_version = EXCLUDED.agent_version,
                os_version = EXCLUDED.os_version,
                last_seen_utc = EXCLUDED.last_seen_utc,
                queue_depth = EXCLUDED.queue_depth,
                db_size_bytes = EXCLUDED.db_size_bytes,
                status = EXCLUDED.status,
                working_set_bytes = EXCLUDED.working_set_bytes,
                clock_skew_seconds = EXCLUDED.clock_skew_seconds;
            """;
        cmd.Parameters.AddWithValue("id", hb.AgentId);
        cmd.Parameters.AddWithValue("cn", hb.ComputerName);
        cmd.Parameters.AddWithValue("ver", (object?)hb.AgentVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("os", (object?)hb.OsVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ts", hb.TimestampUtc);
        cmd.Parameters.AddWithValue("q", hb.LocalQueueDepth);
        cmd.Parameters.AddWithValue("db", hb.DatabaseSizeBytes);
        cmd.Parameters.AddWithValue("st", hb.Status);
        cmd.Parameters.AddWithValue("ws", hb.WorkingSetBytes);
        cmd.Parameters.AddWithValue("skew", hb.ClockSkewSeconds);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> HasIdempotencyKeyAsync(string key)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM idempotency_keys WHERE key = @k LIMIT 1;";
        cmd.Parameters.AddWithValue("k", key);
        var result = await cmd.ExecuteScalarAsync();
        return result is not null;
    }

    public async Task SaveIdempotencyKeyAsync(string key)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO idempotency_keys(key, created_at_utc) VALUES (@k, NOW())
            ON CONFLICT (key) DO NOTHING;
            """;
        cmd.Parameters.AddWithValue("k", key);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task SaveBatchAsync(AgentIngestBatch batch)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();

        foreach (var e in batch.SecurityEvents)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                INSERT INTO security_events(
                    agent_id, computer_name, event_id, timestamp_utc, username, domain,
                    source_ip, source_port, destination_ip, destination_port, logon_type,
                    process_id, process_path, status, raw_xml, event_record_id, payload)
                VALUES (
                    @agent_id, @computer_name, @event_id, @timestamp_utc, @username, @domain,
                    @source_ip, @source_port, @destination_ip, @destination_port, @logon_type,
                    @process_id, @process_path, @status, @raw_xml, @event_record_id, @payload::jsonb);
                """;
            cmd.Parameters.AddWithValue("agent_id", e.AgentId);
            cmd.Parameters.AddWithValue("computer_name", e.ComputerName);
            cmd.Parameters.AddWithValue("event_id", e.EventId);
            cmd.Parameters.AddWithValue("timestamp_utc", e.TimestampUtc);
            cmd.Parameters.AddWithValue("username", (object?)e.Username ?? DBNull.Value);
            cmd.Parameters.AddWithValue("domain", (object?)e.Domain ?? DBNull.Value);
            cmd.Parameters.AddWithValue("source_ip", (object?)e.SourceIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("source_port", (object?)e.SourcePort ?? DBNull.Value);
            cmd.Parameters.AddWithValue("destination_ip", (object?)e.DestinationIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("destination_port", (object?)e.DestinationPort ?? DBNull.Value);
            cmd.Parameters.AddWithValue("logon_type", (object?)e.LogonType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("process_id", (object?)e.ProcessId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("process_path", (object?)e.ProcessPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("status", (object?)e.Status ?? DBNull.Value);
            cmd.Parameters.AddWithValue("raw_xml", (object?)e.RawXml ?? DBNull.Value);
            cmd.Parameters.AddWithValue("event_record_id", e.EventRecordId);
            cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(e, JsonOptions));
            await cmd.ExecuteNonQueryAsync();
        }

        foreach (var n in batch.NetworkConnections)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                INSERT INTO network_connections(
                    agent_id, computer_name, timestamp_utc, protocol, local_address, local_port,
                    remote_address, remote_port, process_id, process_name, process_path,
                    process_command_line, service_names, is_new, is_closed, payload)
                VALUES (
                    @agent_id, @computer_name, @timestamp_utc, @protocol, @local_address, @local_port,
                    @remote_address, @remote_port, @process_id, @process_name, @process_path,
                    @process_command_line, @service_names, @is_new, @is_closed, @payload::jsonb);
                """;
            cmd.Parameters.AddWithValue("agent_id", n.AgentId);
            cmd.Parameters.AddWithValue("computer_name", n.ComputerName);
            cmd.Parameters.AddWithValue("timestamp_utc", n.TimestampUtc);
            cmd.Parameters.AddWithValue("protocol", n.Protocol);
            cmd.Parameters.AddWithValue("local_address", n.LocalAddress);
            cmd.Parameters.AddWithValue("local_port", n.LocalPort);
            cmd.Parameters.AddWithValue("remote_address", n.RemoteAddress);
            cmd.Parameters.AddWithValue("remote_port", n.RemotePort);
            cmd.Parameters.AddWithValue("process_id", n.ProcessId);
            cmd.Parameters.AddWithValue("process_name", (object?)n.ProcessName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("process_path", (object?)n.ProcessPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("process_command_line", (object?)n.ProcessCommandLine ?? DBNull.Value);
            cmd.Parameters.AddWithValue("service_names", (object?)n.ServiceNames ?? DBNull.Value);
            cmd.Parameters.AddWithValue("is_new", n.IsNew);
            cmd.Parameters.AddWithValue("is_closed", n.IsClosed);
            cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(n, JsonOptions));
            await cmd.ExecuteNonQueryAsync();
        }

        foreach (var a in batch.Alerts)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                INSERT INTO detection_alerts(alert_id, agent_id, computer_name, rule_id, severity, timestamp_utc, source_ip, destination_ip, username, payload)
                VALUES (@alert_id, @agent_id, @computer_name, @rule_id, @severity, @timestamp_utc, @source_ip, @destination_ip, @username, @payload::jsonb)
                ON CONFLICT (alert_id) DO NOTHING;
                """;
            cmd.Parameters.AddWithValue("alert_id", a.AlertId);
            cmd.Parameters.AddWithValue("agent_id", a.AgentId);
            cmd.Parameters.AddWithValue("computer_name", a.ComputerName);
            cmd.Parameters.AddWithValue("rule_id", a.RuleId);
            cmd.Parameters.AddWithValue("severity", (int)a.Severity);
            cmd.Parameters.AddWithValue("timestamp_utc", a.TimestampUtc);
            cmd.Parameters.AddWithValue("source_ip", (object?)a.SourceIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("destination_ip", (object?)a.DestinationIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("username", (object?)a.Username ?? DBNull.Value);
            cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(a, JsonOptions));
            await cmd.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
    }

    public async Task UpsertIncidentAsync(Incident incident)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO incidents(
                incident_id, first_seen_utc, last_seen_utc, severity, title, description, correlation_key,
                source_host, source_agent_id, source_ip, source_port, source_process_id, source_process_name,
                source_process_path, source_service_names, source_command_line,
                destination_host, destination_agent_id, destination_ip, destination_port,
                username, domain, logon_type, failed_logon_count, successful_logon_count, privileged_logon,
                evidence_json, status)
            VALUES (
                @incident_id, @first_seen_utc, @last_seen_utc, @severity, @title, @description, @correlation_key,
                @source_host, @source_agent_id, @source_ip, @source_port, @source_process_id, @source_process_name,
                @source_process_path, @source_service_names, @source_command_line,
                @destination_host, @destination_agent_id, @destination_ip, @destination_port,
                @username, @domain, @logon_type, @failed_logon_count, @successful_logon_count, @privileged_logon,
                @evidence_json, @status)
            ON CONFLICT (incident_id) DO UPDATE SET
                last_seen_utc = EXCLUDED.last_seen_utc,
                failed_logon_count = EXCLUDED.failed_logon_count,
                successful_logon_count = EXCLUDED.successful_logon_count,
                privileged_logon = EXCLUDED.privileged_logon,
                evidence_json = EXCLUDED.evidence_json,
                severity = EXCLUDED.severity,
                source_process_id = COALESCE(EXCLUDED.source_process_id, incidents.source_process_id),
                source_process_name = COALESCE(EXCLUDED.source_process_name, incidents.source_process_name),
                source_service_names = COALESCE(EXCLUDED.source_service_names, incidents.source_service_names),
                destination_port = COALESCE(EXCLUDED.destination_port, incidents.destination_port);
            """;
        cmd.Parameters.AddWithValue("incident_id", incident.IncidentId);
        cmd.Parameters.AddWithValue("first_seen_utc", incident.FirstSeenUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : incident.FirstSeenUtc);
        cmd.Parameters.AddWithValue("last_seen_utc", incident.LastSeenUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : incident.LastSeenUtc);
        cmd.Parameters.AddWithValue("severity", (int)incident.Severity);
        cmd.Parameters.AddWithValue("title", incident.Title);
        cmd.Parameters.AddWithValue("description", incident.Description ?? string.Empty);
        cmd.Parameters.AddWithValue("correlation_key", string.IsNullOrEmpty(incident.CorrelationKey) ? incident.IncidentId : incident.CorrelationKey);
        cmd.Parameters.AddWithValue("source_host", (object?)incident.SourceHost ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_agent_id", (object?)incident.SourceAgentId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_ip", (object?)incident.SourceIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_port", (object?)incident.SourcePort ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_process_id", (object?)incident.ProcessId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_process_name", (object?)incident.ProcessName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_process_path", (object?)incident.ProcessPath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_service_names", (object?)incident.SourceServiceNames ?? DBNull.Value);
        cmd.Parameters.AddWithValue("source_command_line", (object?)incident.ProcessCommandLine ?? DBNull.Value);
        cmd.Parameters.AddWithValue("destination_host", (object?)incident.DestinationHost ?? DBNull.Value);
        cmd.Parameters.AddWithValue("destination_agent_id", (object?)incident.DestinationAgentId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("destination_ip", (object?)incident.DestinationIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("destination_port", (object?)incident.DestinationPort ?? DBNull.Value);
        cmd.Parameters.AddWithValue("username", (object?)incident.Username ?? DBNull.Value);
        cmd.Parameters.AddWithValue("domain", (object?)incident.Domain ?? DBNull.Value);
        cmd.Parameters.AddWithValue("logon_type", (object?)incident.LogonType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("failed_logon_count", incident.FailedAttempts);
        cmd.Parameters.AddWithValue("successful_logon_count", incident.SuccessfulLoginDetected ? 1 : 0);
        cmd.Parameters.AddWithValue("privileged_logon", incident.PrivilegedLogon);
        cmd.Parameters.AddWithValue("evidence_json", string.IsNullOrEmpty(incident.EvidenceJson)
            ? JsonSerializer.Serialize(incident.EvidenceEvents)
            : incident.EvidenceJson);
        cmd.Parameters.AddWithValue("status", incident.Status);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<Incident>> ListIncidentsAsync(int take)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT incident_id, first_seen_utc, last_seen_utc, severity, title, description, correlation_key,
                   source_host, source_agent_id, source_ip, source_port, source_process_id, source_process_name,
                   source_process_path, source_service_names, source_command_line,
                   destination_host, destination_agent_id, destination_ip, destination_port,
                   username, domain, logon_type, failed_logon_count, successful_logon_count, privileged_logon,
                   evidence_json, status
            FROM incidents
            ORDER BY last_seen_utc DESC
            LIMIT @take;
            """;
        cmd.Parameters.AddWithValue("take", take);
        var list = new List<Incident>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(ReadIncident(reader));
        }

        return list;
    }

    public async Task<Incident?> GetIncidentAsync(string id)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT incident_id, first_seen_utc, last_seen_utc, severity, title, description, correlation_key,
                   source_host, source_agent_id, source_ip, source_port, source_process_id, source_process_name,
                   source_process_path, source_service_names, source_command_line,
                   destination_host, destination_agent_id, destination_ip, destination_port,
                   username, domain, logon_type, failed_logon_count, successful_logon_count, privileged_logon,
                   evidence_json, status
            FROM incidents WHERE incident_id = @id;
            """;
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return ReadIncident(reader);
    }

    public async Task<IReadOnlyList<object>> ListAgentsAsync()
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT agent_id, computer_name, agent_version, os_version, last_seen_utc, status FROM agents ORDER BY last_seen_utc DESC;";
        var list = new List<object>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new
            {
                agentId = reader.GetString(0),
                computerName = reader.GetString(1),
                agentVersion = reader.IsDBNull(2) ? null : reader.GetString(2),
                osVersion = reader.IsDBNull(3) ? null : reader.GetString(3),
                lastSeenUtc = reader.GetFieldValue<DateTimeOffset>(4),
                status = reader.IsDBNull(5) ? null : reader.GetString(5)
            });
        }

        return list;
    }

    public async Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(
        string remoteIp,
        int? remotePort,
        DateTimeOffset from,
        DateTimeOffset to)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT agent_id, computer_name, timestamp_utc, local_address, local_port, remote_address, remote_port,
                   process_id, process_name, process_path, process_command_line, service_names
            FROM network_connections
            WHERE remote_address = @remote
              AND timestamp_utc BETWEEN @from AND @to
              AND (@port IS NULL OR remote_port = @port)
            ORDER BY timestamp_utc DESC
            LIMIT 200;
            """;
        cmd.Parameters.AddWithValue("remote", remoteIp);
        cmd.Parameters.AddWithValue("from", from);
        cmd.Parameters.AddWithValue("to", to);
        cmd.Parameters.AddWithValue("port", (object?)remotePort ?? DBNull.Value);
        var list = new List<NetworkConnectionRecord>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new NetworkConnectionRecord
            {
                AgentId = reader.GetString(0),
                ComputerName = reader.GetString(1),
                TimestampUtc = reader.GetFieldValue<DateTimeOffset>(2),
                LocalAddress = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                LocalPort = reader.IsDBNull(4) ? 0 : reader.GetInt32(4),
                RemoteAddress = reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
                RemotePort = reader.IsDBNull(6) ? 0 : reader.GetInt32(6),
                ProcessId = reader.IsDBNull(7) ? 0 : reader.GetInt32(7),
                ProcessName = reader.IsDBNull(8) ? null : reader.GetString(8),
                ProcessPath = reader.IsDBNull(9) ? null : reader.GetString(9),
                ProcessCommandLine = reader.IsDBNull(10) ? null : reader.GetString(10),
                ServiceNames = reader.IsDBNull(11) ? null : reader.GetString(11)
            });
        }

        return list;
    }

    private static Incident ReadIncident(NpgsqlDataReader reader) => new()
    {
        IncidentId = reader.GetString(0),
        FirstSeenUtc = reader.GetFieldValue<DateTimeOffset>(1),
        LastSeenUtc = reader.GetFieldValue<DateTimeOffset>(2),
        Severity = (Severity)reader.GetInt32(3),
        Title = reader.GetString(4),
        Description = reader.GetString(5),
        CorrelationKey = reader.GetString(6),
        SourceHost = reader.IsDBNull(7) ? null : reader.GetString(7),
        SourceAgentId = reader.IsDBNull(8) ? null : reader.GetString(8),
        SourceIp = reader.IsDBNull(9) ? null : reader.GetString(9),
        SourcePort = reader.IsDBNull(10) ? null : reader.GetInt32(10),
        SourceProcessId = reader.IsDBNull(11) ? null : reader.GetInt32(11),
        SourceProcessName = reader.IsDBNull(12) ? null : reader.GetString(12),
        SourceProcessPath = reader.IsDBNull(13) ? null : reader.GetString(13),
        SourceServiceNames = reader.IsDBNull(14) ? null : reader.GetString(14),
        SourceCommandLine = reader.IsDBNull(15) ? null : reader.GetString(15),
        DestinationHost = reader.IsDBNull(16) ? null : reader.GetString(16),
        DestinationAgentId = reader.IsDBNull(17) ? null : reader.GetString(17),
        DestinationIp = reader.IsDBNull(18) ? null : reader.GetString(18),
        DestinationPort = reader.IsDBNull(19) ? null : reader.GetInt32(19),
        Username = reader.IsDBNull(20) ? null : reader.GetString(20),
        Domain = reader.IsDBNull(21) ? null : reader.GetString(21),
        LogonType = reader.IsDBNull(22) ? null : reader.GetInt32(22),
        FailedLogonCount = reader.GetInt32(23),
        SuccessfulLogonCount = reader.GetInt32(24),
        PrivilegedLogon = reader.GetBoolean(25),
        EvidenceJson = reader.IsDBNull(26) ? "[]" : reader.GetString(26),
        Status = reader.GetString(27)
    };

    public async Task SavePendingActionAsync(ResponseActionRequest request, string agentKey)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO pending_actions(request_id, agent_key, payload, created_at_utc, delivered)
            VALUES (@id, @agent, @payload, NOW(), FALSE)
            ON CONFLICT (request_id) DO UPDATE SET agent_key=EXCLUDED.agent_key, payload=EXCLUDED.payload, delivered=FALSE;
            """;
        cmd.Parameters.AddWithValue("id", request.RequestId);
        cmd.Parameters.AddWithValue("agent", agentKey);
        cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(request, JsonOptions));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT request_id, payload, agent_key FROM pending_actions
            WHERE delivered=FALSE AND (agent_key=@a OR agent_key='broadcast')
            ORDER BY created_at_utc ASC LIMIT 50;
            """;
        cmd.Parameters.AddWithValue("a", agentId);
        var rows = new List<(string Id, string Payload, string Key)>();
        await using (var reader = await cmd.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
                rows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        var result = new List<ResponseActionRequest>();
        foreach (var (id, payload, key) in rows)
        {
            var req = JsonSerializer.Deserialize<ResponseActionRequest>(payload, JsonOptions);
            if (req is null) continue;
            result.Add(req);
            if (!string.Equals(key, "broadcast", StringComparison.OrdinalIgnoreCase))
            {
                await using var mark = conn.CreateCommand();
                mark.CommandText = "UPDATE pending_actions SET delivered=TRUE WHERE request_id=@id;";
                mark.Parameters.AddWithValue("id", id);
                await mark.ExecuteNonQueryAsync();
            }
        }

        return result;
    }

    public async Task<ResponseActionRequest?> GetPendingActionAsync(string requestId)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM pending_actions WHERE request_id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("id", requestId);
        var o = await cmd.ExecuteScalarAsync();
        return o is string json ? JsonSerializer.Deserialize<ResponseActionRequest>(json, JsonOptions) : null;
    }

    public async Task UpsertCampaignJsonAsync(string campaignId, string json)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO threat_campaigns(campaign_id, payload, last_seen_utc)
            VALUES (@id, @p, NOW())
            ON CONFLICT (campaign_id) DO UPDATE SET payload=EXCLUDED.payload, last_seen_utc=NOW();
            """;
        cmd.Parameters.AddWithValue("id", campaignId);
        cmd.Parameters.AddWithValue("p", json);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT campaign_id, payload FROM threat_campaigns ORDER BY last_seen_utc DESC LIMIT @n;";
        cmd.Parameters.AddWithValue("n", Math.Clamp(take, 1, 500));
        var list = new List<(string, string)>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            list.Add((reader.GetString(0), reader.GetString(1)));
        return list;
    }

    private async Task EnsurePendingTablesAsync()
    {
        try
        {
            await using var conn = new NpgsqlConnection(_cs);
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                CREATE TABLE IF NOT EXISTS pending_actions (
                    request_id TEXT PRIMARY KEY,
                    agent_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    delivered BOOLEAN NOT NULL DEFAULT FALSE
                );
                CREATE TABLE IF NOT EXISTS threat_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    last_seen_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    actor TEXT,
                    action TEXT,
                    target TEXT,
                    result TEXT,
                    detail_json TEXT,
                    source_ip TEXT
                );
                CREATE TABLE IF NOT EXISTS agent_policies (
                    policy_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    json TEXT NOT NULL,
                    updated_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """;
            await cmd.ExecuteNonQueryAsync();
        }
        catch
        {
            // DB may be offline; callers will surface errors
        }
    }

    // P0 auth/policy/audit — best-effort Postgres parity
    public async Task AppendAuditAsync(string actor, string action, string? target, string result, string? detailJson, string? sourceIp)
    {
        try
        {
            await EnsurePendingTablesAsync();
            await using var conn = new NpgsqlConnection(_cs);
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO audit_log(timestamp_utc, actor, action, target, result, detail_json, source_ip)
                VALUES (NOW(), @actor, @action, @target, @result, @detail, @ip);
                """;
            cmd.Parameters.AddWithValue("actor", actor);
            cmd.Parameters.AddWithValue("action", action);
            cmd.Parameters.AddWithValue("target", (object?)target ?? DBNull.Value);
            cmd.Parameters.AddWithValue("result", result);
            cmd.Parameters.AddWithValue("detail", (object?)detailJson ?? DBNull.Value);
            cmd.Parameters.AddWithValue("ip", (object?)sourceIp ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "AppendAudit failed");
        }
    }

    public async Task<IReadOnlyList<AuditLogEntry>> ListAuditAsync(int take)
    {
        try
        {
            await EnsurePendingTablesAsync();
            await using var conn = new NpgsqlConnection(_cs);
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                SELECT id, timestamp_utc, actor, action, target, result, detail_json, source_ip
                FROM audit_log ORDER BY id DESC LIMIT @n;
                """;
            cmd.Parameters.AddWithValue("n", Math.Clamp(take, 1, 1000));
            var list = new List<AuditLogEntry>();
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                list.Add(new AuditLogEntry
                {
                    Id = reader.GetInt64(0),
                    TimestampUtc = reader.GetFieldValue<DateTimeOffset>(1),
                    Actor = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Action = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    Target = reader.IsDBNull(4) ? null : reader.GetString(4),
                    Result = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    DetailJson = reader.IsDBNull(6) ? null : reader.GetString(6),
                    SourceIp = reader.IsDBNull(7) ? null : reader.GetString(7)
                });
            }

            return list;
        }
        catch
        {
            return Array.Empty<AuditLogEntry>();
        }
    }

    public Task<AgentPolicy> GetActivePolicyAsync(string? agentId = null) =>
        Task.FromResult(new AgentPolicy { PolicyId = "default", PolicyVersion = 1, Mode = "Ids", DetectOnly = true });

    public async Task UpsertPolicyAsync(AgentPolicy policy)
    {
        await EnsurePendingTablesAsync();
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO agent_policies(policy_id, version, json, updated_utc)
            VALUES (@id, @v, @j, NOW())
            ON CONFLICT (policy_id) DO UPDATE SET version=EXCLUDED.version, json=EXCLUDED.json, updated_utc=NOW();
            """;
        cmd.Parameters.AddWithValue("id", policy.PolicyId);
        cmd.Parameters.AddWithValue("v", policy.PolicyVersion);
        cmd.Parameters.AddWithValue("j", System.Text.Json.JsonSerializer.Serialize(policy));
        await cmd.ExecuteNonQueryAsync();
    }

    public Task<string?> IssueAgentApiKeyAsync(string agentId, bool rotate) =>
        Task.FromResult<string?>(Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());

    public Task SetAgentApiKeyHashAsync(string agentId, string keyHash) => Task.CompletedTask;

    public Task<string?> FindAgentIdByApiKeyHashAsync(string keyHash) => Task.FromResult<string?>(null);

    public Task UpdateAgentIntegrityAsync(string agentId, string? binarySha256, bool? isSigned, int? policyVersion) =>
        Task.CompletedTask;

    public Task SaveAgentMetricsAsync(AgentHeartbeat hb) => Task.CompletedTask;

    public Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60) =>
        Task.FromResult<IReadOnlyList<AgentMetricsSample>>(Array.Empty<AgentMetricsSample>());

    public async Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60)
    {
        var all = await ListAgentsAsync();
        return all.OfType<AgentInventoryItem>().FirstOrDefault(a =>
            string.Equals(a.AgentId, agentId, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status, description, tags_json, metadata_json, created_at_utc, updated_at_utc " +
            "FROM tenant_assets WHERE tenant_id=@tenant ORDER BY name, asset_id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        var list = new List<TenantAsset>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            list.Add(ReadAsset(reader));
        return list;
    }

    public async Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status, description, tags_json, metadata_json, created_at_utc, updated_at_utc " +
            "FROM tenant_assets WHERE tenant_id=@tenant AND asset_id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", assetId);
        await using var reader = await cmd.ExecuteReaderAsync();
        return await reader.ReadAsync() ? ReadAsset(reader) : null;
    }

    public async Task UpsertAssetAsync(string tenantId, TenantAsset asset)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO tenant_assets(
                asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status,
                description, tags_json, metadata_json, created_at_utc, updated_at_utc)
            VALUES (@id, @tenant, @name, @kind, @hostname, @address, @environment, @criticality, @status,
                @description, @tags, @metadata, @created, @updated)
            ON CONFLICT(asset_id) DO UPDATE SET
                name=EXCLUDED.name,
                kind=EXCLUDED.kind,
                hostname=EXCLUDED.hostname,
                address=EXCLUDED.address,
                environment=EXCLUDED.environment,
                criticality=EXCLUDED.criticality,
                status=EXCLUDED.status,
                description=EXCLUDED.description,
                tags_json=EXCLUDED.tags_json,
                metadata_json=EXCLUDED.metadata_json,
                updated_at_utc=EXCLUDED.updated_at_utc
            WHERE tenant_assets.tenant_id=EXCLUDED.tenant_id;
            """;
        cmd.Parameters.AddWithValue("id", asset.AssetId);
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("name", asset.Name);
        cmd.Parameters.AddWithValue("kind", asset.Kind);
        cmd.Parameters.AddWithValue("hostname", (object?)asset.Hostname ?? DBNull.Value);
        cmd.Parameters.AddWithValue("address", (object?)asset.Address ?? DBNull.Value);
        cmd.Parameters.AddWithValue("environment", asset.Environment);
        cmd.Parameters.AddWithValue("criticality", asset.Criticality);
        cmd.Parameters.AddWithValue("status", asset.Status);
        cmd.Parameters.AddWithValue("description", (object?)asset.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tags", JsonSerializer.Serialize(asset.Tags, JsonOptions));
        cmd.Parameters.AddWithValue("metadata", JsonSerializer.Serialize(asset.Metadata, JsonOptions));
        cmd.Parameters.AddWithValue("created", asset.CreatedAtUtc);
        cmd.Parameters.AddWithValue("updated", asset.UpdatedAtUtc);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> DeleteAssetAsync(string tenantId, string assetId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM tenant_assets WHERE tenant_id=@tenant AND asset_id=@id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", assetId);
        return await cmd.ExecuteNonQueryAsync() > 0;
    }

    public async Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM topology_documents WHERE tenant_id=@tenant ORDER BY updated_at_utc DESC, topology_id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        var list = new List<TopologyDocument>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var item = JsonSerializer.Deserialize<TopologyDocument>(reader.GetString(0), JsonOptions);
            if (item is not null) list.Add(item);
        }
        return list;
    }

    public async Task<TopologyDocument?> GetTopologyAsync(string tenantId, string topologyId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM topology_documents WHERE tenant_id=@tenant AND topology_id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", topologyId);
        var payload = await cmd.ExecuteScalarAsync();
        return payload is string json ? JsonSerializer.Deserialize<TopologyDocument>(json, JsonOptions) : null;
    }

    public async Task UpsertTopologyAsync(string tenantId, TopologyDocument topology)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO topology_documents(topology_id, tenant_id, name, description, version, payload, created_at_utc, updated_at_utc)
            VALUES (@id, @tenant, @name, @description, @version, @payload, @created, @updated)
            ON CONFLICT(topology_id) DO UPDATE SET
                name=EXCLUDED.name,
                description=EXCLUDED.description,
                version=EXCLUDED.version,
                payload=EXCLUDED.payload,
                updated_at_utc=EXCLUDED.updated_at_utc
            WHERE topology_documents.tenant_id=EXCLUDED.tenant_id;
            """;
        cmd.Parameters.AddWithValue("id", topology.TopologyId);
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("name", topology.Name);
        cmd.Parameters.AddWithValue("description", (object?)topology.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("version", topology.Version);
        cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(topology, JsonOptions));
        cmd.Parameters.AddWithValue("created", topology.CreatedAtUtc);
        cmd.Parameters.AddWithValue("updated", topology.UpdatedAtUtc);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> DeleteTopologyAsync(string tenantId, string topologyId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM topology_documents WHERE tenant_id=@tenant AND topology_id=@id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", topologyId);
        return await cmd.ExecuteNonQueryAsync() > 0;
    }

    public async Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM detection_workflows WHERE tenant_id=@tenant ORDER BY updated_at_utc DESC, workflow_id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        var list = new List<DetectionWorkflow>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var item = JsonSerializer.Deserialize<DetectionWorkflow>(reader.GetString(0), JsonOptions);
            if (item is not null) list.Add(item);
        }
        return list;
    }

    public async Task<DetectionWorkflow?> GetWorkflowAsync(string tenantId, string workflowId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM detection_workflows WHERE tenant_id=@tenant AND workflow_id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", workflowId);
        var payload = await cmd.ExecuteScalarAsync();
        return payload is string json ? JsonSerializer.Deserialize<DetectionWorkflow>(json, JsonOptions) : null;
    }

    public async Task UpsertWorkflowAsync(string tenantId, DetectionWorkflow workflow)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO detection_workflows(workflow_id, tenant_id, name, topology_id, enabled, version, payload, created_at_utc, updated_at_utc)
            VALUES (@id, @tenant, @name, @topology, @enabled, @version, @payload, @created, @updated)
            ON CONFLICT(workflow_id) DO UPDATE SET
                name=EXCLUDED.name,
                topology_id=EXCLUDED.topology_id,
                enabled=EXCLUDED.enabled,
                version=EXCLUDED.version,
                payload=EXCLUDED.payload,
                updated_at_utc=EXCLUDED.updated_at_utc
            WHERE detection_workflows.tenant_id=EXCLUDED.tenant_id;
            """;
        cmd.Parameters.AddWithValue("id", workflow.WorkflowId);
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("name", workflow.Name);
        cmd.Parameters.AddWithValue("topology", (object?)workflow.TopologyId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", workflow.Enabled);
        cmd.Parameters.AddWithValue("version", workflow.Version);
        cmd.Parameters.AddWithValue("payload", JsonSerializer.Serialize(workflow, JsonOptions));
        cmd.Parameters.AddWithValue("created", workflow.CreatedAtUtc);
        cmd.Parameters.AddWithValue("updated", workflow.UpdatedAtUtc);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId)
    {
        await using var conn = new NpgsqlConnection(_cs);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM detection_workflows WHERE tenant_id=@tenant AND workflow_id=@id;";
        cmd.Parameters.AddWithValue("tenant", tenantId);
        cmd.Parameters.AddWithValue("id", workflowId);
        return await cmd.ExecuteNonQueryAsync() > 0;
    }

    private static TenantAsset ReadAsset(NpgsqlDataReader reader)
    {
        var tags = JsonSerializer.Deserialize<List<string>>(reader.GetString(10), JsonOptions) ?? [];
        var metadata = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(11), JsonOptions)
                       ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        return new TenantAsset
        {
            AssetId = reader.GetString(0),
            TenantId = reader.GetString(1),
            Name = reader.GetString(2),
            Kind = reader.GetString(3),
            Hostname = reader.IsDBNull(4) ? null : reader.GetString(4),
            Address = reader.IsDBNull(5) ? null : reader.GetString(5),
            Environment = reader.GetString(6),
            Criticality = reader.GetString(7),
            Status = reader.GetString(8),
            Description = reader.IsDBNull(9) ? null : reader.GetString(9),
            Tags = tags,
            Metadata = metadata,
            CreatedAtUtc = reader.GetFieldValue<DateTimeOffset>(12),
            UpdatedAtUtc = reader.GetFieldValue<DateTimeOffset>(13)
        };
    }
}
