using System.Text.Json;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Data;

public sealed class SqliteCentralOptions
{
    public const string SectionName = "Sqlite";
    public string DatabasePath { get; set; } =
        @"C:\ProgramData\NTShield\Server\central.db";
}

/// <summary>
/// Default Central store for lab / single-server installs (no PostgreSQL required).
/// </summary>
public sealed class SqliteCentralStore : ICentralStore
{
    private readonly string _dbPath;
    private readonly ILogger<SqliteCentralStore> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public SqliteCentralStore(IOptions<SqliteCentralOptions> options, ILogger<SqliteCentralStore> logger)
    {
        _dbPath = options.Value.DatabasePath;
        _logger = logger;
    }

    private SqliteConnection Open()
    {
        var dir = Path.GetDirectoryName(_dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString());
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    public async Task InitializeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
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
                    last_seen_utc TEXT NOT NULL,
                    queue_depth INTEGER,
                    db_size_bytes INTEGER,
                    status TEXT,
                    working_set_bytes INTEGER,
                    clock_skew_seconds REAL
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    key TEXT PRIMARY KEY,
                    created_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    computer_name TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    username TEXT,
                    domain TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    logon_type INTEGER,
                    process_id INTEGER,
                    process_path TEXT,
                    status TEXT,
                    raw_xml TEXT,
                    event_record_id INTEGER,
                    payload TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_sec_events_ts ON security_events(timestamp_utc);
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    computer_name TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    protocol TEXT,
                    local_address TEXT,
                    local_port INTEGER,
                    remote_address TEXT,
                    remote_port INTEGER,
                    process_id INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    process_command_line TEXT,
                    service_names TEXT,
                    is_new INTEGER,
                    is_closed INTEGER,
                    payload TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_net_remote ON network_connections(remote_address, timestamp_utc);
                CREATE TABLE IF NOT EXISTS detection_alerts (
                    alert_id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    computer_name TEXT,
                    rule_id TEXT,
                    severity INTEGER,
                    timestamp_utc TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    username TEXT,
                    payload TEXT
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    first_seen_utc TEXT,
                    last_seen_utc TEXT,
                    severity INTEGER,
                    title TEXT,
                    description TEXT,
                    correlation_key TEXT,
                    source_host TEXT,
                    source_agent_id TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    source_process_id INTEGER,
                    source_process_name TEXT,
                    source_process_path TEXT,
                    source_service_names TEXT,
                    source_command_line TEXT,
                    destination_host TEXT,
                    destination_agent_id TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    username TEXT,
                    domain TEXT,
                    logon_type INTEGER,
                    failed_logon_count INTEGER,
                    successful_logon_count INTEGER,
                    privileged_logon INTEGER,
                    evidence_json TEXT,
                    status TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_incidents_last ON incidents(last_seen_utc);
                CREATE TABLE IF NOT EXISTS pending_actions (
                    request_id TEXT PRIMARY KEY,
                    agent_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS ix_pending_agent ON pending_actions(agent_key, delivered);
                CREATE TABLE IF NOT EXISTS threat_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT,
                    action TEXT,
                    target TEXT,
                    result TEXT,
                    detail_json TEXT,
                    source_ip TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_log(timestamp_utc);
                CREATE TABLE IF NOT EXISTS agent_policies (
                    policy_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    json TEXT NOT NULL,
                    updated_utc TEXT NOT NULL
                );
                """;
            await cmd.ExecuteNonQueryAsync();

            // Best-effort schema upgrades for existing DBs
            foreach (var alter in new[]
                     {
                         "ALTER TABLE agents ADD COLUMN central_url TEXT;",
                         "ALTER TABLE agents ADD COLUMN platform TEXT;",
                         "ALTER TABLE agents ADD COLUMN last_error TEXT;",
                         "ALTER TABLE agents ADD COLUMN agent_api_key_hash TEXT;",
                         "ALTER TABLE agents ADD COLUMN binary_sha256 TEXT;",
                         "ALTER TABLE agents ADD COLUMN is_binary_signed INTEGER;",
                         "ALTER TABLE agents ADD COLUMN policy_version INTEGER;",
                         "ALTER TABLE agents ADD COLUMN cpu_percent REAL;",
                         "ALTER TABLE agents ADD COLUMN mem_used_percent REAL;",
                         "ALTER TABLE agents ADD COLUMN disk_used_percent REAL;",
                         "ALTER TABLE agents ADD COLUMN net_rx_bps REAL;",
                         "ALTER TABLE agents ADD COLUMN net_tx_bps REAL;",
                         "ALTER TABLE agents ADD COLUMN disk_read_bps REAL;",
                         "ALTER TABLE agents ADD COLUMN disk_write_bps REAL;",
                         "ALTER TABLE agents ADD COLUMN load1 REAL;",
                         "ALTER TABLE agents ADD COLUMN host_mem_used INTEGER;",
                         "ALTER TABLE agents ADD COLUMN host_mem_total INTEGER;",
                         "ALTER TABLE agents ADD COLUMN metrics_summary TEXT;"
                     })
            {
                try
                {
                    await using var alt = conn.CreateCommand();
                    alt.CommandText = alter;
                    await alt.ExecuteNonQueryAsync();
                }
                catch
                {
                    // column already exists
                }
            }

            await using (var metricsTbl = conn.CreateCommand())
            {
                metricsTbl.CommandText =
                    """
                    CREATE TABLE IF NOT EXISTS agent_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        timestamp_utc TEXT NOT NULL,
                        cpu REAL,
                        mem_pct REAL,
                        disk_pct REAL,
                        net_rx REAL,
                        net_tx REAL,
                        io_r REAL,
                        io_w REAL,
                        load1 REAL,
                        queue_depth INTEGER,
                        working_set INTEGER,
                        status TEXT
                    );
                    CREATE INDEX IF NOT EXISTS ix_agent_metrics_agent_ts ON agent_metrics(agent_id, timestamp_utc);
                    """;
                await metricsTbl.ExecuteNonQueryAsync();
            }

            await using (var topologyTbl = conn.CreateCommand())
            {
                topologyTbl.CommandText =
                    """
                    CREATE TABLE IF NOT EXISTS customer_tenants (
                        tenant_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        legal_name TEXT,
                        contact_name TEXT,
                        contact_email TEXT,
                        plan TEXT NOT NULL,
                        status TEXT NOT NULL,
                        notes TEXT,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS tenant_agent_assignments (
                        agent_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        assigned_at_utc TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_tenant_agent_assignments_tenant ON tenant_agent_assignments(tenant_id, agent_id);

                    CREATE TABLE IF NOT EXISTS security_reports (
                        report_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        period_start_utc TEXT NOT NULL,
                        period_end_utc TEXT NOT NULL,
                        generated_at_utc TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_security_reports_tenant ON security_reports(tenant_id, generated_at_utc);

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
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_tenant_assets_tenant ON tenant_assets(tenant_id, updated_at_utc);

                    CREATE TABLE IF NOT EXISTS topology_documents (
                        topology_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT,
                        version INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_topology_documents_tenant ON topology_documents(tenant_id, updated_at_utc);

                    CREATE TABLE IF NOT EXISTS detection_workflows (
                        workflow_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        topology_id TEXT,
                        enabled INTEGER NOT NULL,
                        version INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_detection_workflows_tenant ON detection_workflows(tenant_id, updated_at_utc);

                    INSERT OR IGNORE INTO customer_tenants(
                        tenant_id, name, plan, status, created_at_utc, updated_at_utc)
                    VALUES ('default', 'Default customer', 'standard', 'active',
                        strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));

                    INSERT OR IGNORE INTO tenant_agent_assignments(agent_id, tenant_id, assigned_at_utc)
                    SELECT agent_id, 'default', strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM agents;
                    """;
                await topologyTbl.ExecuteNonQueryAsync();
            }

            // Default policy if missing
            await using (var seed = conn.CreateCommand())
            {
                seed.CommandText = "SELECT COUNT(1) FROM agent_policies WHERE policy_id='default';";
                var count = Convert.ToInt64(await seed.ExecuteScalarAsync() ?? 0L);
                if (count == 0)
                {
                    var defaultPolicy = new AgentPolicy { PolicyId = "default", PolicyVersion = 1, Mode = "Ids", DetectOnly = true };
                    await using var ins = conn.CreateCommand();
                    ins.CommandText =
                        "INSERT INTO agent_policies(policy_id, version, json, updated_utc) VALUES ('default', 1, $j, $t);";
                    ins.Parameters.AddWithValue("$j", JsonSerializer.Serialize(defaultPolicy, JsonOptions));
                    ins.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
                    await ins.ExecuteNonQueryAsync();
                }
            }

            _logger.LogInformation("SQLite Central store ready at {Path}", _dbPath);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RegisterAgentAsync(AgentRegistrationRequest req)
    {
        await UpsertAgentCoreAsync(req.AgentId, req.ComputerName, req.AgentVersion, req.OsVersion,
            queue: 0, db: 0, status: "Registered", ws: 0, skew: 0, hostIp: req.HostIp, thumb: req.CertificateThumbprint);

        if (!string.IsNullOrWhiteSpace(req.TenantId))
        {
            await AssignAgentToTenantAsync(req.TenantId.Trim().ToLowerInvariant(), req.AgentId);
        }
        else
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "INSERT OR IGNORE INTO tenant_agent_assignments(agent_id, tenant_id, assigned_at_utc) VALUES ($agent, 'default', $assigned);";
            cmd.Parameters.AddWithValue("$agent", req.AgentId);
            cmd.Parameters.AddWithValue("$assigned", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
    }

    public async Task UpsertAgentAsync(AgentHeartbeat hb)
    {
        await UpsertAgentCoreAsync(hb.AgentId, hb.ComputerName, hb.AgentVersion, hb.OsVersion,
            hb.LocalQueueDepth, hb.DatabaseSizeBytes, hb.Status, hb.WorkingSetBytes, hb.ClockSkewSeconds,
            hostIp: hb.HostIp, thumb: null, ts: hb.TimestampUtc,
            centralUrl: hb.CentralUrl, platform: hb.Platform, lastError: hb.LastError,
            binarySha256: hb.BinarySha256, isSigned: hb.IsBinarySigned, policyVersion: hb.AppliedPolicyVersion,
            cpu: hb.CpuPercentEstimate, memPct: hb.MemUsedPercent, diskPct: hb.DiskUsedPercent,
            netRx: hb.NetworkRxBytesPerSec, netTx: hb.NetworkTxBytesPerSec,
            ioR: hb.DiskReadBytesPerSec, ioW: hb.DiskWriteBytesPerSec, load1: hb.LoadAverage1,
            hostMemUsed: hb.HostMemUsedBytes, hostMemTotal: hb.HostMemTotalBytes,
            metricsSummary: hb.MetricsSummary);
        await SaveAgentMetricsAsync(hb);
    }

    private async Task UpsertAgentCoreAsync(
        string agentId, string computerName, string? version, string? os,
        long queue, long db, string status, long ws, double skew,
        string? hostIp, string? thumb, DateTimeOffset? ts = null,
        string? centralUrl = null, string? platform = null, string? lastError = null,
        string? binarySha256 = null, bool? isSigned = null, int? policyVersion = null,
        double? cpu = null, double? memPct = null, double? diskPct = null,
        double? netRx = null, double? netTx = null, double? ioR = null, double? ioW = null,
        double? load1 = null, long? hostMemUsed = null, long? hostMemTotal = null,
        string? metricsSummary = null)
    {
        var when = (ts ?? DateTimeOffset.UtcNow).ToString("O");
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO agents(agent_id, computer_name, agent_version, os_version, host_ip, certificate_thumbprint,
                    last_seen_utc, queue_depth, db_size_bytes, status, working_set_bytes, clock_skew_seconds,
                    central_url, platform, last_error, binary_sha256, is_binary_signed, policy_version,
                    cpu_percent, mem_used_percent, disk_used_percent, net_rx_bps, net_tx_bps, disk_read_bps, disk_write_bps,
                    load1, host_mem_used, host_mem_total, metrics_summary)
                VALUES ($id, $cn, $ver, $os, $ip, $thumb, $ts, $q, $db, $st, $ws, $skew, $curl, $plat, $err, $sha, $sig, $pv,
                    $cpu, $mem, $disk, $nrx, $ntx, $ior, $iow, $load, $hmu, $hmt, $ms)
                ON CONFLICT(agent_id) DO UPDATE SET
                    computer_name=excluded.computer_name,
                    agent_version=excluded.agent_version,
                    os_version=excluded.os_version,
                    host_ip=COALESCE(excluded.host_ip, agents.host_ip),
                    certificate_thumbprint=COALESCE(excluded.certificate_thumbprint, agents.certificate_thumbprint),
                    last_seen_utc=excluded.last_seen_utc,
                    queue_depth=excluded.queue_depth,
                    db_size_bytes=excluded.db_size_bytes,
                    status=excluded.status,
                    working_set_bytes=excluded.working_set_bytes,
                    clock_skew_seconds=excluded.clock_skew_seconds,
                    central_url=COALESCE(excluded.central_url, agents.central_url),
                    platform=COALESCE(excluded.platform, agents.platform),
                    last_error=excluded.last_error,
                    binary_sha256=COALESCE(excluded.binary_sha256, agents.binary_sha256),
                    is_binary_signed=COALESCE(excluded.is_binary_signed, agents.is_binary_signed),
                    policy_version=COALESCE(excluded.policy_version, agents.policy_version),
                    cpu_percent=COALESCE(excluded.cpu_percent, agents.cpu_percent),
                    mem_used_percent=COALESCE(excluded.mem_used_percent, agents.mem_used_percent),
                    disk_used_percent=COALESCE(excluded.disk_used_percent, agents.disk_used_percent),
                    net_rx_bps=COALESCE(excluded.net_rx_bps, agents.net_rx_bps),
                    net_tx_bps=COALESCE(excluded.net_tx_bps, agents.net_tx_bps),
                    disk_read_bps=COALESCE(excluded.disk_read_bps, agents.disk_read_bps),
                    disk_write_bps=COALESCE(excluded.disk_write_bps, agents.disk_write_bps),
                    load1=COALESCE(excluded.load1, agents.load1),
                    host_mem_used=COALESCE(excluded.host_mem_used, agents.host_mem_used),
                    host_mem_total=COALESCE(excluded.host_mem_total, agents.host_mem_total),
                    metrics_summary=COALESCE(excluded.metrics_summary, agents.metrics_summary);
                """;
            cmd.Parameters.AddWithValue("$id", agentId);
            cmd.Parameters.AddWithValue("$cn", computerName);
            cmd.Parameters.AddWithValue("$ver", (object?)version ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$os", (object?)os ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ip", (object?)hostIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$thumb", (object?)thumb ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ts", when);
            cmd.Parameters.AddWithValue("$q", queue);
            cmd.Parameters.AddWithValue("$db", db);
            cmd.Parameters.AddWithValue("$st", status);
            cmd.Parameters.AddWithValue("$ws", ws);
            cmd.Parameters.AddWithValue("$skew", skew);
            cmd.Parameters.AddWithValue("$curl", (object?)centralUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$plat", (object?)platform ?? "windows");
            cmd.Parameters.AddWithValue("$err", (object?)lastError ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sha", (object?)binarySha256 ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sig", isSigned.HasValue ? (isSigned.Value ? 1 : 0) : DBNull.Value);
            cmd.Parameters.AddWithValue("$pv", policyVersion.HasValue ? policyVersion.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$cpu", cpu.HasValue ? cpu.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$mem", memPct.HasValue ? memPct.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$disk", diskPct.HasValue ? diskPct.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$nrx", netRx.HasValue ? netRx.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$ntx", netTx.HasValue ? netTx.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$ior", ioR.HasValue ? ioR.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$iow", ioW.HasValue ? ioW.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$load", load1.HasValue ? load1.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$hmu", hostMemUsed.HasValue ? hostMemUsed.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$hmt", hostMemTotal.HasValue ? hostMemTotal.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$ms", (object?)metricsSummary ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> HasIdempotencyKeyAsync(string key)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM idempotency_keys WHERE key=$k LIMIT 1;";
        cmd.Parameters.AddWithValue("$k", key);
        return await cmd.ExecuteScalarAsync() is not null;
    }

    public async Task SaveIdempotencyKeyAsync(string key)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO idempotency_keys(key, created_at_utc) VALUES ($k, $t);";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task SaveBatchAsync(AgentIngestBatch batch)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var tx = conn.BeginTransaction();

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
                        $agent_id, $computer_name, $event_id, $timestamp_utc, $username, $domain,
                        $source_ip, $source_port, $destination_ip, $destination_port, $logon_type,
                        $process_id, $process_path, $status, $raw_xml, $event_record_id, $payload);
                    """;
                cmd.Parameters.AddWithValue("$agent_id", e.AgentId);
                cmd.Parameters.AddWithValue("$computer_name", e.ComputerName);
                cmd.Parameters.AddWithValue("$event_id", e.EventId);
                cmd.Parameters.AddWithValue("$timestamp_utc", e.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$username", (object?)e.Username ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$domain", (object?)e.Domain ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$source_ip", (object?)e.SourceIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$source_port", (object?)e.SourcePort ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$destination_ip", (object?)e.DestinationIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$destination_port", (object?)e.DestinationPort ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$logon_type", (object?)e.LogonType ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_id", (object?)e.ProcessId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_path", (object?)e.ProcessPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$status", (object?)e.Status ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$raw_xml", (object?)e.RawXml ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$event_record_id", e.EventRecordId);
                cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(e, JsonOptions));
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
                        $agent_id, $computer_name, $timestamp_utc, $protocol, $local_address, $local_port,
                        $remote_address, $remote_port, $process_id, $process_name, $process_path,
                        $process_command_line, $service_names, $is_new, $is_closed, $payload);
                    """;
                cmd.Parameters.AddWithValue("$agent_id", n.AgentId);
                cmd.Parameters.AddWithValue("$computer_name", n.ComputerName);
                cmd.Parameters.AddWithValue("$timestamp_utc", n.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$protocol", n.Protocol);
                cmd.Parameters.AddWithValue("$local_address", n.LocalAddress);
                cmd.Parameters.AddWithValue("$local_port", n.LocalPort);
                cmd.Parameters.AddWithValue("$remote_address", n.RemoteAddress);
                cmd.Parameters.AddWithValue("$remote_port", n.RemotePort);
                cmd.Parameters.AddWithValue("$process_id", n.ProcessId);
                cmd.Parameters.AddWithValue("$process_name", (object?)n.ProcessName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_path", (object?)n.ProcessPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_command_line", (object?)n.ProcessCommandLine ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$service_names", (object?)n.ServiceNames ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$is_new", n.IsNew ? 1 : 0);
                cmd.Parameters.AddWithValue("$is_closed", n.IsClosed ? 1 : 0);
                cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(n, JsonOptions));
                await cmd.ExecuteNonQueryAsync();
            }

            foreach (var a in batch.Alerts)
            {
                await using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT OR IGNORE INTO detection_alerts(
                        alert_id, agent_id, computer_name, rule_id, severity, timestamp_utc,
                        source_ip, destination_ip, username, payload)
                    VALUES ($alert_id, $agent_id, $computer_name, $rule_id, $severity, $timestamp_utc,
                        $source_ip, $destination_ip, $username, $payload);
                    """;
                cmd.Parameters.AddWithValue("$alert_id", a.AlertId);
                cmd.Parameters.AddWithValue("$agent_id", a.AgentId);
                cmd.Parameters.AddWithValue("$computer_name", a.ComputerName);
                cmd.Parameters.AddWithValue("$rule_id", a.RuleId);
                cmd.Parameters.AddWithValue("$severity", (int)a.Severity);
                cmd.Parameters.AddWithValue("$timestamp_utc", a.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$source_ip", (object?)a.SourceIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$destination_ip", (object?)a.DestinationIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$username", (object?)a.Username ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(a, JsonOptions));
                await cmd.ExecuteNonQueryAsync();
            }

            await tx.CommitAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task UpsertIncidentAsync(Incident incident)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
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
                    $incident_id, $first_seen_utc, $last_seen_utc, $severity, $title, $description, $correlation_key,
                    $source_host, $source_agent_id, $source_ip, $source_port, $source_process_id, $source_process_name,
                    $source_process_path, $source_service_names, $source_command_line,
                    $destination_host, $destination_agent_id, $destination_ip, $destination_port,
                    $username, $domain, $logon_type, $failed_logon_count, $successful_logon_count, $privileged_logon,
                    $evidence_json, $status)
                ON CONFLICT(incident_id) DO UPDATE SET
                    last_seen_utc=excluded.last_seen_utc,
                    severity=excluded.severity,
                    title=excluded.title,
                    description=excluded.description,
                    evidence_json=excluded.evidence_json,
                    status=excluded.status,
                    failed_logon_count=excluded.failed_logon_count,
                    successful_logon_count=excluded.successful_logon_count;
                """;
            cmd.Parameters.AddWithValue("$incident_id", incident.IncidentId);
            cmd.Parameters.AddWithValue("$first_seen_utc", incident.FirstSeenUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$last_seen_utc", incident.LastSeenUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$severity", (int)incident.Severity);
            cmd.Parameters.AddWithValue("$title", incident.Title ?? "");
            cmd.Parameters.AddWithValue("$description", incident.Description ?? "");
            cmd.Parameters.AddWithValue("$correlation_key", incident.CorrelationKey ?? "");
            cmd.Parameters.AddWithValue("$source_host", (object?)incident.SourceHost ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_agent_id", (object?)incident.SourceAgentId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_ip", (object?)incident.SourceIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_port", (object?)incident.SourcePort ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_process_id", (object?)incident.SourceProcessId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_process_name", (object?)incident.SourceProcessName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_process_path", (object?)incident.SourceProcessPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_service_names", (object?)incident.SourceServiceNames ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source_command_line", (object?)incident.SourceCommandLine ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$destination_host", (object?)incident.DestinationHost ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$destination_agent_id", (object?)incident.DestinationAgentId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$destination_ip", (object?)incident.DestinationIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$destination_port", (object?)incident.DestinationPort ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$username", (object?)incident.Username ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$domain", (object?)incident.Domain ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$logon_type", (object?)incident.LogonType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$failed_logon_count", incident.FailedLogonCount);
            cmd.Parameters.AddWithValue("$successful_logon_count", incident.SuccessfulLogonCount);
            cmd.Parameters.AddWithValue("$privileged_logon", incident.PrivilegedLogon ? 1 : 0);
            cmd.Parameters.AddWithValue("$evidence_json",
                string.IsNullOrWhiteSpace(incident.EvidenceJson) ? "[]" : incident.EvidenceJson);
            cmd.Parameters.AddWithValue("$status", incident.Status ?? "Open");
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SecurityEventRecord>> ListSecurityEventsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        var filters = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenantId))
        {
            filters.Add("EXISTS (SELECT 1 FROM tenant_agent_assignments taa WHERE taa.agent_id=e.agent_id AND taa.tenant_id=$tenant)");
            cmd.Parameters.AddWithValue("$tenant", tenantId);
        }
        if (fromUtc is not null)
        {
            filters.Add("e.timestamp_utc >= $from");
            cmd.Parameters.AddWithValue("$from", fromUtc.Value.ToString("O"));
        }
        if (toUtc is not null)
        {
            filters.Add("e.timestamp_utc <= $to");
            cmd.Parameters.AddWithValue("$to", toUtc.Value.ToString("O"));
        }
        var where = filters.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", filters)}";
        cmd.CommandText =
            $"""
            SELECT e.id, e.agent_id, e.computer_name, e.event_id, e.timestamp_utc, e.username, e.domain,
                   e.source_ip, e.source_port, e.destination_ip, e.destination_port, e.logon_type,
                   e.process_id, e.process_path, e.status, e.raw_xml, e.event_record_id
            FROM security_events e
            {where}
            ORDER BY e.timestamp_utc DESC
            LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$take", take);
        var list = new List<SecurityEventRecord>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new SecurityEventRecord
            {
                Id = reader.GetInt64(0),
                AgentId = reader.GetString(1),
                ComputerName = reader.GetString(2),
                EventId = reader.GetInt32(3),
                TimestampUtc = DateTimeOffset.Parse(reader.GetString(4)),
                Username = reader.IsDBNull(5) ? null : reader.GetString(5),
                Domain = reader.IsDBNull(6) ? null : reader.GetString(6),
                SourceIp = reader.IsDBNull(7) ? null : reader.GetString(7),
                SourcePort = reader.IsDBNull(8) ? null : reader.GetInt32(8),
                DestinationIp = reader.IsDBNull(9) ? null : reader.GetString(9),
                DestinationPort = reader.IsDBNull(10) ? null : reader.GetInt32(10),
                LogonType = reader.IsDBNull(11) ? null : reader.GetInt32(11),
                ProcessId = reader.IsDBNull(12) ? null : reader.GetInt32(12),
                ProcessPath = reader.IsDBNull(13) ? null : reader.GetString(13),
                Status = reader.IsDBNull(14) ? null : reader.GetString(14),
                RawXml = reader.IsDBNull(15) ? string.Empty : reader.GetString(15),
                EventRecordId = reader.IsDBNull(16) ? 0 : reader.GetInt64(16)
            });
        }

        return list;
    }

    public async Task<IReadOnlyList<Incident>> ListIncidentsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        var filters = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenantId))
        {
            filters.Add(
                """
                (
                    EXISTS (
                        SELECT 1 FROM tenant_agent_assignments taa
                        WHERE taa.tenant_id=$tenant
                          AND (taa.agent_id=i.source_agent_id OR taa.agent_id=i.destination_agent_id))
                    OR ($tenant='default' AND NOT EXISTS (
                        SELECT 1 FROM tenant_agent_assignments mapped
                        WHERE mapped.agent_id=i.source_agent_id OR mapped.agent_id=i.destination_agent_id))
                )
                """);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
        }
        if (fromUtc is not null)
        {
            filters.Add("i.last_seen_utc >= $from");
            cmd.Parameters.AddWithValue("$from", fromUtc.Value.ToString("O"));
        }
        if (toUtc is not null)
        {
            filters.Add("i.last_seen_utc <= $to");
            cmd.Parameters.AddWithValue("$to", toUtc.Value.ToString("O"));
        }
        var where = filters.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", filters)}";
        cmd.CommandText =
            $"""
            SELECT incident_id, first_seen_utc, last_seen_utc, severity, title, description, correlation_key,
                   source_host, source_agent_id, source_ip, source_port, source_process_id, source_process_name,
                   source_process_path, source_service_names, source_command_line,
                   destination_host, destination_agent_id, destination_ip, destination_port,
                   username, domain, logon_type, failed_logon_count, successful_logon_count, privileged_logon,
                   evidence_json, status
            FROM incidents i
            {where}
            ORDER BY last_seen_utc DESC LIMIT $take;
            """;
        cmd.Parameters.AddWithValue("$take", take);
        var list = new List<Incident>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(ReadIncident(reader));
        }

        return list;
    }

    public async Task<long> CountIncidentsAsync(
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        var filters = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenantId))
        {
            filters.Add(
                """
                (
                    EXISTS (
                        SELECT 1 FROM tenant_agent_assignments taa
                        WHERE taa.tenant_id=$tenant
                          AND (taa.agent_id=i.source_agent_id OR taa.agent_id=i.destination_agent_id))
                    OR ($tenant='default' AND NOT EXISTS (
                        SELECT 1 FROM tenant_agent_assignments mapped
                        WHERE mapped.agent_id=i.source_agent_id OR mapped.agent_id=i.destination_agent_id))
                )
                """);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
        }
        if (fromUtc is not null)
        {
            filters.Add("i.last_seen_utc >= $from");
            cmd.Parameters.AddWithValue("$from", fromUtc.Value.ToString("O"));
        }
        if (toUtc is not null)
        {
            filters.Add("i.last_seen_utc <= $to");
            cmd.Parameters.AddWithValue("$to", toUtc.Value.ToString("O"));
        }
        var where = filters.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", filters)}";
        cmd.CommandText = $"SELECT COUNT(*) FROM incidents i {where};";
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    public async Task<TenantReportAggregate> GetReportAggregateAsync(
        string tenantId,
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc)
    {
        await using var conn = Open();
        var result = new TenantReportAggregate();

        await using (var eventCmd = conn.CreateCommand())
        {
            eventCmd.CommandText =
                """
                SELECT COUNT(*)
                FROM security_events e
                WHERE e.timestamp_utc >= $from AND e.timestamp_utc <= $to
                  AND EXISTS (
                    SELECT 1 FROM tenant_agent_assignments taa
                    WHERE taa.tenant_id=$tenant AND taa.agent_id=e.agent_id);
                """;
            eventCmd.Parameters.AddWithValue("$tenant", tenantId);
            eventCmd.Parameters.AddWithValue("$from", fromUtc.ToUniversalTime().ToString("O"));
            eventCmd.Parameters.AddWithValue("$to", toUtc.ToUniversalTime().ToString("O"));
            result.ThreatEvents = Convert.ToInt32(await eventCmd.ExecuteScalarAsync());
        }

        await using (var incidentCmd = conn.CreateCommand())
        {
            incidentCmd.CommandText =
                """
                SELECT COUNT(*),
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(i.status,'')) IN ('closed','resolved') THEN 0 ELSE 1 END),0),
                       COALESCE(SUM(CASE WHEN i.severity=4 THEN 1 ELSE 0 END),0),
                       COALESCE(SUM(CASE WHEN i.severity=3 THEN 1 ELSE 0 END),0),
                       COALESCE(SUM(CASE WHEN i.severity=2 THEN 1 ELSE 0 END),0),
                       COALESCE(SUM(CASE WHEN i.severity=1 THEN 1 ELSE 0 END),0)
                FROM incidents i
                WHERE i.last_seen_utc >= $from AND i.last_seen_utc <= $to
                  AND (
                    EXISTS (
                        SELECT 1 FROM tenant_agent_assignments taa
                        WHERE taa.tenant_id=$tenant
                          AND (taa.agent_id=i.source_agent_id OR taa.agent_id=i.destination_agent_id))
                    OR ($tenant='default' AND NOT EXISTS (
                        SELECT 1 FROM tenant_agent_assignments mapped
                        WHERE mapped.agent_id=i.source_agent_id OR mapped.agent_id=i.destination_agent_id))
                  );
                """;
            incidentCmd.Parameters.AddWithValue("$tenant", tenantId);
            incidentCmd.Parameters.AddWithValue("$from", fromUtc.ToUniversalTime().ToString("O"));
            incidentCmd.Parameters.AddWithValue("$to", toUtc.ToUniversalTime().ToString("O"));
            await using var reader = await incidentCmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                result.Incidents = Convert.ToInt32(reader.GetValue(0));
                result.OpenIncidents = Convert.ToInt32(reader.GetValue(1));
                result.CriticalIncidents = Convert.ToInt32(reader.GetValue(2));
                result.HighIncidents = Convert.ToInt32(reader.GetValue(3));
                result.MediumIncidents = Convert.ToInt32(reader.GetValue(4));
                result.LowIncidents = Convert.ToInt32(reader.GetValue(5));
            }
        }

        return result;
    }

    public async Task<Incident?> GetIncidentAsync(string id, string? tenantId = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT incident_id, first_seen_utc, last_seen_utc, severity, title, description, correlation_key,
                   source_host, source_agent_id, source_ip, source_port, source_process_id, source_process_name,
                   source_process_path, source_service_names, source_command_line,
                   destination_host, destination_agent_id, destination_ip, destination_port,
                   username, domain, logon_type, failed_logon_count, successful_logon_count, privileged_logon,
                   evidence_json, status
            FROM incidents i
            WHERE incident_id=$id
              AND ($tenant IS NULL OR EXISTS (
                    SELECT 1 FROM tenant_agent_assignments taa
                    WHERE taa.tenant_id=$tenant
                      AND (taa.agent_id=i.source_agent_id OR taa.agent_id=i.destination_agent_id))
                   OR ($tenant='default' AND NOT EXISTS (
                    SELECT 1 FROM tenant_agent_assignments mapped
                    WHERE mapped.agent_id=i.source_agent_id OR mapped.agent_id=i.destination_agent_id)))
            LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return ReadIncident(reader);
    }

    public async Task<IReadOnlyList<object>> ListAgentsAsync(string? tenantId = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT agent_id, computer_name, agent_version, os_version, last_seen_utc, status, queue_depth,
                   host_ip, central_url, platform, last_error, binary_sha256, is_binary_signed, policy_version,
                   db_size_bytes, working_set_bytes, clock_skew_seconds,
                   cpu_percent, mem_used_percent, disk_used_percent, net_rx_bps, net_tx_bps,
                   disk_read_bps, disk_write_bps, load1, host_mem_used, host_mem_total, metrics_summary
            FROM agents a
            WHERE $tenant IS NULL OR EXISTS (
                SELECT 1 FROM tenant_agent_assignments taa
                WHERE taa.agent_id=a.agent_id AND taa.tenant_id=$tenant)
            ORDER BY last_seen_utc DESC;
            """;
        cmd.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        var list = new List<object>();
        var now = DateTimeOffset.UtcNow;
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            list.Add(ReadInventoryRow(reader, now));

        return list;
    }

    private static AgentInventoryItem ReadInventoryRow(SqliteDataReader reader, DateTimeOffset now)
    {
        var lastSeen = DateTimeOffset.Parse(reader.GetString(4));
        var offlineSec = (int)Math.Max(0, (now - lastSeen).TotalSeconds);
        var online = offlineSec <= 120;
        double? Rd(int i) => reader.FieldCount > i && !reader.IsDBNull(i) ? reader.GetDouble(i) : null;
        long? Rl(int i) => reader.FieldCount > i && !reader.IsDBNull(i) ? reader.GetInt64(i) : null;
        string? Rs(int i) => reader.FieldCount > i && !reader.IsDBNull(i) ? reader.GetString(i) : null;

        return new AgentInventoryItem
        {
            AgentId = reader.GetString(0),
            ComputerName = reader.GetString(1),
            AgentVersion = Rs(2),
            OsVersion = Rs(3),
            LastSeenUtc = lastSeen,
            Status = online ? (Rs(5) ?? "Healthy") : "Offline",
            QueueDepth = Rl(6) ?? 0,
            HostIp = Rs(7),
            CentralUrl = Rs(8),
            Platform = Rs(9) ?? "windows",
            LastError = Rs(10),
            BinarySha256 = Rs(11),
            IsBinarySigned = reader.FieldCount > 12 && !reader.IsDBNull(12) ? reader.GetInt64(12) != 0 : null,
            PolicyVersion = reader.FieldCount > 13 && !reader.IsDBNull(13) ? (int)reader.GetInt64(13) : null,
            DatabaseSizeBytes = Rl(14) ?? 0,
            WorkingSetBytes = Rl(15) ?? 0,
            ClockSkewSeconds = Rd(16) ?? 0,
            CpuPercent = Rd(17),
            MemUsedPercent = Rd(18),
            DiskUsedPercent = Rd(19),
            NetworkRxBytesPerSec = Rd(20),
            NetworkTxBytesPerSec = Rd(21),
            DiskReadBytesPerSec = Rd(22),
            DiskWriteBytesPerSec = Rd(23),
            LoadAverage1 = Rd(24),
            HostMemUsedBytes = Rl(25),
            HostMemTotalBytes = Rl(26),
            MetricsSummary = Rs(27),
            Online = online,
            OfflineSeconds = offlineSec
        };
    }

    public async Task SavePendingActionAsync(ResponseActionRequest request, string agentKey)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO pending_actions(request_id, agent_key, payload, created_at_utc, delivered)
                VALUES ($id, $agent, $payload, $ts, 0)
                ON CONFLICT(request_id) DO UPDATE SET
                    agent_key=excluded.agent_key,
                    payload=excluded.payload,
                    delivered=0;
                """;
            cmd.Parameters.AddWithValue("$id", request.RequestId);
            cmd.Parameters.AddWithValue("$agent", agentKey);
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(request, JsonOptions));
            cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            // Prefer agent-specific queue; include broadcast once (marked delivered for that row only if agent_key=broadcast — rare)
            cmd.CommandText =
                """
                SELECT request_id, payload, agent_key FROM pending_actions
                WHERE delivered=0 AND (agent_key=$a OR agent_key='broadcast')
                ORDER BY created_at_utc ASC
                LIMIT 50;
                """;
            cmd.Parameters.AddWithValue("$a", agentId);
            var rows = new List<(string Id, string Payload, string AgentKey)>();
            await using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                    rows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
            }

            var result = new List<ResponseActionRequest>();
            foreach (var (id, payload, agentKey) in rows)
            {
                var req = JsonSerializer.Deserialize<ResponseActionRequest>(payload, JsonOptions);
                if (req is null) continue;
                result.Add(req);

                // Consume agent-specific actions. Leave true broadcast for other agents (not deleted).
                if (!string.Equals(agentKey, "broadcast", StringComparison.OrdinalIgnoreCase))
                {
                    await using var mark = conn.CreateCommand();
                    mark.CommandText = "UPDATE pending_actions SET delivered=1 WHERE request_id=$id;";
                    mark.Parameters.AddWithValue("$id", id);
                    await mark.ExecuteNonQueryAsync();
                }
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<ResponseActionRequest?> GetPendingActionAsync(string requestId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM pending_actions WHERE request_id=$id LIMIT 1;";
        cmd.Parameters.AddWithValue("$id", requestId);
        var o = await cmd.ExecuteScalarAsync();
        if (o is not string json) return null;
        return JsonSerializer.Deserialize<ResponseActionRequest>(json, JsonOptions);
    }

    public async Task UpsertCampaignJsonAsync(string campaignId, string json)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO threat_campaigns(campaign_id, payload, last_seen_utc)
                VALUES ($id, $p, $ts)
                ON CONFLICT(campaign_id) DO UPDATE SET payload=excluded.payload, last_seen_utc=excluded.last_seen_utc;
                """;
            cmd.Parameters.AddWithValue("$id", campaignId);
            cmd.Parameters.AddWithValue("$p", json);
            cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT campaign_id, payload FROM threat_campaigns
            ORDER BY last_seen_utc DESC LIMIT $n;
            """;
        cmd.Parameters.AddWithValue("$n", Math.Clamp(take, 1, 500));
        var list = new List<(string, string)>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            list.Add((reader.GetString(0), reader.GetString(1)));
        return list;
    }

    public async Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(
        string remoteIp, int? remotePort, DateTimeOffset from, DateTimeOffset to)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT agent_id, computer_name, timestamp_utc, local_address, local_port, remote_address, remote_port,
                   process_id, process_name, process_path, process_command_line, service_names
            FROM network_connections
            WHERE remote_address=$remote
              AND timestamp_utc BETWEEN $from AND $to
              AND ($port IS NULL OR remote_port=$port)
            ORDER BY timestamp_utc DESC
            LIMIT 200;
            """;
        cmd.Parameters.AddWithValue("$remote", remoteIp);
        cmd.Parameters.AddWithValue("$from", from.ToString("O"));
        cmd.Parameters.AddWithValue("$to", to.ToString("O"));
        cmd.Parameters.AddWithValue("$port", (object?)remotePort ?? DBNull.Value);
        var list = new List<NetworkConnectionRecord>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new NetworkConnectionRecord
            {
                AgentId = reader.GetString(0),
                ComputerName = reader.GetString(1),
                TimestampUtc = DateTimeOffset.Parse(reader.GetString(2)),
                LocalAddress = reader.IsDBNull(3) ? "" : reader.GetString(3),
                LocalPort = reader.IsDBNull(4) ? 0 : reader.GetInt32(4),
                RemoteAddress = reader.IsDBNull(5) ? "" : reader.GetString(5),
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

    private static Incident ReadIncident(SqliteDataReader reader)
    {
        var i = new Incident
        {
            IncidentId = reader.GetString(0),
            FirstSeenUtc = DateTimeOffset.Parse(reader.GetString(1)),
            LastSeenUtc = DateTimeOffset.Parse(reader.GetString(2)),
            Severity = (Severity)reader.GetInt32(3),
            Title = reader.IsDBNull(4) ? "" : reader.GetString(4),
            Description = reader.IsDBNull(5) ? "" : reader.GetString(5),
            CorrelationKey = reader.IsDBNull(6) ? "" : reader.GetString(6),
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
            FailedLogonCount = reader.IsDBNull(23) ? 0 : reader.GetInt32(23),
            SuccessfulLogonCount = reader.IsDBNull(24) ? 0 : reader.GetInt32(24),
            PrivilegedLogon = !reader.IsDBNull(25) && reader.GetInt32(25) == 1,
            Status = reader.IsDBNull(27) ? "Open" : reader.GetString(27)
        };
        return i;
    }

    public async Task AppendAuditAsync(string actor, string action, string? target, string result, string? detailJson, string? sourceIp)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO audit_log(timestamp_utc, actor, action, target, result, detail_json, source_ip)
                VALUES ($ts, $actor, $action, $target, $result, $detail, $ip);
                """;
            cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$actor", actor);
            cmd.Parameters.AddWithValue("$action", action);
            cmd.Parameters.AddWithValue("$target", (object?)target ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$result", result);
            cmd.Parameters.AddWithValue("$detail", (object?)detailJson ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ip", (object?)sourceIp ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AuditLogEntry>> ListAuditAsync(int take)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT id, timestamp_utc, actor, action, target, result, detail_json, source_ip
            FROM audit_log ORDER BY id DESC LIMIT $n;
            """;
        cmd.Parameters.AddWithValue("$n", Math.Clamp(take, 1, 1000));
        var list = new List<AuditLogEntry>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new AuditLogEntry
            {
                Id = reader.GetInt64(0),
                TimestampUtc = DateTimeOffset.Parse(reader.GetString(1)),
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

    public async Task<AgentPolicy> GetActivePolicyAsync(string? agentId = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM agent_policies WHERE policy_id='default' LIMIT 1;";
        var o = await cmd.ExecuteScalarAsync();
        if (o is string json)
        {
            var p = JsonSerializer.Deserialize<AgentPolicy>(json, JsonOptions);
            if (p is not null) return p;
        }

        return new AgentPolicy { PolicyId = "default", PolicyVersion = 1, Mode = "Ids", DetectOnly = true };
    }

    public async Task UpsertPolicyAsync(AgentPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(policy.PolicyId))
            policy.PolicyId = "default";
        if (policy.PolicyVersion < 1)
            policy.PolicyVersion = 1;

        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO agent_policies(policy_id, version, json, updated_utc)
                VALUES ($id, $v, $j, $t)
                ON CONFLICT(policy_id) DO UPDATE SET version=excluded.version, json=excluded.json, updated_utc=excluded.updated_utc;
                """;
            cmd.Parameters.AddWithValue("$id", policy.PolicyId);
            cmd.Parameters.AddWithValue("$v", policy.PolicyVersion);
            cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(policy, JsonOptions));
            cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string?> IssueAgentApiKeyAsync(string agentId, bool rotate)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            if (!rotate)
            {
                await using var check = conn.CreateCommand();
                check.CommandText = "SELECT agent_api_key_hash FROM agents WHERE agent_id=$id LIMIT 1;";
                check.Parameters.AddWithValue("$id", agentId);
                var existing = await check.ExecuteScalarAsync();
                if (existing is string h && !string.IsNullOrWhiteSpace(h))
                    return null; // keep existing — caller may already have key
            }

            var plain = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            var hash = NTShield.Server.Security.SecretBootstrapper.HashApiKey(plain);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                UPDATE agents SET agent_api_key_hash=$h WHERE agent_id=$id;
                INSERT INTO agents(agent_id, computer_name, last_seen_utc, status, agent_api_key_hash)
                SELECT $id, $id, $ts, 'Registered', $h
                WHERE NOT EXISTS (SELECT 1 FROM agents WHERE agent_id=$id);
                """;
            // SQLite: two statements — first update, then insert if missing
            cmd.CommandText = "UPDATE agents SET agent_api_key_hash=$h WHERE agent_id=$id;";
            cmd.Parameters.AddWithValue("$h", hash);
            cmd.Parameters.AddWithValue("$id", agentId);
            var n = await cmd.ExecuteNonQueryAsync();
            if (n == 0)
            {
                await using var ins = conn.CreateCommand();
                ins.CommandText =
                    "INSERT INTO agents(agent_id, computer_name, last_seen_utc, status, agent_api_key_hash) VALUES ($id, $cn, $ts, 'Registered', $h);";
                ins.Parameters.AddWithValue("$id", agentId);
                ins.Parameters.AddWithValue("$cn", agentId);
                ins.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
                ins.Parameters.AddWithValue("$h", hash);
                await ins.ExecuteNonQueryAsync();
            }

            return plain;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SetAgentApiKeyHashAsync(string agentId, string keyHash)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE agents SET agent_api_key_hash=$h WHERE agent_id=$id;";
            cmd.Parameters.AddWithValue("$h", keyHash);
            cmd.Parameters.AddWithValue("$id", agentId);
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string?> FindAgentIdByApiKeyHashAsync(string keyHash)
    {
        if (string.IsNullOrWhiteSpace(keyHash)) return null;
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT agent_id FROM agents WHERE agent_api_key_hash=$h LIMIT 1;";
        cmd.Parameters.AddWithValue("$h", keyHash);
        var o = await cmd.ExecuteScalarAsync();
        return o as string;
    }

    public async Task UpdateAgentIntegrityAsync(string agentId, string? binarySha256, bool? isSigned, int? policyVersion)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                UPDATE agents SET
                    binary_sha256=COALESCE($sha, binary_sha256),
                    is_binary_signed=COALESCE($sig, is_binary_signed),
                    policy_version=COALESCE($pv, policy_version)
                WHERE agent_id=$id;
                """;
            cmd.Parameters.AddWithValue("$id", agentId);
            cmd.Parameters.AddWithValue("$sha", (object?)binarySha256 ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sig", isSigned.HasValue ? (isSigned.Value ? 1 : 0) : DBNull.Value);
            cmd.Parameters.AddWithValue("$pv", policyVersion.HasValue ? policyVersion.Value : DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAgentMetricsAsync(AgentHeartbeat hb)
    {
        if (string.IsNullOrWhiteSpace(hb.AgentId)) return;
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO agent_metrics(agent_id, timestamp_utc, cpu, mem_pct, disk_pct, net_rx, net_tx, io_r, io_w, load1, queue_depth, working_set, status)
                VALUES ($id, $ts, $cpu, $mem, $disk, $nrx, $ntx, $ior, $iow, $load, $q, $ws, $st);
                """;
            cmd.Parameters.AddWithValue("$id", hb.AgentId);
            cmd.Parameters.AddWithValue("$ts", (hb.TimestampUtc == default ? DateTimeOffset.UtcNow : hb.TimestampUtc).ToString("O"));
            cmd.Parameters.AddWithValue("$cpu", hb.CpuPercentEstimate.HasValue ? hb.CpuPercentEstimate.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$mem", hb.MemUsedPercent.HasValue ? hb.MemUsedPercent.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$disk", hb.DiskUsedPercent.HasValue ? hb.DiskUsedPercent.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$nrx", hb.NetworkRxBytesPerSec.HasValue ? hb.NetworkRxBytesPerSec.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$ntx", hb.NetworkTxBytesPerSec.HasValue ? hb.NetworkTxBytesPerSec.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$ior", hb.DiskReadBytesPerSec.HasValue ? hb.DiskReadBytesPerSec.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$iow", hb.DiskWriteBytesPerSec.HasValue ? hb.DiskWriteBytesPerSec.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$load", hb.LoadAverage1.HasValue ? hb.LoadAverage1.Value : DBNull.Value);
            cmd.Parameters.AddWithValue("$q", hb.LocalQueueDepth);
            cmd.Parameters.AddWithValue("$ws", hb.WorkingSetBytes);
            cmd.Parameters.AddWithValue("$st", (object?)hb.Status ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();

            // Prune: keep last ~500 samples per agent
            await using var prune = conn.CreateCommand();
            prune.CommandText =
                """
                DELETE FROM agent_metrics WHERE agent_id=$id AND id NOT IN (
                  SELECT id FROM agent_metrics WHERE agent_id=$id ORDER BY id DESC LIMIT 500
                );
                """;
            prune.Parameters.AddWithValue("$id", hb.AgentId);
            await prune.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT timestamp_utc, cpu, mem_pct, disk_pct, net_rx, net_tx, io_r, io_w, load1, queue_depth, working_set, status
            FROM agent_metrics WHERE agent_id=$id ORDER BY id DESC LIMIT $n;
            """;
        cmd.Parameters.AddWithValue("$id", agentId);
        cmd.Parameters.AddWithValue("$n", Math.Clamp(take, 1, 500));
        var list = new List<AgentMetricsSample>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new AgentMetricsSample
            {
                TimestampUtc = DateTimeOffset.Parse(reader.GetString(0)),
                CpuPercent = reader.IsDBNull(1) ? null : reader.GetDouble(1),
                MemUsedPercent = reader.IsDBNull(2) ? null : reader.GetDouble(2),
                DiskUsedPercent = reader.IsDBNull(3) ? null : reader.GetDouble(3),
                NetworkRxBytesPerSec = reader.IsDBNull(4) ? null : reader.GetDouble(4),
                NetworkTxBytesPerSec = reader.IsDBNull(5) ? null : reader.GetDouble(5),
                DiskReadBytesPerSec = reader.IsDBNull(6) ? null : reader.GetDouble(6),
                DiskWriteBytesPerSec = reader.IsDBNull(7) ? null : reader.GetDouble(7),
                LoadAverage1 = reader.IsDBNull(8) ? null : reader.GetDouble(8),
                QueueDepth = reader.IsDBNull(9) ? 0 : reader.GetInt64(9),
                WorkingSetBytes = reader.IsDBNull(10) ? 0 : reader.GetInt64(10),
                Status = reader.IsDBNull(11) ? null : reader.GetString(11)
            });
        }

        return list;
    }

    public async Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60, string? tenantId = null)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT agent_id, computer_name, agent_version, os_version, last_seen_utc, status, queue_depth,
                   host_ip, central_url, platform, last_error, binary_sha256, is_binary_signed, policy_version,
                   db_size_bytes, working_set_bytes, clock_skew_seconds,
                   cpu_percent, mem_used_percent, disk_used_percent, net_rx_bps, net_tx_bps,
                   disk_read_bps, disk_write_bps, load1, host_mem_used, host_mem_total, metrics_summary
            FROM agents a
            WHERE agent_id=$id
              AND ($tenant IS NULL OR EXISTS (
                    SELECT 1 FROM tenant_agent_assignments taa
                    WHERE taa.agent_id=a.agent_id AND taa.tenant_id=$tenant))
            LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$id", agentId);
        cmd.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
        var item = ReadInventoryRow(reader, DateTimeOffset.UtcNow);
        await reader.DisposeAsync();
        item.MetricsHistory = (await ListAgentMetricsAsync(agentId, metricsTake)).ToList();
        return item;
    }

    public async Task<IReadOnlyList<CustomerTenant>> ListTenantsAsync()
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT tenant_id, name, legal_name, contact_name, contact_email, plan, status, notes, created_at_utc, updated_at_utc " +
            "FROM customer_tenants ORDER BY name COLLATE NOCASE, tenant_id;";
        var list = new List<CustomerTenant>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) list.Add(ReadTenant(reader));
        return list;
    }

    public async Task<CustomerTenant?> GetTenantAsync(string tenantId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT tenant_id, name, legal_name, contact_name, contact_email, plan, status, notes, created_at_utc, updated_at_utc " +
            "FROM customer_tenants WHERE tenant_id=$tenant LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        await using var reader = await cmd.ExecuteReaderAsync();
        return await reader.ReadAsync() ? ReadTenant(reader) : null;
    }

    public async Task UpsertTenantAsync(CustomerTenant tenant)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO customer_tenants(
                    tenant_id, name, legal_name, contact_name, contact_email, plan, status, notes,
                    created_at_utc, updated_at_utc)
                VALUES ($tenant, $name, $legal, $contact, $email, $plan, $status, $notes, $created, $updated)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    name=excluded.name,
                    legal_name=excluded.legal_name,
                    contact_name=excluded.contact_name,
                    contact_email=excluded.contact_email,
                    plan=excluded.plan,
                    status=excluded.status,
                    notes=excluded.notes,
                    updated_at_utc=excluded.updated_at_utc;
                """;
            cmd.Parameters.AddWithValue("$tenant", tenant.TenantId);
            cmd.Parameters.AddWithValue("$name", tenant.Name);
            cmd.Parameters.AddWithValue("$legal", (object?)tenant.LegalName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$contact", (object?)tenant.ContactName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$email", (object?)tenant.ContactEmail ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$plan", tenant.Plan);
            cmd.Parameters.AddWithValue("$status", tenant.Status);
            cmd.Parameters.AddWithValue("$notes", (object?)tenant.Notes ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$created", tenant.CreatedAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$updated", tenant.UpdatedAtUtc.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TenantAgentAssignment>> ListAgentAssignmentsAsync()
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT tenant_id, agent_id, assigned_at_utc FROM tenant_agent_assignments ORDER BY tenant_id, agent_id;";
        var list = new List<TenantAgentAssignment>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new TenantAgentAssignment
            {
                TenantId = reader.GetString(0),
                AgentId = reader.GetString(1),
                AssignedAtUtc = DateTimeOffset.Parse(reader.GetString(2))
            });
        }
        return list;
    }

    public async Task AssignAgentToTenantAsync(string tenantId, string agentId)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO tenant_agent_assignments(agent_id, tenant_id, assigned_at_utc)
                SELECT $agent, $tenant, $assigned
                WHERE EXISTS (SELECT 1 FROM agents WHERE agent_id=$agent)
                  AND EXISTS (SELECT 1 FROM customer_tenants WHERE tenant_id=$tenant)
                ON CONFLICT(agent_id) DO UPDATE SET
                    tenant_id=excluded.tenant_id,
                    assigned_at_utc=excluded.assigned_at_utc;
                """;
            cmd.Parameters.AddWithValue("$agent", agentId);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$assigned", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SecurityReportRecord>> ListReportsAsync(string tenantId, int take)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT payload FROM security_reports WHERE tenant_id=$tenant ORDER BY generated_at_utc DESC LIMIT $take;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        cmd.Parameters.AddWithValue("$take", take);
        var list = new List<SecurityReportRecord>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var report = JsonSerializer.Deserialize<SecurityReportRecord>(reader.GetString(0), JsonOptions);
            if (report is not null) list.Add(report);
        }
        return list;
    }

    public async Task<SecurityReportRecord?> GetReportAsync(string tenantId, string reportId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM security_reports WHERE tenant_id=$tenant AND report_id=$id LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        cmd.Parameters.AddWithValue("$id", reportId);
        var payload = await cmd.ExecuteScalarAsync();
        return payload is string json ? JsonSerializer.Deserialize<SecurityReportRecord>(json, JsonOptions) : null;
    }

    public async Task UpsertReportAsync(SecurityReportRecord report)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO security_reports(
                    report_id, tenant_id, title, period_start_utc, period_end_utc, generated_at_utc, payload)
                VALUES ($id, $tenant, $title, $start, $end, $generated, $payload)
                ON CONFLICT(report_id) DO UPDATE SET
                    title=excluded.title,
                    period_start_utc=excluded.period_start_utc,
                    period_end_utc=excluded.period_end_utc,
                    generated_at_utc=excluded.generated_at_utc,
                    payload=excluded.payload
                WHERE security_reports.tenant_id=excluded.tenant_id;
                """;
            cmd.Parameters.AddWithValue("$id", report.ReportId);
            cmd.Parameters.AddWithValue("$tenant", report.TenantId);
            cmd.Parameters.AddWithValue("$title", report.Title);
            cmd.Parameters.AddWithValue("$start", report.PeriodStartUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$end", report.PeriodEndUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$generated", report.GeneratedAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(report, JsonOptions));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status, description, tags_json, metadata_json, created_at_utc, updated_at_utc " +
            "FROM tenant_assets WHERE tenant_id=$tenant ORDER BY name COLLATE NOCASE, asset_id;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        var list = new List<TenantAsset>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            list.Add(ReadAsset(reader));
        return list;
    }

    public async Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status, description, tags_json, metadata_json, created_at_utc, updated_at_utc " +
            "FROM tenant_assets WHERE tenant_id=$tenant AND asset_id=$id LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        cmd.Parameters.AddWithValue("$id", assetId);
        await using var reader = await cmd.ExecuteReaderAsync();
        return await reader.ReadAsync() ? ReadAsset(reader) : null;
    }

    public async Task UpsertAssetAsync(string tenantId, TenantAsset asset)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO tenant_assets(
                    asset_id, tenant_id, name, kind, hostname, address, environment, criticality, status,
                    description, tags_json, metadata_json, created_at_utc, updated_at_utc)
                VALUES ($id, $tenant, $name, $kind, $hostname, $address, $environment, $criticality, $status,
                    $description, $tags, $metadata, $created, $updated)
                ON CONFLICT(asset_id) DO UPDATE SET
                    name=excluded.name,
                    kind=excluded.kind,
                    hostname=excluded.hostname,
                    address=excluded.address,
                    environment=excluded.environment,
                    criticality=excluded.criticality,
                    status=excluded.status,
                    description=excluded.description,
                    tags_json=excluded.tags_json,
                    metadata_json=excluded.metadata_json,
                    updated_at_utc=excluded.updated_at_utc
                WHERE tenant_assets.tenant_id=excluded.tenant_id;
                """;
            cmd.Parameters.AddWithValue("$id", asset.AssetId);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$name", asset.Name);
            cmd.Parameters.AddWithValue("$kind", asset.Kind);
            cmd.Parameters.AddWithValue("$hostname", (object?)asset.Hostname ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$address", (object?)asset.Address ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$environment", asset.Environment);
            cmd.Parameters.AddWithValue("$criticality", asset.Criticality);
            cmd.Parameters.AddWithValue("$status", asset.Status);
            cmd.Parameters.AddWithValue("$description", (object?)asset.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(asset.Tags, JsonOptions));
            cmd.Parameters.AddWithValue("$metadata", JsonSerializer.Serialize(asset.Metadata, JsonOptions));
            cmd.Parameters.AddWithValue("$created", asset.CreatedAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$updated", asset.UpdatedAtUtc.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> DeleteAssetAsync(string tenantId, string assetId)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM tenant_assets WHERE tenant_id=$tenant AND asset_id=$id;";
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$id", assetId);
            return await cmd.ExecuteNonQueryAsync() > 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT payload FROM topology_documents WHERE tenant_id=$tenant ORDER BY updated_at_utc DESC, topology_id;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
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
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM topology_documents WHERE tenant_id=$tenant AND topology_id=$id LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        cmd.Parameters.AddWithValue("$id", topologyId);
        var payload = await cmd.ExecuteScalarAsync();
        return payload is string json ? JsonSerializer.Deserialize<TopologyDocument>(json, JsonOptions) : null;
    }

    public async Task UpsertTopologyAsync(string tenantId, TopologyDocument topology)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO topology_documents(topology_id, tenant_id, name, description, version, payload, created_at_utc, updated_at_utc)
                VALUES ($id, $tenant, $name, $description, $version, $payload, $created, $updated)
                ON CONFLICT(topology_id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    version=excluded.version,
                    payload=excluded.payload,
                    updated_at_utc=excluded.updated_at_utc
                WHERE topology_documents.tenant_id=excluded.tenant_id;
                """;
            cmd.Parameters.AddWithValue("$id", topology.TopologyId);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$name", topology.Name);
            cmd.Parameters.AddWithValue("$description", (object?)topology.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$version", topology.Version);
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(topology, JsonOptions));
            cmd.Parameters.AddWithValue("$created", topology.CreatedAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$updated", topology.UpdatedAtUtc.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> DeleteTopologyAsync(string tenantId, string topologyId)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM topology_documents WHERE tenant_id=$tenant AND topology_id=$id;";
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$id", topologyId);
            return await cmd.ExecuteNonQueryAsync() > 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT payload FROM detection_workflows WHERE tenant_id=$tenant ORDER BY updated_at_utc DESC, workflow_id;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
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
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT payload FROM detection_workflows WHERE tenant_id=$tenant AND workflow_id=$id LIMIT 1;";
        cmd.Parameters.AddWithValue("$tenant", tenantId);
        cmd.Parameters.AddWithValue("$id", workflowId);
        var payload = await cmd.ExecuteScalarAsync();
        return payload is string json ? JsonSerializer.Deserialize<DetectionWorkflow>(json, JsonOptions) : null;
    }

    public async Task UpsertWorkflowAsync(string tenantId, DetectionWorkflow workflow)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO detection_workflows(workflow_id, tenant_id, name, topology_id, enabled, version, payload, created_at_utc, updated_at_utc)
                VALUES ($id, $tenant, $name, $topology, $enabled, $version, $payload, $created, $updated)
                ON CONFLICT(workflow_id) DO UPDATE SET
                    name=excluded.name,
                    topology_id=excluded.topology_id,
                    enabled=excluded.enabled,
                    version=excluded.version,
                    payload=excluded.payload,
                    updated_at_utc=excluded.updated_at_utc
                WHERE detection_workflows.tenant_id=excluded.tenant_id;
                """;
            cmd.Parameters.AddWithValue("$id", workflow.WorkflowId);
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$name", workflow.Name);
            cmd.Parameters.AddWithValue("$topology", (object?)workflow.TopologyId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$enabled", workflow.Enabled ? 1 : 0);
            cmd.Parameters.AddWithValue("$version", workflow.Version);
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(workflow, JsonOptions));
            cmd.Parameters.AddWithValue("$created", workflow.CreatedAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$updated", workflow.UpdatedAtUtc.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId)
    {
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM detection_workflows WHERE tenant_id=$tenant AND workflow_id=$id;";
            cmd.Parameters.AddWithValue("$tenant", tenantId);
            cmd.Parameters.AddWithValue("$id", workflowId);
            return await cmd.ExecuteNonQueryAsync() > 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static CustomerTenant ReadTenant(SqliteDataReader reader) => new()
    {
        TenantId = reader.GetString(0),
        Name = reader.GetString(1),
        LegalName = reader.IsDBNull(2) ? null : reader.GetString(2),
        ContactName = reader.IsDBNull(3) ? null : reader.GetString(3),
        ContactEmail = reader.IsDBNull(4) ? null : reader.GetString(4),
        Plan = reader.GetString(5),
        Status = reader.GetString(6),
        Notes = reader.IsDBNull(7) ? null : reader.GetString(7),
        CreatedAtUtc = DateTimeOffset.Parse(reader.GetString(8)),
        UpdatedAtUtc = DateTimeOffset.Parse(reader.GetString(9))
    };

    private static TenantAsset ReadAsset(SqliteDataReader reader)
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
            CreatedAtUtc = DateTimeOffset.Parse(reader.GetString(12)),
            UpdatedAtUtc = DateTimeOffset.Parse(reader.GetString(13))
        };
    }
}
