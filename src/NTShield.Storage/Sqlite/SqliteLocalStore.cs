using System.Text.Json;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using NTShield.Storage.Security;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Storage.Sqlite;

public sealed class SqliteLocalStore : ILocalStore
{
    private readonly StorageOptions _storageOptions;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<SqliteLocalStore> _logger;
    private readonly string _dbPath;
    // Single shared SqliteConnection is NOT thread-safe — serialize all DB work on one gate.
    // (Previously 4 concurrent slots caused hangs/starvation under load.)
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection? _connection;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public SqliteLocalStore(
        IOptions<StorageOptions> storageOptions,
        IOptions<AgentOptions> agentOptions,
        ILogger<SqliteLocalStore> logger)
    {
        _storageOptions = storageOptions.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
        Directory.CreateDirectory(_agentOptions.DataDirectory);
        _dbPath = Path.Combine(_agentOptions.DataDirectory, _storageOptions.DatabaseFileName);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = _dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Shared
            }.ToString());
            await _connection.OpenAsync(cancellationToken);
            await SchemaMigrator.MigrateAsync(_connection, cancellationToken);
            _logger.LogInformation("SQLite local store ready at {Path}", _dbPath);
        }
        finally
        {
            _gate.Release();
        }
    }

    private SqliteConnection Conn =>
        _connection ?? throw new InvalidOperationException("Local store not initialized.");

    public async Task SaveSecurityEventsAsync(IEnumerable<SecurityEventRecord> events, CancellationToken cancellationToken)
    {
        var list = events.ToList();
        if (list.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var e in list)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT INTO security_events(
                        timestamp_utc, computer_name, agent_id, event_id, channel, provider_name,
                        username, domain, source_ip, source_port, destination_ip, destination_port,
                        logon_type, authentication_package, process_id, process_path, logon_process,
                        status, substatus, target_user_name, target_domain_name, workstation_name,
                        service_name, task_name, raw_xml, event_record_id, collected_at_utc)
                    VALUES (
                        $timestamp_utc, $computer_name, $agent_id, $event_id, $channel, $provider_name,
                        $username, $domain, $source_ip, $source_port, $destination_ip, $destination_port,
                        $logon_type, $authentication_package, $process_id, $process_path, $logon_process,
                        $status, $substatus, $target_user_name, $target_domain_name, $workstation_name,
                        $service_name, $task_name, $raw_xml, $event_record_id, $collected_at_utc);
                    """;
                cmd.Parameters.AddWithValue("$timestamp_utc", e.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$computer_name", e.ComputerName);
                cmd.Parameters.AddWithValue("$agent_id", e.AgentId);
                cmd.Parameters.AddWithValue("$event_id", e.EventId);
                cmd.Parameters.AddWithValue("$channel", e.Channel);
                cmd.Parameters.AddWithValue("$provider_name", (object?)e.ProviderName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$username", (object?)e.Username ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$domain", (object?)e.Domain ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$source_ip", (object?)e.SourceIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$source_port", (object?)e.SourcePort ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$destination_ip", (object?)e.DestinationIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$destination_port", (object?)e.DestinationPort ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$logon_type", (object?)e.LogonType ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$authentication_package", (object?)e.AuthenticationPackage ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_id", (object?)e.ProcessId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_path", (object?)e.ProcessPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$logon_process", (object?)e.LogonProcess ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$status", (object?)e.Status ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$substatus", (object?)e.SubStatus ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$target_user_name", (object?)e.TargetUserName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$target_domain_name", (object?)e.TargetDomainName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$workstation_name", (object?)e.WorkstationName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$service_name", (object?)e.ServiceName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$task_name", (object?)e.TaskName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$raw_xml", e.RawXml);
                cmd.Parameters.AddWithValue("$event_record_id", e.EventRecordId);
                cmd.Parameters.AddWithValue("$collected_at_utc", e.CollectedAtUtc.ToString("O"));
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.SecurityEvent, JsonSerializer.Serialize(list, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveNetworkConnectionsAsync(IEnumerable<NetworkConnectionRecord> connections, CancellationToken cancellationToken)
    {
        var list = connections.ToList();
        if (list.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var c in list)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT INTO network_connections(
                        timestamp_utc, computer_name, agent_id, protocol, local_address, local_port,
                        remote_address, remote_port, tcp_state, process_id, process_name, process_path,
                        process_command_line, process_owner, parent_process_id, digital_signature_status,
                        signer_name, executable_sha256, service_names, service_display_names,
                        is_new, is_closed, connection_key)
                    VALUES (
                        $timestamp_utc, $computer_name, $agent_id, $protocol, $local_address, $local_port,
                        $remote_address, $remote_port, $tcp_state, $process_id, $process_name, $process_path,
                        $process_command_line, $process_owner, $parent_process_id, $digital_signature_status,
                        $signer_name, $executable_sha256, $service_names, $service_display_names,
                        $is_new, $is_closed, $connection_key);
                    """;
                cmd.Parameters.AddWithValue("$timestamp_utc", c.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$computer_name", c.ComputerName);
                cmd.Parameters.AddWithValue("$agent_id", c.AgentId);
                cmd.Parameters.AddWithValue("$protocol", c.Protocol);
                cmd.Parameters.AddWithValue("$local_address", c.LocalAddress);
                cmd.Parameters.AddWithValue("$local_port", c.LocalPort);
                cmd.Parameters.AddWithValue("$remote_address", c.RemoteAddress);
                cmd.Parameters.AddWithValue("$remote_port", c.RemotePort);
                cmd.Parameters.AddWithValue("$tcp_state", (object?)c.TcpState ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_id", c.ProcessId);
                cmd.Parameters.AddWithValue("$process_name", (object?)c.ProcessName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_path", (object?)c.ProcessPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_command_line", (object?)c.ProcessCommandLine ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_owner", (object?)c.ProcessOwner ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$parent_process_id", (object?)c.ParentProcessId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$digital_signature_status", (object?)c.DigitalSignatureStatus ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$signer_name", (object?)c.SignerName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$executable_sha256", (object?)c.ExecutableSha256 ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$service_names", (object?)c.ServiceNames ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$service_display_names", (object?)c.ServiceDisplayNames ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$is_new", c.IsNew ? 1 : 0);
                cmd.Parameters.AddWithValue("$is_closed", c.IsClosed ? 1 : 0);
                cmd.Parameters.AddWithValue("$connection_key", c.ConnectionKey);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.NetworkConnection, JsonSerializer.Serialize(list, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveProcessesAsync(IEnumerable<ProcessRecord> processes, CancellationToken cancellationToken)
    {
        var list = processes.ToList();
        if (list.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var p in list)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT INTO processes(
                        timestamp_utc, computer_name, agent_id, process_id, parent_process_id, process_name,
                        full_path, command_line, user_name, start_time_utc, executable_sha256, signer_name,
                        digital_signature_status, integrity_level, listening_ports, outbound_destinations, service_names)
                    VALUES (
                        $timestamp_utc, $computer_name, $agent_id, $process_id, $parent_process_id, $process_name,
                        $full_path, $command_line, $user_name, $start_time_utc, $executable_sha256, $signer_name,
                        $digital_signature_status, $integrity_level, $listening_ports, $outbound_destinations, $service_names);
                    """;
                cmd.Parameters.AddWithValue("$timestamp_utc", p.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$computer_name", p.ComputerName);
                cmd.Parameters.AddWithValue("$agent_id", p.AgentId);
                cmd.Parameters.AddWithValue("$process_id", p.ProcessId);
                cmd.Parameters.AddWithValue("$parent_process_id", (object?)p.ParentProcessId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$process_name", p.ProcessName);
                cmd.Parameters.AddWithValue("$full_path", (object?)p.FullPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$command_line", (object?)p.CommandLine ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$user_name", (object?)p.User ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$start_time_utc", (object?)p.StartTimeUtc?.ToString("O") ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$executable_sha256", (object?)p.ExecutableSha256 ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$signer_name", (object?)p.SignerName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$digital_signature_status", (object?)p.DigitalSignatureStatus ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$integrity_level", (object?)p.IntegrityLevel ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$listening_ports", (object?)p.ListeningPorts ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$outbound_destinations", (object?)p.OutboundDestinations ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$service_names", (object?)p.ServiceNames ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.ProcessSnapshot, JsonSerializer.Serialize(list, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveServicesAsync(IEnumerable<ServiceRecord> services, CancellationToken cancellationToken)
    {
        var list = services.ToList();
        if (list.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var s in list)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT INTO services(
                        timestamp_utc, computer_name, agent_id, process_id, service_name, display_name,
                        start_account, image_path, state, start_mode)
                    VALUES (
                        $timestamp_utc, $computer_name, $agent_id, $process_id, $service_name, $display_name,
                        $start_account, $image_path, $state, $start_mode);
                    """;
                cmd.Parameters.AddWithValue("$timestamp_utc", s.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$computer_name", s.ComputerName);
                cmd.Parameters.AddWithValue("$agent_id", s.AgentId);
                cmd.Parameters.AddWithValue("$process_id", s.ProcessId);
                cmd.Parameters.AddWithValue("$service_name", s.ServiceName);
                cmd.Parameters.AddWithValue("$display_name", (object?)s.DisplayName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$start_account", (object?)s.StartAccount ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$image_path", (object?)s.ImagePath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$state", (object?)s.State ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$start_mode", (object?)s.StartMode ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.ServiceMap, JsonSerializer.Serialize(list, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveScheduledTasksAsync(IEnumerable<ScheduledTaskRecord> tasks, CancellationToken cancellationToken)
    {
        var list = tasks.ToList();
        if (list.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var t in list)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    INSERT INTO scheduled_tasks(
                        timestamp_utc, computer_name, agent_id, task_path, task_name, command, arguments,
                        run_as_account, triggers, enabled, last_run_result, last_run_time_utc, change_type)
                    VALUES (
                        $timestamp_utc, $computer_name, $agent_id, $task_path, $task_name, $command, $arguments,
                        $run_as_account, $triggers, $enabled, $last_run_result, $last_run_time_utc, $change_type);
                    """;
                cmd.Parameters.AddWithValue("$timestamp_utc", t.TimestampUtc.ToString("O"));
                cmd.Parameters.AddWithValue("$computer_name", t.ComputerName);
                cmd.Parameters.AddWithValue("$agent_id", t.AgentId);
                cmd.Parameters.AddWithValue("$task_path", t.TaskPath);
                cmd.Parameters.AddWithValue("$task_name", t.TaskName);
                cmd.Parameters.AddWithValue("$command", (object?)t.Command ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$arguments", (object?)t.Arguments ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$run_as_account", (object?)t.RunAsAccount ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$triggers", (object?)t.Triggers ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$enabled", t.Enabled ? 1 : 0);
                cmd.Parameters.AddWithValue("$last_run_result", (object?)t.LastRunResult ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$last_run_time_utc", (object?)t.LastRunTimeUtc?.ToString("O") ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$change_type", (object?)t.ChangeType ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.ScheduledTask, JsonSerializer.Serialize(list, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAlertAsync(DetectionAlert alert, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO detection_alerts(
                    alert_id, timestamp_utc, computer_name, agent_id, rule_id, rule_name, severity,
                    title, description, source_ip, destination_ip, username, event_count,
                    distinct_user_count, distinct_destination_count, evidence_json, suppressed, cooldown_until_utc)
                VALUES (
                    $alert_id, $timestamp_utc, $computer_name, $agent_id, $rule_id, $rule_name, $severity,
                    $title, $description, $source_ip, $destination_ip, $username, $event_count,
                    $distinct_user_count, $distinct_destination_count, $evidence_json, $suppressed, $cooldown_until_utc);
                """;
            cmd.Parameters.AddWithValue("$alert_id", alert.AlertId);
            cmd.Parameters.AddWithValue("$timestamp_utc", alert.TimestampUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$computer_name", alert.ComputerName);
            cmd.Parameters.AddWithValue("$agent_id", alert.AgentId);
            cmd.Parameters.AddWithValue("$rule_id", alert.RuleId);
            cmd.Parameters.AddWithValue("$rule_name", alert.RuleName);
            cmd.Parameters.AddWithValue("$severity", (int)alert.Severity);
            cmd.Parameters.AddWithValue("$title", alert.Title);
            cmd.Parameters.AddWithValue("$description", alert.Description);
            cmd.Parameters.AddWithValue("$source_ip", (object?)alert.SourceIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$destination_ip", (object?)alert.DestinationIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$username", (object?)alert.Username ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$event_count", alert.EventCount);
            cmd.Parameters.AddWithValue("$distinct_user_count", alert.DistinctUserCount);
            cmd.Parameters.AddWithValue("$distinct_destination_count", alert.DistinctDestinationCount);
            cmd.Parameters.AddWithValue("$evidence_json", alert.EvidenceJson);
            cmd.Parameters.AddWithValue("$suppressed", alert.Suppressed ? 1 : 0);
            cmd.Parameters.AddWithValue("$cooldown_until_utc", (object?)alert.CooldownUntilUtc?.ToString("O") ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
            await EnqueueOutboundUnsafeAsync(QueueItemType.DetectionAlert, JsonSerializer.Serialize(alert, JsonOptions), cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveResponseActionAsync(ResponseActionRecord action, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO response_actions(
                    action_id, request_id, requester, timestamp_utc, computer_name, agent_id, alert_id, incident_id,
                    action_type, status, reason, before_state, result, rollback_command, details, error,
                    approved, approval_id, audit_log)
                VALUES (
                    $action_id, $request_id, $requester, $timestamp_utc, $computer_name, $agent_id, $alert_id, $incident_id,
                    $action_type, $status, $reason, $before_state, $result, $rollback_command, $details, $error,
                    $approved, $approval_id, $audit_log);
                """;
            cmd.Parameters.AddWithValue("$action_id", action.ActionId);
            cmd.Parameters.AddWithValue("$request_id", action.RequestId);
            cmd.Parameters.AddWithValue("$requester", action.Requester);
            cmd.Parameters.AddWithValue("$timestamp_utc", action.TimestampUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$computer_name", action.ComputerName);
            cmd.Parameters.AddWithValue("$agent_id", action.AgentId);
            cmd.Parameters.AddWithValue("$alert_id", action.AlertId);
            cmd.Parameters.AddWithValue("$incident_id", (object?)action.IncidentId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$action_type", action.ActionType);
            cmd.Parameters.AddWithValue("$status", action.Status);
            cmd.Parameters.AddWithValue("$reason", (object?)action.Reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$before_state", (object?)action.BeforeState ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$result", (object?)action.Result ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rollback_command", (object?)action.RollbackCommand ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$details", (object?)action.Details ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$error", (object?)action.Error ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$approved", action.Approved ? 1 : 0);
            cmd.Parameters.AddWithValue("$approval_id", (object?)action.ApprovalId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$audit_log", (object?)action.AuditLog ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SecurityEventRecord>> QuerySecurityEventsAsync(
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc,
        int? eventId = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                SELECT timestamp_utc, computer_name, agent_id, event_id, channel, provider_name,
                       username, domain, source_ip, source_port, destination_ip, destination_port,
                       logon_type, authentication_package, process_id, process_path, logon_process,
                       status, substatus, target_user_name, target_domain_name, workstation_name,
                       service_name, task_name, raw_xml, event_record_id, collected_at_utc, id
                FROM security_events
                WHERE timestamp_utc >= $from AND timestamp_utc <= $to
                """;
            if (eventId.HasValue)
            {
                cmd.CommandText += " AND event_id = $event_id";
                cmd.Parameters.AddWithValue("$event_id", eventId.Value);
            }

            cmd.CommandText += " ORDER BY timestamp_utc DESC LIMIT 5000;";
            cmd.Parameters.AddWithValue("$from", fromUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$to", toUtc.ToString("O"));

            var results = new List<SecurityEventRecord>();
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(new SecurityEventRecord
                {
                    TimestampUtc = DateTimeOffset.Parse(reader.GetString(0)),
                    ComputerName = reader.GetString(1),
                    AgentId = reader.GetString(2),
                    EventId = reader.GetInt32(3),
                    Channel = reader.GetString(4),
                    ProviderName = reader.IsDBNull(5) ? null : reader.GetString(5),
                    Username = reader.IsDBNull(6) ? null : reader.GetString(6),
                    Domain = reader.IsDBNull(7) ? null : reader.GetString(7),
                    SourceIp = reader.IsDBNull(8) ? null : reader.GetString(8),
                    SourcePort = reader.IsDBNull(9) ? null : reader.GetInt32(9),
                    DestinationIp = reader.IsDBNull(10) ? null : reader.GetString(10),
                    DestinationPort = reader.IsDBNull(11) ? null : reader.GetInt32(11),
                    LogonType = reader.IsDBNull(12) ? null : reader.GetInt32(12),
                    AuthenticationPackage = reader.IsDBNull(13) ? null : reader.GetString(13),
                    ProcessId = reader.IsDBNull(14) ? null : reader.GetInt32(14),
                    ProcessPath = reader.IsDBNull(15) ? null : reader.GetString(15),
                    LogonProcess = reader.IsDBNull(16) ? null : reader.GetString(16),
                    Status = reader.IsDBNull(17) ? null : reader.GetString(17),
                    SubStatus = reader.IsDBNull(18) ? null : reader.GetString(18),
                    TargetUserName = reader.IsDBNull(19) ? null : reader.GetString(19),
                    TargetDomainName = reader.IsDBNull(20) ? null : reader.GetString(20),
                    WorkstationName = reader.IsDBNull(21) ? null : reader.GetString(21),
                    ServiceName = reader.IsDBNull(22) ? null : reader.GetString(22),
                    TaskName = reader.IsDBNull(23) ? null : reader.GetString(23),
                    RawXml = reader.GetString(24),
                    EventRecordId = reader.GetInt64(25),
                    CollectedAtUtc = DateTimeOffset.Parse(reader.GetString(26)),
                    Id = reader.GetInt64(27)
                });
            }

            return results;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string?> GetStateAsync(string key, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT value FROM agent_state WHERE key = $key;";
            cmd.Parameters.AddWithValue("$key", key);
            var result = await cmd.ExecuteScalarAsync(cancellationToken);
            return result as string;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SetStateAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO agent_state(key, value, updated_at_utc)
                VALUES ($key, $value, $t)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at_utc = excluded.updated_at_utc;
                """;
            cmd.Parameters.AddWithValue("$key", key);
            cmd.Parameters.AddWithValue("$value", value);
            cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task EnqueueOutboundAsync(QueueItemType type, string payloadJson, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await EnqueueOutboundUnsafeAsync(type, payloadJson, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task EnqueueOutboundUnsafeAsync(QueueItemType type, string payloadJson, CancellationToken cancellationToken)
    {
        // Enforce offline queue limit (drop oldest pending if over cap).
        await using (var countCmd = Conn.CreateCommand())
        {
            countCmd.CommandText = "SELECT COUNT(1) FROM outbound_queue WHERE status = 'Pending';";
            var depth = Convert.ToInt64(await countCmd.ExecuteScalarAsync(cancellationToken));
            var limit = _storageOptions.OfflineQueueLimit > 0 ? _storageOptions.OfflineQueueLimit : 100_000;
            if (depth >= limit)
            {
                var drop = (int)Math.Min(1000, depth - limit + 1);
                await using var dropCmd = Conn.CreateCommand();
                dropCmd.CommandText =
                    """
                    DELETE FROM outbound_queue
                    WHERE id IN (
                      SELECT id FROM outbound_queue WHERE status = 'Pending' ORDER BY id ASC LIMIT $n
                    );
                    """;
                dropCmd.Parameters.AddWithValue("$n", drop);
                await dropCmd.ExecuteNonQueryAsync(cancellationToken);
                _logger.LogWarning("Offline queue at limit {Limit}; dropped {Drop} oldest items", limit, drop);
            }
        }

        await using var cmd = Conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO outbound_queue(item_type, payload_json, attempts, created_at_utc, status)
            VALUES ($type, $payload, 0, $t, 'Pending');
            """;
        cmd.Parameters.AddWithValue("$type", (int)type);
        cmd.Parameters.AddWithValue("$payload", payloadJson);
        cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<OutboundQueueItem>> DequeueOutboundBatchAsync(int batchSize, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                SELECT id, item_type, payload_json, attempts, created_at_utc
                FROM outbound_queue
                WHERE status = 'Pending'
                ORDER BY id ASC
                LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", batchSize);
            var list = new List<OutboundQueueItem>();
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new OutboundQueueItem
                {
                    Id = reader.GetInt64(0),
                    ItemType = (QueueItemType)reader.GetInt32(1),
                    PayloadJson = reader.GetString(2),
                    Attempts = reader.GetInt32(3),
                    CreatedAtUtc = DateTimeOffset.Parse(reader.GetString(4))
                });
            }

            return list;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkOutboundSentAsync(IEnumerable<long> ids, CancellationToken cancellationToken)
    {
        var idList = ids.ToList();
        if (idList.Count == 0) return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(cancellationToken);
            foreach (var id in idList)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText =
                    """
                    UPDATE outbound_queue
                    SET status = 'Sent', sent_at_utc = $t
                    WHERE id = $id;
                    """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await tx.CommitAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkOutboundFailedAsync(long id, string error, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                UPDATE outbound_queue
                SET attempts = attempts + 1, last_error = $error,
                    status = CASE WHEN attempts + 1 >= 20 THEN 'Dead' ELSE 'Pending' END
                WHERE id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$error", error);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<long> GetOutboundQueueDepthAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(1) FROM outbound_queue WHERE status = 'Pending';";
            var result = await cmd.ExecuteScalarAsync(cancellationToken);
            return Convert.ToInt64(result);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RunMaintenanceAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var cutoff = DateTimeOffset.UtcNow.AddDays(-_storageOptions.RetentionDays).ToString("O");
            foreach (var table in new[]
                     {
                         "security_events", "network_connections", "processes", "services",
                         "scheduled_tasks", "detection_alerts", "response_actions"
                     })
            {
                await using var cmd = Conn.CreateCommand();
                cmd.CommandText = $"DELETE FROM {table} WHERE timestamp_utc < $cutoff;";
                cmd.Parameters.AddWithValue("$cutoff", cutoff);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var cmd = Conn.CreateCommand())
            {
                cmd.CommandText = "DELETE FROM outbound_queue WHERE status = 'Sent' AND sent_at_utc < $cutoff;";
                cmd.Parameters.AddWithValue("$cutoff", cutoff);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }

            var size = await GetDatabaseSizeBytesUnsafeAsync();
            var maxBytes = Math.Max(64, _storageOptions.MaxDatabaseSizeMb) * 1024L * 1024L;
            if (size > maxBytes)
            {
                _logger.LogWarning("Database size {Size} exceeds max {Max}; running aggressive purge", size, maxBytes);
                // Keep only last 24h of high-volume tables (8GB DBs hang startup otherwise)
                var aggressiveCutoff = DateTimeOffset.UtcNow.AddHours(-24).ToString("O");
                foreach (var table in new[]
                         {
                             "security_events", "network_connections", "processes", "services",
                             "scheduled_tasks", "detection_alerts"
                         })
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await using var cmd = Conn.CreateCommand();
                    cmd.CommandText = $"DELETE FROM {table} WHERE timestamp_utc < $cutoff;";
                    cmd.Parameters.AddWithValue("$cutoff", aggressiveCutoff);
                    var n = await cmd.ExecuteNonQueryAsync(cancellationToken);
                    if (n > 0)
                        _logger.LogInformation("Aggressive purge {Table} deleted={Count}", table, n);
                }

                await using (var q = Conn.CreateCommand())
                {
                    q.CommandText = "DELETE FROM outbound_queue WHERE status = 'Sent';";
                    await q.ExecuteNonQueryAsync(cancellationToken);
                }
            }

            await using (var vacuum = Conn.CreateCommand())
            {
                vacuum.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                await vacuum.ExecuteNonQueryAsync(cancellationToken);
            }

            // VACUUM reclaims disk; only when still oversized (can take time on huge files)
            size = await GetDatabaseSizeBytesUnsafeAsync();
            if (size > maxBytes)
            {
                _logger.LogWarning("Running VACUUM to reclaim space (size={Size})", size);
                await using var vac = Conn.CreateCommand();
                vac.CommandText = "VACUUM;";
                vac.CommandTimeout = 600;
                await vac.ExecuteNonQueryAsync(cancellationToken);
                size = await GetDatabaseSizeBytesUnsafeAsync();
                _logger.LogInformation("After VACUUM size={Size}", size);
            }

            // Nuclear option: still huge after purge+vacuum → rotate DB file so agent stays healthy
            if (size > maxBytes * 2)
            {
                _logger.LogError(
                    "Local DB still {Size} bytes after purge (max={Max}). Rotating database so agent stays healthy.",
                    size, maxBytes);
                try
                {
                    if (_connection is not null)
                    {
                        await _connection.DisposeAsync();
                        _connection = null;
                    }

                    var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
                    var bak = _dbPath + $".oversized.{stamp}.bak";
                    if (File.Exists(_dbPath))
                        File.Move(_dbPath, bak, overwrite: true);
                    foreach (var side in new[] { "-wal", "-shm" })
                    {
                        var p = _dbPath + side;
                        if (File.Exists(p))
                            File.Move(p, bak + side, overwrite: true);
                    }

                    _connection = new SqliteConnection(new SqliteConnectionStringBuilder
                    {
                        DataSource = _dbPath,
                        Mode = SqliteOpenMode.ReadWriteCreate,
                        Cache = SqliteCacheMode.Shared
                    }.ToString());
                    await _connection.OpenAsync(cancellationToken);
                    await SchemaMigrator.MigrateAsync(_connection, cancellationToken);
                    _logger.LogWarning("Rotated oversized DB to {Bak}; fresh store ready", bak);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to rotate oversized local DB");
                    if (_connection is null)
                    {
                        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
                        {
                            DataSource = _dbPath,
                            Mode = SqliteOpenMode.ReadWriteCreate,
                            Cache = SqliteCacheMode.Shared
                        }.ToString());
                        await _connection.OpenAsync(cancellationToken);
                        await SchemaMigrator.MigrateAsync(_connection, cancellationToken);
                    }
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<long> GetDatabaseSizeBytesAsync(CancellationToken cancellationToken)
    {
        // File lengths only — do not take the DB gate (avoids status/heartbeat blocking on queue writes).
        cancellationToken.ThrowIfCancellationRequested();
        return GetDatabaseSizeBytesUnsafeAsync();
    }

    private Task<long> GetDatabaseSizeBytesUnsafeAsync()
    {
        long size = 0;
        if (File.Exists(_dbPath)) size += new FileInfo(_dbPath).Length;
        if (File.Exists(_dbPath + "-wal")) size += new FileInfo(_dbPath + "-wal").Length;
        if (File.Exists(_dbPath + "-shm")) size += new FileInfo(_dbPath + "-shm").Length;
        return Task.FromResult(size);
    }

    public async Task ProtectSecretAsync(string name, string plaintext, CancellationToken cancellationToken)
    {
        var protectedValue = DpapiSecretProtector.Protect(plaintext);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO secrets(name, protected_value, updated_at_utc)
                VALUES ($name, $value, $t)
                ON CONFLICT(name) DO UPDATE SET protected_value = excluded.protected_value, updated_at_utc = excluded.updated_at_utc;
                """;
            cmd.Parameters.AddWithValue("$name", name);
            cmd.Parameters.AddWithValue("$value", protectedValue);
            cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string?> UnprotectSecretAsync(string name, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT protected_value FROM secrets WHERE name = $name;";
            cmd.Parameters.AddWithValue("$name", name);
            var result = await cmd.ExecuteScalarAsync(cancellationToken) as string;
            return result is null ? null : DpapiSecretProtector.Unprotect(result);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        if (_connection is not null)
        {
            await _connection.DisposeAsync();
            _connection = null;
        }

        _gate.Dispose();
    }
}
