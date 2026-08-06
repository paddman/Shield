using Microsoft.Data.Sqlite;

namespace NTShield.Storage.Sqlite;

internal static class SchemaMigrator
{
    public const int CurrentSchemaVersion = 1;

    public static async Task MigrateAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText =
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL,
                    applied_at_utc TEXT NOT NULL
                );
                """;
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        var version = await GetSchemaVersionAsync(connection, cancellationToken);
        if (version < 1)
        {
            await ApplyV1Async(connection, cancellationToken);
            await SetSchemaVersionAsync(connection, 1, cancellationToken);
        }
    }

    private static async Task<int> GetSchemaVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_version;";
        var result = await cmd.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result);
    }

    private static async Task SetSchemaVersionAsync(SqliteConnection connection, int version, CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "INSERT INTO schema_version(version, applied_at_utc) VALUES ($v, $t);";
        cmd.Parameters.AddWithValue("$v", version);
        cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ApplyV1Async(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                provider_name TEXT,
                username TEXT,
                domain TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                logon_type INTEGER,
                authentication_package TEXT,
                process_id INTEGER,
                process_path TEXT,
                logon_process TEXT,
                status TEXT,
                substatus TEXT,
                target_user_name TEXT,
                target_domain_name TEXT,
                workstation_name TEXT,
                service_name TEXT,
                task_name TEXT,
                raw_xml TEXT NOT NULL,
                event_record_id INTEGER NOT NULL,
                collected_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_security_events_ts ON security_events(timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_security_events_event_id ON security_events(event_id);
            CREATE INDEX IF NOT EXISTS ix_security_events_source_ip ON security_events(source_ip);
            CREATE INDEX IF NOT EXISTS ix_security_events_username ON security_events(username);

            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                protocol TEXT NOT NULL,
                local_address TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_address TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                tcp_state INTEGER,
                process_id INTEGER NOT NULL,
                process_name TEXT,
                process_path TEXT,
                process_command_line TEXT,
                process_owner TEXT,
                parent_process_id INTEGER,
                digital_signature_status TEXT,
                signer_name TEXT,
                executable_sha256 TEXT,
                service_names TEXT,
                service_display_names TEXT,
                is_new INTEGER NOT NULL,
                is_closed INTEGER NOT NULL,
                connection_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_network_connections_ts ON network_connections(timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_network_connections_remote ON network_connections(remote_address, remote_port);
            CREATE INDEX IF NOT EXISTS ix_network_connections_pid ON network_connections(process_id);

            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                parent_process_id INTEGER,
                process_name TEXT NOT NULL,
                full_path TEXT,
                command_line TEXT,
                user_name TEXT,
                start_time_utc TEXT,
                executable_sha256 TEXT,
                signer_name TEXT,
                digital_signature_status TEXT,
                integrity_level TEXT,
                listening_ports TEXT,
                outbound_destinations TEXT,
                service_names TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_processes_ts ON processes(timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_processes_pid ON processes(process_id);

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                display_name TEXT,
                start_account TEXT,
                image_path TEXT,
                state TEXT,
                start_mode TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_services_pid ON services(process_id);

            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                task_path TEXT NOT NULL,
                task_name TEXT NOT NULL,
                command TEXT,
                arguments TEXT,
                run_as_account TEXT,
                triggers TEXT,
                enabled INTEGER NOT NULL,
                last_run_result TEXT,
                last_run_time_utc TEXT,
                change_type TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_scheduled_tasks_ts ON scheduled_tasks(timestamp_utc);

            CREATE TABLE IF NOT EXISTS detection_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL UNIQUE,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                event_count INTEGER NOT NULL,
                distinct_user_count INTEGER NOT NULL,
                distinct_destination_count INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                suppressed INTEGER NOT NULL,
                cooldown_until_utc TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_detection_alerts_ts ON detection_alerts(timestamp_utc);
            CREATE INDEX IF NOT EXISTS ix_detection_alerts_rule ON detection_alerts(rule_id);

            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL UNIQUE,
                request_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                incident_id TEXT,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                before_state TEXT,
                result TEXT,
                rollback_command TEXT,
                details TEXT,
                error TEXT,
                approved INTEGER NOT NULL DEFAULT 0,
                approval_id TEXT,
                audit_log TEXT
            );

            CREATE TABLE IF NOT EXISTS idempotency_keys (
                key TEXT PRIMARY KEY NOT NULL,
                created_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_type INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at_utc TEXT NOT NULL,
                sent_at_utc TEXT,
                status TEXT NOT NULL DEFAULT 'Pending'
            );
            CREATE INDEX IF NOT EXISTS ix_outbound_queue_status ON outbound_queue(status, id);

            CREATE TABLE IF NOT EXISTS secrets (
                name TEXT PRIMARY KEY NOT NULL,
                protected_value TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }
}
