-- NT Shield Central — PostgreSQL schema
-- Apply with: psql -f 001_init.sql

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
    logon_process TEXT,
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
    rule_id TEXT,
    source_host TEXT,
    source_agent_id TEXT,
    source_ip TEXT,
    source_port INT,
    source_process_id INT,
    source_process_name TEXT,
    source_process_path TEXT,
    source_service_names TEXT,
    source_command_line TEXT,
    service_account TEXT,
    destination_host TEXT,
    destination_agent_id TEXT,
    destination_ip TEXT,
    destination_port INT,
    username TEXT,
    domain TEXT,
    logon_type INT,
    logon_process TEXT,
    failed_logon_count INT,
    distinct_usernames INT,
    successful_logon_count INT,
    privileged_logon BOOLEAN,
    evidence_json TEXT,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_incidents_key ON incidents(correlation_key);
CREATE INDEX IF NOT EXISTS ix_incidents_last ON incidents(last_seen_utc DESC);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_actions (
    request_id TEXT PRIMARY KEY,
    agent_id TEXT,
    action_type TEXT NOT NULL,
    requester TEXT,
    reason TEXT,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    approval_id TEXT,
    status TEXT NOT NULL,
    payload JSONB,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT,
    action TEXT NOT NULL,
    detail JSONB
);
