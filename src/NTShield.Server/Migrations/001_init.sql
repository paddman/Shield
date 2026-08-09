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
    tenant_id TEXT NOT NULL DEFAULT 'default',
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
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE security_events ALTER COLUMN tenant_id SET DEFAULT 'default';
UPDATE security_events SET tenant_id='default' WHERE tenant_id IS NULL;
ALTER TABLE security_events ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_sec_events_tenant_ts
    ON security_events(tenant_id, timestamp_utc DESC);

CREATE TABLE IF NOT EXISTS network_connections (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
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
ALTER TABLE network_connections
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE network_connections ALTER COLUMN tenant_id SET DEFAULT 'default';
UPDATE network_connections SET tenant_id='default' WHERE tenant_id IS NULL;
ALTER TABLE network_connections ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_net_tenant_remote
    ON network_connections(tenant_id, remote_address, timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS ix_net_tenant_ts
    ON network_connections(tenant_id, timestamp_utc DESC);

CREATE TABLE IF NOT EXISTS detection_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
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
ALTER TABLE detection_alerts
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE detection_alerts ALTER COLUMN tenant_id SET DEFAULT 'default';
UPDATE detection_alerts SET tenant_id='default' WHERE tenant_id IS NULL;
ALTER TABLE detection_alerts ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_ts
    ON detection_alerts(tenant_id, timestamp_utc DESC);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
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
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE incidents ALTER COLUMN tenant_id SET DEFAULT 'default';
UPDATE incidents SET tenant_id='default' WHERE tenant_id IS NULL;
ALTER TABLE incidents ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_incidents_tenant_last
    ON incidents(tenant_id, last_seen_utc DESC);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agent ingest idempotency is tenant- and authenticated-agent scoped. The
-- legacy table above remains for upgrade compatibility but is not used by new
-- ingest requests.
CREATE TABLE IF NOT EXISTS ingest_idempotency_claims (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    lease_owner TEXT,
    lease_until_utc TIMESTAMPTZ,
    created_at_utc TIMESTAMPTZ NOT NULL,
    updated_at_utc TIMESTAMPTZ NOT NULL,
    completed_at_utc TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, agent_id, key_hash)
);
CREATE INDEX IF NOT EXISTS ix_ingest_idempotency_lease
    ON ingest_idempotency_claims(status, lease_until_utc);

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
