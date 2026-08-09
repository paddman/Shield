using System.Text.Json;
using ClickHouse.Driver;
using Microsoft.Extensions.Options;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Data;

/// <summary>
/// ClickHouse analytics sink with a transactional PostgreSQL or SQLite control plane.
/// ClickHouse is append/merge oriented; API keys, policies and pending actions therefore
/// remain in the configured control store while telemetry, incidents, alerts and metrics
/// are written to ClickHouse. PostgreSQL is required for production multi-node operation;
/// SQLite remains available for a single-node lab.
/// </summary>
public sealed partial class ClickHouseStore : ICentralStore
{
    private readonly ICentralStore _control;
    private readonly ClickHouseOptions _options;
    private readonly ILogger<ClickHouseStore> _logger;
    private readonly ClickHouseClient _client;
    private readonly string _table;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public ClickHouseStore(
        SqliteCentralStore sqliteControl,
        PostgresStore postgresControl,
        IOptions<ClickHouseOptions> options,
        ILogger<ClickHouseStore> logger)
    {
        _options = options.Value;
        _control = _options.ControlProvider.Trim().ToLowerInvariant() switch
        {
            "postgres" or "postgresql" => postgresControl,
            "sqlite" or "sqlite-lab" => sqliteControl,
            _ => throw new InvalidOperationException(
                "ClickHouse:ControlProvider must be 'Postgres' or 'Sqlite'.")
        };
        _logger = logger;
        _client = new ClickHouseClient(_options.ConnectionString);
        var database = string.IsNullOrWhiteSpace(_options.Database) ? "ntshield" : _options.Database;
        _table = $"{QuoteIdentifier(database)}.events";
    }

    public async Task InitializeAsync()
    {
        await _control.InitializeAsync();
        try
        {
            var database = string.IsNullOrWhiteSpace(_options.Database) ? "ntshield" : _options.Database;
            await _client.ExecuteNonQueryAsync($"CREATE DATABASE IF NOT EXISTS {QuoteIdentifier(database)}");
            await _client.ExecuteNonQueryAsync($"""
                CREATE TABLE IF NOT EXISTS {_table} (
                    event_time DateTime64(3, 'UTC'),
                    event_type LowCardinality(String),
                    entity_id String,
                    agent_id String,
                    tenant_id LowCardinality(String) DEFAULT 'default',
                    payload String
                ) ENGINE = MergeTree
                PARTITION BY toYYYYMM(event_time)
                ORDER BY (event_type, agent_id, event_time, entity_id)
                """);
            await _client.ExecuteNonQueryAsync(
                $"ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS tenant_id LowCardinality(String) DEFAULT 'default'");
            _logger.LogInformation("ClickHouse analytics store ready at {Database}.{Table}", database, "events");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClickHouse initialize failed");
            if (_options.FailWrites) throw;
        }
    }

    public async Task RegisterAgentAsync(AgentRegistrationRequest req)
    {
        await _control.RegisterAgentAsync(req);
        await WriteAsync("agent_registration", req.AgentId, DateTimeOffset.UtcNow, req.AgentId, req,
            req.TenantId ?? "default");
    }

    public async Task UpsertAgentAsync(AgentHeartbeat hb)
    {
        await _control.UpsertAgentAsync(hb);
        await WriteAsync("agent_heartbeat", hb.AgentId, hb.TimestampUtc, hb.AgentId, hb);
    }

    public Task<IngestIdempotencyClaimState> TryClaimIngestIdempotencyAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseUntilUtc,
        CancellationToken cancellationToken = default) =>
        _control.TryClaimIngestIdempotencyAsync(
            tenantId, agentId, keyHash, leaseOwner, nowUtc, leaseUntilUtc, cancellationToken);

    public Task<bool> RenewIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseUntilUtc,
        CancellationToken cancellationToken = default) =>
        _control.RenewIngestIdempotencyClaimAsync(
            tenantId, agentId, keyHash, leaseOwner, nowUtc, leaseUntilUtc, cancellationToken);

    public Task<bool> CompleteIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset completedAtUtc,
        CancellationToken cancellationToken = default) =>
        _control.CompleteIngestIdempotencyClaimAsync(
            tenantId, agentId, keyHash, leaseOwner, completedAtUtc, cancellationToken);

    public Task ReleaseIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        CancellationToken cancellationToken = default) =>
        _control.ReleaseIngestIdempotencyClaimAsync(
            tenantId, agentId, keyHash, leaseOwner, cancellationToken);

    public async Task SaveBatchAsync(AgentIngestBatch batch, string tenantId = "default")
    {
        tenantId = NormalizeTenantId(tenantId);
        await _control.SaveBatchAsync(batch, tenantId);
        var rows = new List<object[]>();
        foreach (var item in batch.SecurityEvents)
        {
            item.TenantId = tenantId;
            rows.Add(Row("security_event", $"{batch.AgentId}:{item.EventRecordId}:{item.TimestampUtc.Ticks}",
                item.TimestampUtc, batch.AgentId, item, tenantId));
        }

        foreach (var item in batch.NetworkConnections)
        {
            item.TenantId = tenantId;
            rows.Add(Row("network_connection", $"{batch.AgentId}:{item.TimestampUtc.Ticks}:{item.RemoteAddress}:{item.RemotePort}",
                item.TimestampUtc, batch.AgentId, item, tenantId));
        }

        foreach (var item in batch.Alerts)
        {
            item.TenantId = tenantId;
            rows.Add(Row("detection_alert", item.AlertId, item.TimestampUtc, batch.AgentId, item, tenantId));
        }

        await InsertRowsAsync(rows);
    }

    public async Task UpsertIncidentAsync(Incident incident, string tenantId = "default")
    {
        tenantId = NormalizeTenantId(tenantId);
        incident.TenantId = tenantId;
        await _control.UpsertIncidentAsync(incident, tenantId);
        await WriteAsync("incident", incident.IncidentId, incident.LastSeenUtc, incident.SourceAgentId ?? "", incident, tenantId);
    }

    public Task<IReadOnlyList<SecurityEventRecord>> ListSecurityEventsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null) =>
        _control.ListSecurityEventsAsync(take, tenantId, fromUtc, toUtc);

    public Task<IReadOnlyList<Incident>> ListIncidentsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null) =>
        _control.ListIncidentsAsync(take, tenantId, fromUtc, toUtc);

    public Task<long> CountIncidentsAsync(
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null) =>
        _control.CountIncidentsAsync(tenantId, fromUtc, toUtc);

    public Task<TenantReportAggregate> GetReportAggregateAsync(
        string tenantId,
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc) =>
        _control.GetReportAggregateAsync(tenantId, fromUtc, toUtc);

    public Task<TenantReportAggregate> GetDashboardOverviewAggregateAsync(
        string tenantId,
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc,
        CancellationToken cancellationToken = default) =>
        _control.GetDashboardOverviewAggregateAsync(
            tenantId, fromUtc, toUtc, cancellationToken);

    public Task<Incident?> GetIncidentAsync(string id, string? tenantId = null) =>
        _control.GetIncidentAsync(id, tenantId);

    public Task<IReadOnlyList<object>> ListAgentsAsync(string? tenantId = null) =>
        _control.ListAgentsAsync(tenantId);

    public Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(
        string remoteIp, int? remotePort, DateTimeOffset from, DateTimeOffset to, string? tenantId = null) =>
        _control.FindOutboundAsync(remoteIp, remotePort, from, to, tenantId);

    public Task SavePendingActionAsync(ResponseActionRequest request, string agentKey) =>
        _control.SavePendingActionAsync(request, agentKey);

    public Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId) =>
        _control.TakePendingActionsAsync(agentId);

    public Task<ResponseActionRequest?> GetPendingActionAsync(string requestId) =>
        _control.GetPendingActionAsync(requestId);

    public async Task UpsertCampaignJsonAsync(string campaignId, string json)
    {
        await _control.UpsertCampaignJsonAsync(campaignId, json);
        var tenantId = "default";
        try
        {
            tenantId = NormalizeTenantId(JsonSerializer.Deserialize<ThreatCampaign>(json, JsonOptions)?.TenantId);
        }
        catch (JsonException)
        {
            // Preserve legacy/unknown campaign payloads in the default analytics partition.
        }
        await WriteAsync("threat_campaign", campaignId, DateTimeOffset.UtcNow, "", json, tenantId);
    }

    public Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take) =>
        _control.ListCampaignJsonAsync(take);

    public Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonPageAsync(
        string? afterCampaignId,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListCampaignJsonPageAsync(afterCampaignId, take, cancellationToken);

    public async Task AppendAuditAsync(string actor, string action, string? target, string result, string? detailJson, string? sourceIp)
    {
        await _control.AppendAuditAsync(actor, action, target, result, detailJson, sourceIp);
        await WriteAsync("audit", target ?? action, DateTimeOffset.UtcNow, "", new
        {
            actor,
            action,
            target,
            result,
            detailJson,
            sourceIp
        });
    }

    public Task<IReadOnlyList<AuditLogEntry>> ListAuditAsync(int take) => _control.ListAuditAsync(take);

    public Task<AgentPolicy> GetActivePolicyAsync(string? agentId = null) => _control.GetActivePolicyAsync(agentId);

    public Task UpsertPolicyAsync(AgentPolicy policy) => _control.UpsertPolicyAsync(policy);

    public Task<string?> IssueAgentApiKeyAsync(string agentId, bool rotate) =>
        _control.IssueAgentApiKeyAsync(agentId, rotate);

    public Task SetAgentApiKeyHashAsync(string agentId, string keyHash) =>
        _control.SetAgentApiKeyHashAsync(agentId, keyHash);

    public Task<string?> FindAgentIdByApiKeyHashAsync(string keyHash) =>
        _control.FindAgentIdByApiKeyHashAsync(keyHash);

    public Task UpdateAgentIntegrityAsync(string agentId, string? binarySha256, bool? isSigned, int? policyVersion) =>
        _control.UpdateAgentIntegrityAsync(agentId, binarySha256, isSigned, policyVersion);

    public async Task SaveAgentMetricsAsync(AgentHeartbeat hb)
    {
        await _control.SaveAgentMetricsAsync(hb);
        await WriteAsync("agent_metric", hb.AgentId, hb.TimestampUtc, hb.AgentId, hb);
    }

    public Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60, string? tenantId = null) =>
        _control.GetAgentAsync(agentId, metricsTake, tenantId);

    public Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60) =>
        _control.ListAgentMetricsAsync(agentId, take);

    public Task<IReadOnlyList<CustomerTenant>> ListTenantsAsync() => _control.ListTenantsAsync();

    public Task<CustomerTenant?> GetTenantAsync(string tenantId) => _control.GetTenantAsync(tenantId);

    public Task UpsertTenantAsync(CustomerTenant tenant) => _control.UpsertTenantAsync(tenant);

    public Task<IReadOnlyList<TenantAgentAssignment>> ListAgentAssignmentsAsync() =>
        _control.ListAgentAssignmentsAsync();

    public Task AssignAgentToTenantAsync(string tenantId, string agentId) =>
        _control.AssignAgentToTenantAsync(tenantId, agentId);

    public Task<IReadOnlyList<SecurityReportRecord>> ListReportsAsync(string tenantId, int take) =>
        _control.ListReportsAsync(tenantId, take);

    public Task<SecurityReportRecord?> GetReportAsync(string tenantId, string reportId) =>
        _control.GetReportAsync(tenantId, reportId);

    public Task UpsertReportAsync(SecurityReportRecord report) => _control.UpsertReportAsync(report);

    public Task<IReadOnlyList<ReportTemplateDefinition>> ListReportTemplatesAsync(string tenantId) =>
        _control.ListReportTemplatesAsync(tenantId);

    public Task<ReportTemplateDefinition?> GetReportTemplateAsync(string tenantId, string templateId) =>
        _control.GetReportTemplateAsync(tenantId, templateId);

    public Task UpsertReportTemplateAsync(string tenantId, ReportTemplateDefinition template) =>
        _control.UpsertReportTemplateAsync(tenantId, template);

    public Task<bool> TryUpdateReportTemplateAsync(
        string tenantId,
        ReportTemplateDefinition template,
        int expectedVersion) =>
        _control.TryUpdateReportTemplateAsync(tenantId, template, expectedVersion);

    public Task<bool> DeleteReportTemplateAsync(string tenantId, string templateId) =>
        _control.DeleteReportTemplateAsync(tenantId, templateId);

    // Topology, asset and workflow graphs are transactional control-plane data;
    // keep them in the SQLite control store when ClickHouse is enabled.
    public Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId) => _control.ListAssetsAsync(tenantId);

    public Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId) =>
        _control.GetAssetAsync(tenantId, assetId);

    public Task UpsertAssetAsync(string tenantId, TenantAsset asset) =>
        _control.UpsertAssetAsync(tenantId, asset);

    public Task<bool> DeleteAssetAsync(string tenantId, string assetId) =>
        _control.DeleteAssetAsync(tenantId, assetId);

    public Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId) =>
        _control.ListTopologiesAsync(tenantId);

    public Task<TopologyDocument?> GetTopologyAsync(string tenantId, string topologyId) =>
        _control.GetTopologyAsync(tenantId, topologyId);

    public Task UpsertTopologyAsync(string tenantId, TopologyDocument topology) =>
        _control.UpsertTopologyAsync(tenantId, topology);

    public Task<bool> DeleteTopologyAsync(string tenantId, string topologyId) =>
        _control.DeleteTopologyAsync(tenantId, topologyId);

    public Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId) =>
        _control.ListWorkflowsAsync(tenantId);

    public Task<DetectionWorkflow?> GetWorkflowAsync(string tenantId, string workflowId) =>
        _control.GetWorkflowAsync(tenantId, workflowId);

    public Task UpsertWorkflowAsync(string tenantId, DetectionWorkflow workflow) =>
        _control.UpsertWorkflowAsync(tenantId, workflow);

    public Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId) =>
        _control.DeleteWorkflowAsync(tenantId, workflowId);

    private async Task WriteAsync(
        string type,
        string entityId,
        DateTimeOffset timestamp,
        string agentId,
        object payload,
        string tenantId = "default")
    {
        await InsertRowsAsync([Row(type, entityId, timestamp, agentId, payload, NormalizeTenantId(tenantId))]);
    }

    private async Task InsertRowsAsync(IReadOnlyList<object[]> rows)
    {
        if (rows.Count == 0) return;
        try
        {
            await _client.InsertBinaryAsync(_table,
                ["event_time", "event_type", "entity_id", "agent_id", "tenant_id", "payload"], rows);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClickHouse analytics insert failed for {Count} rows", rows.Count);
            if (_options.FailWrites) throw;
        }
    }

    private static object[] Row(
        string type,
        string entityId,
        DateTimeOffset timestamp,
        string agentId,
        object payload,
        string tenantId = "default") =>
    [
        timestamp.UtcDateTime,
        type,
        entityId ?? string.Empty,
        agentId ?? string.Empty,
        NormalizeTenantId(tenantId),
        JsonSerializer.Serialize(payload, JsonOptions)
    ];

    private static string QuoteIdentifier(string identifier) =>
        "`" + identifier.Replace("`", "``", StringComparison.Ordinal) + "`";

    private static string NormalizeTenantId(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? "default" : tenantId.Trim().ToLowerInvariant();
}
