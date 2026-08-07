using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Data;

public interface ICentralStore
{
    Task InitializeAsync();
    Task RegisterAgentAsync(AgentRegistrationRequest req);
    Task UpsertAgentAsync(AgentHeartbeat hb);
    Task<bool> HasIdempotencyKeyAsync(string key);
    Task SaveIdempotencyKeyAsync(string key);
    Task SaveBatchAsync(AgentIngestBatch batch);
    Task<IReadOnlyList<SecurityEventRecord>> ListSecurityEventsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null);
    Task UpsertIncidentAsync(Incident incident);
    Task<IReadOnlyList<Incident>> ListIncidentsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null);
    Task<long> CountIncidentsAsync(
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null);
    Task<TenantReportAggregate> GetReportAggregateAsync(
        string tenantId,
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc);
    Task<Incident?> GetIncidentAsync(string id, string? tenantId = null);
    Task<IReadOnlyList<object>> ListAgentsAsync(string? tenantId = null);
    Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(
        string remoteIp,
        int? remotePort,
        DateTimeOffset from,
        DateTimeOffset to);

    // Durable pending actions (survive Central restart)
    Task SavePendingActionAsync(ResponseActionRequest request, string agentKey);
    Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId);
    Task<ResponseActionRequest?> GetPendingActionAsync(string requestId);

    // Durable threat campaigns (JSON blob)
    Task UpsertCampaignJsonAsync(string campaignId, string json);
    Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take);

    // P0: auth + policy + audit
    Task AppendAuditAsync(string actor, string action, string? target, string result, string? detailJson, string? sourceIp);
    Task<IReadOnlyList<AuditLogEntry>> ListAuditAsync(int take);
    Task<AgentPolicy> GetActivePolicyAsync(string? agentId = null);
    Task UpsertPolicyAsync(AgentPolicy policy);
    /// <summary>Issue or keep agent API key. Returns plaintext key when issued/rotated; null when unchanged and not re-issued.</summary>
    Task<string?> IssueAgentApiKeyAsync(string agentId, bool rotate);
    Task SetAgentApiKeyHashAsync(string agentId, string keyHash);
    Task<string?> FindAgentIdByApiKeyHashAsync(string keyHash);
    Task UpdateAgentIntegrityAsync(string agentId, string? binarySha256, bool? isSigned, int? policyVersion);

    /// <summary>Append heartbeat metrics sample for history charts.</summary>
    Task SaveAgentMetricsAsync(AgentHeartbeat hb);
    Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60, string? tenantId = null);
    Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60);

    // Customer registry, agent ownership and generated tenant reports.
    Task<IReadOnlyList<CustomerTenant>> ListTenantsAsync();
    Task<CustomerTenant?> GetTenantAsync(string tenantId);
    Task UpsertTenantAsync(CustomerTenant tenant);
    Task<IReadOnlyList<TenantAgentAssignment>> ListAgentAssignmentsAsync();
    Task AssignAgentToTenantAsync(string tenantId, string agentId);
    Task<IReadOnlyList<SecurityReportRecord>> ListReportsAsync(string tenantId, int take);
    Task<SecurityReportRecord?> GetReportAsync(string tenantId, string reportId);
    Task UpsertReportAsync(SecurityReportRecord report);

    // Tenant-scoped asset inventory, topology maps and declarative workflows.
    Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId);
    Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId);
    Task UpsertAssetAsync(string tenantId, TenantAsset asset);
    Task<bool> DeleteAssetAsync(string tenantId, string assetId);

    Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId);
    Task<TopologyDocument?> GetTopologyAsync(string tenantId, string topologyId);
    Task UpsertTopologyAsync(string tenantId, TopologyDocument topology);
    Task<bool> DeleteTopologyAsync(string tenantId, string topologyId);

    Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId);
    Task<DetectionWorkflow?> GetWorkflowAsync(string tenantId, string workflowId);
    Task UpsertWorkflowAsync(string tenantId, DetectionWorkflow workflow);
    Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId);
}
