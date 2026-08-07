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
    Task UpsertIncidentAsync(Incident incident);
    Task<IReadOnlyList<Incident>> ListIncidentsAsync(int take);
    Task<Incident?> GetIncidentAsync(string id);
    Task<IReadOnlyList<object>> ListAgentsAsync();
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
    Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60);
    Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60);

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
