using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Data;

public enum IngestIdempotencyClaimState
{
    Acquired,
    Completed,
    InProgress
}

public interface ICentralStore
{
    Task InitializeAsync();
    Task RegisterAgentAsync(AgentRegistrationRequest req);
    Task UpsertAgentAsync(AgentHeartbeat hb);
    Task<IngestIdempotencyClaimState> TryClaimIngestIdempotencyAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseUntilUtc,
        CancellationToken cancellationToken = default);
    Task<bool> RenewIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseUntilUtc,
        CancellationToken cancellationToken = default);
    Task<bool> CompleteIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        DateTimeOffset completedAtUtc,
        CancellationToken cancellationToken = default);
    Task ReleaseIngestIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        CancellationToken cancellationToken = default);
    Task SaveBatchAsync(AgentIngestBatch batch, string tenantId = "default");
    Task<IReadOnlyList<SecurityEventRecord>> ListSecurityEventsAsync(
        int take,
        string? tenantId = null,
        DateTimeOffset? fromUtc = null,
        DateTimeOffset? toUtc = null);
    Task UpsertIncidentAsync(Incident incident, string tenantId = "default");
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
    Task<TenantReportAggregate> GetDashboardOverviewAggregateAsync(
        string tenantId,
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc,
        CancellationToken cancellationToken = default);
    Task<Incident?> GetIncidentAsync(string id, string? tenantId = null);
    Task<IReadOnlyList<object>> ListAgentsAsync(string? tenantId = null);
    Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(
        string remoteIp,
        int? remotePort,
        DateTimeOffset from,
        DateTimeOffset to,
        string? tenantId = null);

    // Durable pending actions (survive Central restart)
    Task SavePendingActionAsync(ResponseActionRequest request, string agentKey);
    Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId);
    Task<ResponseActionRequest?> GetPendingActionAsync(string requestId);

    // Durable threat campaigns (JSON blob)
    Task UpsertCampaignJsonAsync(string campaignId, string json);
    Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take);
    Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonPageAsync(
        string? afterCampaignId,
        int take,
        CancellationToken cancellationToken = default);

    // Phase 2 temporal attack-chain projections. All keys and queries are tenant-scoped;
    // list methods are cursor primitives and must keep their result bounded.
    Task UpsertThreatCampaignV2SummaryAsync(
        ThreatCampaignV2Summary summary,
        CancellationToken cancellationToken = default);
    Task<ThreatCampaignV2Summary?> GetThreatCampaignV2SummaryAsync(
        string tenantId,
        string campaignId,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatCampaignV2Summary>> ListThreatCampaignV2SummariesAsync(
        string tenantId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        string? status,
        string? severity,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterCampaignId,
        int take,
        CancellationToken cancellationToken = default);
    Task<long> CountActiveThreatCampaignsAsync(
        string tenantId,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default);
    Task<bool> TryAppendThreatObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default);
    Task<bool> TryAppendThreatCandidateObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateObservationsAsync(
        string tenantId,
        string contactId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateContextObservationsAsync(
        string tenantId,
        string firstNodeId,
        string secondNodeId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default);
    Task UpsertThreatObservationMembershipAsync(
        ThreatObservationMembership membership,
        CancellationToken cancellationToken = default);
    Task MarkThreatCampaignMergedAsync(
        string tenantId,
        string campaignId,
        string mergedIntoCampaignId,
        DateTimeOffset tombstonedAtUtc,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatObservation>> ListThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterObservedAtUtc,
        string? afterObservationId,
        int take,
        CancellationToken cancellationToken = default);
    Task<long> CountThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default);
    Task<long> CountThreatObservationDetailsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatTimelineBucket>> ListThreatTimelineBucketsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        int resolutionSeconds,
        DateTimeOffset? afterBucketStartUtc,
        int take,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatContactAggregate>> ListThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterContactId,
        int take,
        CancellationToken cancellationToken = default);
    Task<long> CountThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default);
    Task EnqueueTemporalCorrelationWorkAsync(
        TemporalCorrelationWorkItem item,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<TemporalCorrelationWorkItem>> LeaseTemporalCorrelationWorkAsync(
        string leaseOwner,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int take,
        CancellationToken cancellationToken = default);
    Task CompleteTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        CancellationToken cancellationToken = default);
    Task FailTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        DateTimeOffset retryAtUtc,
        string error,
        CancellationToken cancellationToken = default);
    Task<int> SweepTemporalThreatDataAsync(
        DateTimeOffset detailBeforeUtc,
        DateTimeOffset aggregateBeforeUtc,
        CancellationToken cancellationToken = default);
    Task<string?> GetTemporalBackfillCursorAsync(CancellationToken cancellationToken = default);
    Task SaveTemporalBackfillCursorAsync(
        string? campaignId,
        CancellationToken cancellationToken = default);

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

    // Tenant-owned declarative report templates. Built-ins live in the service layer.
    Task<IReadOnlyList<ReportTemplateDefinition>> ListReportTemplatesAsync(string tenantId);
    Task<ReportTemplateDefinition?> GetReportTemplateAsync(string tenantId, string templateId);
    Task UpsertReportTemplateAsync(string tenantId, ReportTemplateDefinition template);
    Task<bool> TryUpdateReportTemplateAsync(
        string tenantId,
        ReportTemplateDefinition template,
        int expectedVersion);
    Task<bool> DeleteReportTemplateAsync(string tenantId, string templateId);

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
