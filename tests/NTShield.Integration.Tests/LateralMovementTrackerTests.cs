using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Integration.Tests;

/// <summary>
/// Verifies multi-host threat tracking (A→B→C). Detection only — no offensive behavior.
/// </summary>
public class LateralMovementTrackerTests
{
    private static LateralMovementTracker CreateTracker() =>
        new(
            Options.Create(new CorrelationOptions { TimestampToleranceSeconds = 120 }),
            NullLogger<LateralMovementTracker>.Instance,
            new NullCentralStore());

    [Fact]
    public void Tracks_Threat_From_Source_To_Multiple_Hosts()
    {
        var tracker = CreateTracker();

        var now = DateTimeOffset.UtcNow;
        var hop1 = new Incident
        {
            IncidentId = "inc1",
            Title = "Internal Password Spray",
            RuleId = "INTERNAL_PASSWORD_SPRAY",
            Severity = Severity.High,
            SourceIp = "10.0.105.35",
            SourceHost = "SRC-35",
            DestinationIp = "10.0.105.190",
            DestinationHost = "DEST-190",
            DestinationPort = 80,
            ProcessId = 1684,
            ProcessName = "svchost.exe",
            Services = ["IPTVManagementService"],
            FailedAttempts = 80,
            DistinctUsernames = 11,
            SuccessfulLoginDetected = false,
            FirstSeen = now.AddMinutes(-10),
            LastSeen = now.AddMinutes(-8)
        };

        var hop2 = new Incident
        {
            IncidentId = "inc2",
            Title = "Network Logon Burst",
            RuleId = "NETWORK_LOGON_BURST",
            Severity = Severity.Medium,
            SourceIp = "10.0.105.190",
            SourceHost = "DEST-190",
            DestinationIp = "10.0.105.200",
            DestinationHost = "DEST-200",
            DestinationPort = 445,
            Username = "admin",
            FailedAttempts = 0,
            SuccessfulLoginDetected = true,
            FirstSeen = now.AddMinutes(-5),
            LastSeen = now.AddMinutes(-4)
        };

        var campaigns = tracker.IngestIncidents([hop1, hop2]);
        Assert.NotEmpty(campaigns);

        var multi = tracker.ListCampaigns().FirstOrDefault(c => c.Hops.Count >= 2)
                    ?? campaigns.OrderByDescending(c => c.Hops.Count).First();

        Assert.True(multi.Hops.Count >= 2 || multi.InvolvedIps.Count >= 2);

        var byHost = tracker.FindByHostOrIp("10.0.105.200");
        Assert.NotEmpty(byHost);

        var display = multi.FormatDisplay();
        Assert.Contains("Threat Campaign", display);
        Assert.Contains("Lateral path", display);

        var catalog = tracker.GetThreatCatalog();
        Assert.Contains(catalog, e => e.DetectionRuleId == "INTERNAL_PASSWORD_SPRAY");
        Assert.Contains(catalog, e => e.Category == "lateral_movement");
        Assert.Contains(catalog, e => e.Category == "persistence");
    }

    [Fact]
    public void FindByHost_Returns_Empty_For_Unknown()
    {
        var tracker = CreateTracker();
        Assert.Empty(tracker.FindByHostOrIp("203.0.113.1"));
    }

    [Fact]
    public void Campaigns_With_The_Same_Path_And_Time_Are_Partitioned_By_Tenant()
    {
        var tracker = CreateTracker();
        var timestamp = new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);
        Incident IncidentFor(string id) => new()
        {
            IncidentId = id,
            RuleId = "NETWORK_LOGON_BURST",
            Title = "Same network path",
            Severity = Severity.High,
            SourceAgentId = "shared-agent-id",
            SourceIp = "10.0.0.10",
            DestinationIp = "10.0.0.20",
            LastSeen = timestamp
        };

        var alpha = Assert.Single(tracker.IngestIncidents([IncidentFor("same-id")], "alpha"));
        var beta = Assert.Single(tracker.IngestIncidents([IncidentFor("same-id")], "beta"));

        Assert.NotEqual(alpha.CampaignId, beta.CampaignId);
        Assert.Equal("alpha", alpha.TenantId);
        Assert.Equal("beta", beta.TenantId);
        Assert.Single(tracker.ListCampaigns(10, "alpha"));
        Assert.Single(tracker.ListCampaigns(10, "beta"));
        Assert.Empty(tracker.FindByHostOrIp("10.0.0.20", "other"));

        Assert.Equal(1, tracker.ApplyAnomaly(
            "shared-agent-id", .8, .7, 12, "test", timestamp, tenantId: "alpha"));
        Assert.NotNull(tracker.GetCampaign(alpha.CampaignId, "alpha")?.MlScore);
        Assert.Null(tracker.GetCampaign(beta.CampaignId, "beta")?.MlScore);
    }

    [Fact]
    public async Task Detection_Alert_Becomes_Incident_With_ML_Features()
    {
        var correlator = new CrossHostCorrelator(
            new NullCentralStore(),
            Options.Create(new CorrelationOptions()),
            NullLogger<CrossHostCorrelator>.Instance);
        var incidents = await correlator.CorrelateAsync(new AgentIngestBatch
        {
            AgentId = "agent-1",
            ComputerName = "HOST-1",
            Alerts =
            [
                new DetectionAlert
                {
                    AlertId = "alert-1",
                    AgentId = "agent-1",
                    ComputerName = "HOST-1",
                    RuleId = "HASH_BAD",
                    RuleName = "NT Shield Antivirus",
                    Title = "Antivirus threat detected",
                    Severity = Severity.Critical,
                    IncidentScore = 100,
                    DetectionStage = "signature → heuristic",
                    Features = new Dictionary<string, double> { ["hash_hit"] = 1, ["entropy"] = 7.9 },
                    AssetId = "HOST-1",
                    ObserveBaseline = false,
                    EvidenceJson = "[{\"source\":\"endpoint\"}]"
                }
            ]
        }, CancellationToken.None);

        var incident = Assert.Single(incidents);
        Assert.Equal(100, incident.IncidentScore);
        Assert.Equal(2, incident.Features.Count);
        Assert.Equal("HOST-1", incident.AssetId);
        Assert.False(incident.ObserveBaseline);
    }

    [Fact]
    public void Campaign_summary_is_bounded_and_explains_representative_hops()
    {
        var tracker = CreateTracker();
        var start = DateTimeOffset.UtcNow.AddMinutes(-12);
        for (var index = 0; index < 12; index++)
        {
            tracker.IngestIncidents([
                new Incident
                {
                    IncidentId = $"summary-inc-{index}",
                    RuleId = "NETWORK_LOGON_BURST",
                    Title = "Network Logon Burst",
                    Severity = Severity.Medium,
                    SourceIp = "10.0.0.1",
                    DestinationIp = $"10.0.1.{index + 1}",
                    LastSeen = start.AddMinutes(index)
                }
            ]);
        }

        var campaign = tracker.ListCampaigns().Single();
        Assert.Equal(12, campaign.Hops.Count);
        Assert.Contains("Showing 8 of 12 hops (4 omitted)", campaign.Summary);
        Assert.Contains("10.0.1.1", campaign.Summary);
        Assert.Contains("10.0.1.12", campaign.Summary);
        Assert.True(campaign.Summary.Length < 1_500);
    }

    [Fact]
    public void Attaches_latest_ml_observation_to_matching_campaign()
    {
        var tracker = CreateTracker();
        var campaign = tracker.IngestIncidents([
            new Incident
            {
                IncidentId = "ml-inc-1",
                RuleId = "INTERNAL_PASSWORD_SPRAY",
                Severity = Severity.High,
                SourceAgentId = "agent-source",
                SourceIp = "10.0.0.10",
                DestinationAgentId = "agent-destination",
                DestinationIp = "10.0.0.20",
                LastSeen = DateTimeOffset.UtcNow
            }
        ]).Single();

        var updated = tracker.ApplyAnomaly(
            "agent-source", .91, .84, 27, "isolation_forest+robust_mad",
            DateTimeOffset.UtcNow, ["failed_logons", "unique_remote_ports"]);

        var result = tracker.GetCampaign(campaign.CampaignId);
        Assert.Equal(1, updated);
        Assert.NotNull(result);
        Assert.Equal(.91, result!.MlScore);
        Assert.Equal(.84, result.MlConfidence);
        Assert.Equal(27, result.MlBaselineSamples);
        Assert.Contains("failed_logons", result.MlSignals);
        Assert.Single(result.MlHistory);
        Assert.Equal(.91, result.MlHistory[0].Score);
    }

    [Fact]
    public void Keeps_ml_history_ordered_and_bounded()
    {
        var tracker = CreateTracker();
        var campaign = tracker.IngestIncidents([
            new Incident
            {
                IncidentId = "ml-history-inc-1",
                RuleId = "INTERNAL_PASSWORD_SPRAY",
                Severity = Severity.High,
                SourceAgentId = "agent-history",
                SourceIp = "10.0.0.30",
                DestinationIp = "10.0.0.40",
                LastSeen = DateTimeOffset.UtcNow
            }
        ]).Single();

        var start = DateTimeOffset.UtcNow.AddMinutes(-60);
        for (var index = 0; index < 60; index++)
        {
            tracker.ApplyAnomaly(
                "agent-history", index / 100.0, .8, 20 + index,
                "isolation_forest+robust_mad", start.AddMinutes(index), ["signal"]);
        }

        var result = tracker.GetCampaign(campaign.CampaignId)!;
        Assert.Equal(48, result.MlHistory.Count);
        Assert.Equal(start.AddMinutes(12), result.MlHistory[0].ObservedAtUtc);
        Assert.Equal(start.AddMinutes(59), result.MlHistory[^1].ObservedAtUtc);
        Assert.Equal(.59, result.MlHistory[^1].Score);
    }

    private sealed class NullCentralStore : ICentralStore
    {
        public Task InitializeAsync() => Task.CompletedTask;
        public Task RegisterAgentAsync(AgentRegistrationRequest req) => Task.CompletedTask;
        public Task UpsertAgentAsync(AgentHeartbeat hb) => Task.CompletedTask;
        public Task<IngestIdempotencyClaimState> TryClaimIngestIdempotencyAsync(
            string tenantId, string agentId, string keyHash, string leaseOwner,
            DateTimeOffset nowUtc, DateTimeOffset leaseUntilUtc,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(IngestIdempotencyClaimState.Acquired);
        public Task<bool> RenewIngestIdempotencyClaimAsync(
            string tenantId, string agentId, string keyHash, string leaseOwner,
            DateTimeOffset nowUtc, DateTimeOffset leaseUntilUtc,
            CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<bool> CompleteIngestIdempotencyClaimAsync(
            string tenantId, string agentId, string keyHash, string leaseOwner,
            DateTimeOffset completedAtUtc,
            CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task ReleaseIngestIdempotencyClaimAsync(
            string tenantId, string agentId, string keyHash, string leaseOwner,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task SaveBatchAsync(AgentIngestBatch batch, string tenantId = "default") => Task.CompletedTask;
        public Task<IReadOnlyList<SecurityEventRecord>> ListSecurityEventsAsync(int take, string? tenantId = null, DateTimeOffset? fromUtc = null, DateTimeOffset? toUtc = null) =>
            Task.FromResult<IReadOnlyList<SecurityEventRecord>>(Array.Empty<SecurityEventRecord>());
        public Task UpsertIncidentAsync(Incident incident, string tenantId = "default") => Task.CompletedTask;
        public Task<IReadOnlyList<Incident>> ListIncidentsAsync(int take, string? tenantId = null, DateTimeOffset? fromUtc = null, DateTimeOffset? toUtc = null) => Task.FromResult<IReadOnlyList<Incident>>(Array.Empty<Incident>());
        public Task<long> CountIncidentsAsync(string? tenantId = null, DateTimeOffset? fromUtc = null, DateTimeOffset? toUtc = null) => Task.FromResult(0L);
        public Task<TenantReportAggregate> GetReportAggregateAsync(string tenantId, DateTimeOffset fromUtc, DateTimeOffset toUtc) =>
            Task.FromResult(new TenantReportAggregate());
        public Task<TenantReportAggregate> GetDashboardOverviewAggregateAsync(string tenantId, DateTimeOffset fromUtc, DateTimeOffset toUtc, CancellationToken cancellationToken = default) =>
            Task.FromResult(new TenantReportAggregate());
        public Task<Incident?> GetIncidentAsync(string id, string? tenantId = null) => Task.FromResult<Incident?>(null);
        public Task<IReadOnlyList<object>> ListAgentsAsync(string? tenantId = null) => Task.FromResult<IReadOnlyList<object>>(Array.Empty<object>());
        public Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(string remoteIp, int? remotePort, DateTimeOffset from, DateTimeOffset to, string? tenantId = null) =>
            Task.FromResult<IReadOnlyList<NetworkConnectionRecord>>(Array.Empty<NetworkConnectionRecord>());
        public Task SavePendingActionAsync(ResponseActionRequest request, string agentKey) => Task.CompletedTask;
        public Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId) => Task.FromResult(new List<ResponseActionRequest>());
        public Task<ResponseActionRequest?> GetPendingActionAsync(string requestId) => Task.FromResult<ResponseActionRequest?>(null);
        public Task UpsertCampaignJsonAsync(string campaignId, string json) => Task.CompletedTask;
        public Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take) =>
            Task.FromResult<IReadOnlyList<(string, string)>>(Array.Empty<(string, string)>());
        public Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonPageAsync(string? afterCampaignId, int take, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<(string, string)>>(Array.Empty<(string, string)>());
        public Task UpsertThreatCampaignV2SummaryAsync(ThreatCampaignV2Summary summary, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<ThreatCampaignV2Summary?> GetThreatCampaignV2SummaryAsync(string tenantId, string campaignId, CancellationToken cancellationToken = default) => Task.FromResult<ThreatCampaignV2Summary?>(null);
        public Task<IReadOnlyList<ThreatCampaignV2Summary>> ListThreatCampaignV2SummariesAsync(string tenantId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc, DateTimeOffset? toObservedAtUtc, string? status, string? severity, DateTimeOffset? afterLastObservedAtUtc, string? afterCampaignId, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatCampaignV2Summary>>([]);
        public Task<long> CountActiveThreatCampaignsAsync(string tenantId, DateTimeOffset? fromObservedAtUtc = null, DateTimeOffset? toObservedAtUtc = null, CancellationToken cancellationToken = default) => Task.FromResult(0L);
        public Task<bool> TryAppendThreatObservationAsync(ThreatObservation observation, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> TryAppendThreatCandidateObservationAsync(ThreatObservation observation, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateObservationsAsync(string tenantId, string contactId, DateTimeOffset fromObservedAtUtc, DateTimeOffset toObservedAtUtc, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatObservation>>([]);
        public Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateContextObservationsAsync(string tenantId, string firstNodeId, string secondNodeId, DateTimeOffset fromObservedAtUtc, DateTimeOffset toObservedAtUtc, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatObservation>>([]);
        public Task UpsertThreatObservationMembershipAsync(ThreatObservationMembership membership, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task MarkThreatCampaignMergedAsync(string tenantId, string campaignId, string mergedIntoCampaignId, DateTimeOffset tombstonedAtUtc, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<ThreatObservation>> ListThreatObservationsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc, DateTimeOffset? toObservedAtUtc, DateTimeOffset? afterObservedAtUtc, string? afterObservationId, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatObservation>>([]);
        public Task<long> CountThreatObservationsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc = null, DateTimeOffset? toObservedAtUtc = null, CancellationToken cancellationToken = default) => Task.FromResult(0L);
        public Task<long> CountThreatObservationDetailsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc = null, DateTimeOffset? toObservedAtUtc = null, CancellationToken cancellationToken = default) => Task.FromResult(0L);
        public Task<IReadOnlyList<ThreatTimelineBucket>> ListThreatTimelineBucketsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc, DateTimeOffset? toObservedAtUtc, int resolutionSeconds, DateTimeOffset? afterBucketStartUtc, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatTimelineBucket>>([]);
        public Task<IReadOnlyList<ThreatContactAggregate>> ListThreatContactsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc, DateTimeOffset? toObservedAtUtc, DateTimeOffset? afterLastObservedAtUtc, string? afterContactId, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatContactAggregate>>([]);
        public Task<long> CountThreatContactsAsync(string tenantId, string campaignId, DateTimeOffset watermarkUtc, DateTimeOffset? fromObservedAtUtc = null, DateTimeOffset? toObservedAtUtc = null, CancellationToken cancellationToken = default) => Task.FromResult(0L);
        public Task EnqueueTemporalCorrelationWorkAsync(TemporalCorrelationWorkItem item, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<TemporalCorrelationWorkItem>> LeaseTemporalCorrelationWorkAsync(string leaseOwner, DateTimeOffset nowUtc, TimeSpan leaseDuration, int take, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<TemporalCorrelationWorkItem>>([]);
        public Task CompleteTemporalCorrelationWorkAsync(string workId, string leaseOwner, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task FailTemporalCorrelationWorkAsync(string workId, string leaseOwner, DateTimeOffset retryAtUtc, string error, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<int> SweepTemporalThreatDataAsync(DateTimeOffset detailBeforeUtc, DateTimeOffset aggregateBeforeUtc, CancellationToken cancellationToken = default) => Task.FromResult(0);
        public Task<string?> GetTemporalBackfillCursorAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task SaveTemporalBackfillCursorAsync(string? campaignId, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task AppendAuditAsync(string actor, string action, string? target, string result, string? detailJson, string? sourceIp) => Task.CompletedTask;
        public Task<IReadOnlyList<AuditLogEntry>> ListAuditAsync(int take) => Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());
        public Task<AgentPolicy> GetActivePolicyAsync(string? agentId = null) => Task.FromResult(new AgentPolicy());
        public Task UpsertPolicyAsync(AgentPolicy policy) => Task.CompletedTask;
        public Task<string?> IssueAgentApiKeyAsync(string agentId, bool rotate) => Task.FromResult<string?>(null);
        public Task SetAgentApiKeyHashAsync(string agentId, string keyHash) => Task.CompletedTask;
        public Task<string?> FindAgentIdByApiKeyHashAsync(string keyHash) => Task.FromResult<string?>(null);
        public Task UpdateAgentIntegrityAsync(string agentId, string? binarySha256, bool? isSigned, int? policyVersion) => Task.CompletedTask;
        public Task SaveAgentMetricsAsync(AgentHeartbeat hb) => Task.CompletedTask;
        public Task<IReadOnlyList<AgentMetricsSample>> ListAgentMetricsAsync(string agentId, int take = 60) =>
            Task.FromResult<IReadOnlyList<AgentMetricsSample>>(Array.Empty<AgentMetricsSample>());
        public Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60, string? tenantId = null) => Task.FromResult<AgentInventoryItem?>(null);
        public Task<IReadOnlyList<CustomerTenant>> ListTenantsAsync() =>
            Task.FromResult<IReadOnlyList<CustomerTenant>>(Array.Empty<CustomerTenant>());
        public Task<CustomerTenant?> GetTenantAsync(string tenantId) => Task.FromResult<CustomerTenant?>(null);
        public Task UpsertTenantAsync(CustomerTenant tenant) => Task.CompletedTask;
        public Task<IReadOnlyList<TenantAgentAssignment>> ListAgentAssignmentsAsync() =>
            Task.FromResult<IReadOnlyList<TenantAgentAssignment>>(Array.Empty<TenantAgentAssignment>());
        public Task AssignAgentToTenantAsync(string tenantId, string agentId) => Task.CompletedTask;
        public Task<IReadOnlyList<SecurityReportRecord>> ListReportsAsync(string tenantId, int take) =>
            Task.FromResult<IReadOnlyList<SecurityReportRecord>>(Array.Empty<SecurityReportRecord>());
        public Task<SecurityReportRecord?> GetReportAsync(string tenantId, string reportId) => Task.FromResult<SecurityReportRecord?>(null);
        public Task UpsertReportAsync(SecurityReportRecord report) => Task.CompletedTask;
        public Task<IReadOnlyList<ReportTemplateDefinition>> ListReportTemplatesAsync(string tenantId) =>
            Task.FromResult<IReadOnlyList<ReportTemplateDefinition>>(Array.Empty<ReportTemplateDefinition>());
        public Task<ReportTemplateDefinition?> GetReportTemplateAsync(string tenantId, string templateId) =>
            Task.FromResult<ReportTemplateDefinition?>(null);
        public Task UpsertReportTemplateAsync(string tenantId, ReportTemplateDefinition template) => Task.CompletedTask;
        public Task<bool> TryUpdateReportTemplateAsync(
            string tenantId,
            ReportTemplateDefinition template,
            int expectedVersion) => Task.FromResult(false);
        public Task<bool> DeleteReportTemplateAsync(string tenantId, string templateId) => Task.FromResult(false);
        public Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId) =>
            Task.FromResult<IReadOnlyList<TenantAsset>>(Array.Empty<TenantAsset>());
        public Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId) => Task.FromResult<TenantAsset?>(null);
        public Task UpsertAssetAsync(string tenantId, TenantAsset asset) => Task.CompletedTask;
        public Task<bool> DeleteAssetAsync(string tenantId, string assetId) => Task.FromResult(false);
        public Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId) =>
            Task.FromResult<IReadOnlyList<TopologyDocument>>(Array.Empty<TopologyDocument>());
        public Task<TopologyDocument?> GetTopologyAsync(string tenantId, string topologyId) => Task.FromResult<TopologyDocument?>(null);
        public Task UpsertTopologyAsync(string tenantId, TopologyDocument topology) => Task.CompletedTask;
        public Task<bool> DeleteTopologyAsync(string tenantId, string topologyId) => Task.FromResult(false);
        public Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId) =>
            Task.FromResult<IReadOnlyList<DetectionWorkflow>>(Array.Empty<DetectionWorkflow>());
        public Task<DetectionWorkflow?> GetWorkflowAsync(string tenantId, string workflowId) => Task.FromResult<DetectionWorkflow?>(null);
        public Task UpsertWorkflowAsync(string tenantId, DetectionWorkflow workflow) => Task.CompletedTask;
        public Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId) => Task.FromResult(false);
    }
}
