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

    private sealed class NullCentralStore : ICentralStore
    {
        public Task InitializeAsync() => Task.CompletedTask;
        public Task RegisterAgentAsync(AgentRegistrationRequest req) => Task.CompletedTask;
        public Task UpsertAgentAsync(AgentHeartbeat hb) => Task.CompletedTask;
        public Task<bool> HasIdempotencyKeyAsync(string key) => Task.FromResult(false);
        public Task SaveIdempotencyKeyAsync(string key) => Task.CompletedTask;
        public Task SaveBatchAsync(AgentIngestBatch batch) => Task.CompletedTask;
        public Task UpsertIncidentAsync(Incident incident) => Task.CompletedTask;
        public Task<IReadOnlyList<Incident>> ListIncidentsAsync(int take) => Task.FromResult<IReadOnlyList<Incident>>(Array.Empty<Incident>());
        public Task<Incident?> GetIncidentAsync(string id) => Task.FromResult<Incident?>(null);
        public Task<IReadOnlyList<object>> ListAgentsAsync() => Task.FromResult<IReadOnlyList<object>>(Array.Empty<object>());
        public Task<IReadOnlyList<NetworkConnectionRecord>> FindOutboundAsync(string remoteIp, int? remotePort, DateTimeOffset from, DateTimeOffset to) =>
            Task.FromResult<IReadOnlyList<NetworkConnectionRecord>>(Array.Empty<NetworkConnectionRecord>());
        public Task SavePendingActionAsync(ResponseActionRequest request, string agentKey) => Task.CompletedTask;
        public Task<List<ResponseActionRequest>> TakePendingActionsAsync(string agentId) => Task.FromResult(new List<ResponseActionRequest>());
        public Task<ResponseActionRequest?> GetPendingActionAsync(string requestId) => Task.FromResult<ResponseActionRequest?>(null);
        public Task UpsertCampaignJsonAsync(string campaignId, string json) => Task.CompletedTask;
        public Task<IReadOnlyList<(string Id, string Json)>> ListCampaignJsonAsync(int take) =>
            Task.FromResult<IReadOnlyList<(string, string)>>(Array.Empty<(string, string)>());
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
        public Task<AgentInventoryItem?> GetAgentAsync(string agentId, int metricsTake = 60) => Task.FromResult<AgentInventoryItem?>(null);
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
