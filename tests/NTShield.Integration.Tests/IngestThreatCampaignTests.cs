using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.Services;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class IngestThreatCampaignTests
{
    [Fact]
    public async Task Ingested_Alert_Becomes_Incident_And_Threat_Campaign()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);
        var correlationOptions = Options.Create(new CorrelationOptions { TimestampToleranceSeconds = 120 });
        var tracker = new LateralMovementTracker(
            correlationOptions,
            NullLogger<LateralMovementTracker>.Instance,
            store);
        var correlator = new CrossHostCorrelator(
            store,
            correlationOptions,
            NullLogger<CrossHostCorrelator>.Instance);
        var ingest = new IngestService(
            store,
            correlator,
            tracker,
            NullLogger<IngestService>.Instance);

        try
        {
            await store.InitializeAsync();
            await tracker.LoadAsync();

            var response = await ingest.IngestAsync(new AgentIngestBatch
            {
                AgentId = "agent-dest",
                ComputerName = "DEST-01",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "agent-dest",
                        ComputerName = "DEST-01",
                        EventId = 4625,
                        TimestampUtc = DateTimeOffset.UtcNow,
                        SourceIp = "203.0.113.10",
                        DestinationIp = "10.0.0.20",
                        EventRecordId = 42
                    }
                ],
                Alerts =
                [
                    new DetectionAlert
                    {
                        AlertId = "alert-1",
                        TimestampUtc = DateTimeOffset.UtcNow,
                        ComputerName = "DEST-01",
                        AgentId = "agent-dest",
                        RuleId = "INTERNAL_PASSWORD_SPRAY",
                        RuleName = "Internal Password Spray",
                        Title = "Internal Password Spray",
                        Severity = Severity.High,
                        SourceIp = "10.0.0.10",
                        EventCount = 24
                    }
                ]
            }, CancellationToken.None);

            Assert.True(response.Accepted);
            Assert.Equal("alert-alert-1", Assert.Single(response.CreatedIncidentIds));
            var storedIncident = Assert.Single(await store.ListIncidentsAsync(10, "default"));
            Assert.Null(storedIncident.SourceAgentId);
            Assert.Equal("agent-dest", storedIncident.DestinationAgentId);
            var threatEvents = await store.ListSecurityEventsAsync(10);
            Assert.Contains(threatEvents, item =>
                item.SourceIp == "203.0.113.10" &&
                item.EventId == 4625 &&
                item.EventRecordId == 42);
            Assert.Contains(tracker.ListCampaigns(), campaign =>
                campaign.InvolvedIps.Contains("10.0.0.10") &&
                campaign.InvolvedHosts.Contains("DEST-01"));

            var suppressed = await ingest.IngestAsync(new AgentIngestBatch
            {
                AgentId = "agent-dest",
                ComputerName = "DEST-01",
                Alerts =
                [
                    new DetectionAlert
                    {
                        AlertId = "suppressed-1",
                        AgentId = "agent-dest",
                        ComputerName = "DEST-01",
                        RuleId = "SUPPRESSED_RULE",
                        Severity = Severity.Critical,
                        Suppressed = true,
                        SourceIp = "198.51.100.20"
                    }
                ]
            }, CancellationToken.None);

            Assert.True(suppressed.Accepted);
            Assert.Empty(suppressed.CreatedIncidentIds);
            Assert.Single(await store.ListIncidentsAsync(10, "default"));
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var path = databasePath + suffix;
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }
}
