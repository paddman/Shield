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

public sealed class TenantIsolationTests
{
    [Fact]
    public async Task Agents_Events_Incidents_And_Reports_Are_Tenant_Scoped()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-tenant-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);

        try
        {
            await store.InitializeAsync();
            foreach (var tenantId in new[] { "alpha", "beta" })
            {
                await store.UpsertTenantAsync(new CustomerTenant
                {
                    TenantId = tenantId,
                    Name = tenantId.ToUpperInvariant(),
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
                await store.RegisterAgentAsync(new AgentRegistrationRequest
                {
                    AgentId = $"agent-{tenantId}",
                    TenantId = tenantId,
                    ComputerName = $"HOST-{tenantId.ToUpperInvariant()}"
                });
                await store.SaveBatchAsync(new AgentIngestBatch
                {
                    AgentId = $"agent-{tenantId}",
                    ComputerName = $"HOST-{tenantId.ToUpperInvariant()}",
                    SecurityEvents =
                    [
                        new SecurityEventRecord
                        {
                            AgentId = $"agent-{tenantId}",
                            ComputerName = $"HOST-{tenantId.ToUpperInvariant()}",
                            EventId = 4625,
                            SourceIp = tenantId == "alpha" ? "203.0.113.10" : "198.51.100.20",
                            TimestampUtc = DateTimeOffset.UtcNow,
                            EventRecordId = tenantId == "alpha" ? 1 : 2
                        }
                    ]
                });
                await store.UpsertIncidentAsync(new Incident
                {
                    IncidentId = $"incident-{tenantId}",
                    SourceAgentId = $"agent-{tenantId}",
                    SourceHost = $"HOST-{tenantId.ToUpperInvariant()}",
                    SourceIp = tenantId == "alpha" ? "203.0.113.10" : "198.51.100.20",
                    DestinationIp = "10.0.0.10",
                    Severity = Severity.High,
                    Title = $"{tenantId} incident",
                    FirstSeenUtc = DateTimeOffset.UtcNow,
                    LastSeenUtc = DateTimeOffset.UtcNow
                });
            }

            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "legacy-unmapped",
                SourceAgentId = "retired-agent",
                SourceHost = "LEGACY-HOST",
                Severity = Severity.Medium,
                Title = "Legacy incident without tenant assignment",
                FirstSeenUtc = DateTimeOffset.UtcNow,
                LastSeenUtc = DateTimeOffset.UtcNow
            });

            Assert.All(await store.ListAgentsAsync("alpha"), item =>
                Assert.Equal("agent-alpha", Assert.IsType<AgentInventoryItem>(item).AgentId));
            Assert.All(await store.ListSecurityEventsAsync(50, "alpha"), item =>
                Assert.Equal("agent-alpha", item.AgentId));
            Assert.All(await store.ListIncidentsAsync(50, "alpha"), item =>
                Assert.Equal("incident-alpha", item.IncidentId));
            Assert.Contains(await store.ListIncidentsAsync(50, "default"), item =>
                item.IncidentId == "legacy-unmapped");
            Assert.Null(await store.GetIncidentAsync("legacy-unmapped", "alpha"));
            Assert.NotNull(await store.GetIncidentAsync("legacy-unmapped", "default"));

            var tracker = new LateralMovementTracker(
                Options.Create(new CorrelationOptions()),
                NullLogger<LateralMovementTracker>.Instance,
                store);
            var reportService = new TenantReportService(store, tracker);
            var report = await reportService.GenerateAsync("alpha", new CreateSecurityReportRequest
            {
                PeriodStartUtc = DateTimeOffset.UtcNow.AddDays(-1),
                PeriodEndUtc = DateTimeOffset.UtcNow.AddMinutes(1)
            });
            Assert.Equal(1, report.Metrics.Agents);
            Assert.Equal(1, report.Metrics.ThreatEvents);
            Assert.Equal(1, report.Metrics.Incidents);
            Assert.NotNull(await store.GetReportAsync("alpha", report.ReportId));
            Assert.Null(await store.GetReportAsync("beta", report.ReportId));
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
