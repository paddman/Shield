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

public sealed class DashboardSummaryTests
{
    [Fact]
    public async Task Overview_Aggregate_Bounds_Event_Count_But_Retains_Lifetime_Incident_And_Feed_Freshness()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-dashboard-aggregate-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);

        try
        {
            await store.InitializeAsync();
            var now = DateTimeOffset.UtcNow;
            var recentEventAt = now.AddMinutes(-30);
            var oldConnectionAt = now.AddHours(-36);
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "agent-alpha",
                ComputerName = "ALPHA-01",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "agent-alpha",
                        ComputerName = "ALPHA-01",
                        EventId = 4625,
                        EventRecordId = 1,
                        TimestampUtc = now.AddHours(-48)
                    },
                    new SecurityEventRecord
                    {
                        AgentId = "agent-alpha",
                        ComputerName = "ALPHA-01",
                        EventId = 4624,
                        EventRecordId = 2,
                        TimestampUtc = recentEventAt.ToOffset(TimeSpan.FromHours(7))
                    },
                    new SecurityEventRecord
                    {
                        AgentId = "agent-alpha",
                        ComputerName = "ALPHA-01",
                        EventId = 4688,
                        EventRecordId = 3,
                        TimestampUtc = now.AddHours(1)
                    }
                ],
                NetworkConnections =
                [
                    new NetworkConnectionRecord
                    {
                        AgentId = "agent-alpha",
                        ComputerName = "ALPHA-01",
                        LocalAddress = "10.0.0.10",
                        RemoteAddress = "10.0.0.20",
                        RemotePort = 443,
                        TimestampUtc = oldConnectionAt.ToOffset(TimeSpan.FromHours(-5)),
                        IsNew = true
                    }
                ]
            }, "alpha");
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "agent-beta",
                ComputerName = "BETA-01",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "agent-beta",
                        ComputerName = "BETA-01",
                        EventId = 4625,
                        EventRecordId = 1,
                        TimestampUtc = now.AddMinutes(-5)
                    }
                ],
                NetworkConnections =
                [
                    new NetworkConnectionRecord
                    {
                        AgentId = "agent-beta",
                        ComputerName = "BETA-01",
                        LocalAddress = "10.1.0.10",
                        RemoteAddress = "10.1.0.20",
                        RemotePort = 443,
                        TimestampUtc = now.AddMinutes(-5),
                        IsNew = true
                    }
                ]
            }, "beta");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "old-open-incident",
                TenantId = "alpha",
                Title = "Still open",
                Severity = Severity.High,
                Status = "Open",
                SourceHost = "ALPHA-01",
                SourceAgentId = " ",
                DestinationIp = "10.0.0.20",
                FirstSeenUtc = now.AddDays(-31),
                LastSeenUtc = now.AddDays(-30)
            }, "alpha");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "beta-open-incident",
                TenantId = "beta",
                Title = "Other tenant",
                Severity = Severity.Critical,
                Status = "Open",
                SourceHost = "BETA-01",
                FirstSeenUtc = now.AddMinutes(-10),
                LastSeenUtc = now.AddMinutes(-5)
            }, "beta");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "alpha-resolved-incident",
                TenantId = "alpha",
                Title = "Resolved",
                Severity = Severity.Critical,
                Status = " Resolved ",
                SourceHost = "ALPHA-02",
                FirstSeenUtc = now.AddHours(-2),
                LastSeenUtc = now.AddHours(-1)
            }, "alpha");

            var aggregate = await store.GetDashboardOverviewAggregateAsync(
                " ALPHA ", now.AddHours(-24), now);

            Assert.Equal(1, aggregate.ThreatEvents);
            Assert.Equal(2, aggregate.Incidents);
            Assert.Equal(1, aggregate.OpenIncidents);
            Assert.Equal(1, aggregate.HighOpenIncidents);
            Assert.Equal(0, aggregate.CriticalOpenIncidents);
            Assert.Equal(2, aggregate.AffectedAssets);
            Assert.Equal(recentEventAt, aggregate.LatestEventAtUtc);
            Assert.Equal(oldConnectionAt, aggregate.LatestConnectionAtUtc);
            Assert.Equal(TimeSpan.Zero, aggregate.LatestEventAtUtc?.Offset);
            Assert.Equal(TimeSpan.Zero, aggregate.LatestConnectionAtUtc?.Offset);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                store.GetDashboardOverviewAggregateAsync(
                    "alpha", now.AddHours(-24), now, new CancellationToken(canceled: true)));
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

    [Fact]
    public async Task Fresh_Heartbeat_Does_Not_Mask_Missing_Event_And_Network_Feeds()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-dashboard-freshness-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);

        try
        {
            await store.InitializeAsync();
            await store.UpsertTenantAsync(new CustomerTenant
            {
                TenantId = "alpha",
                Name = "Alpha",
                CreatedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });
            await store.RegisterAgentAsync(new AgentRegistrationRequest
            {
                AgentId = "agent-alpha",
                TenantId = "alpha",
                ComputerName = "ALPHA-01"
            });
            await store.UpsertAgentAsync(new AgentHeartbeat
            {
                AgentId = "agent-alpha",
                ComputerName = "ALPHA-01",
                TimestampUtc = DateTimeOffset.UtcNow
            });

            var tracker = new LateralMovementTracker(
                Options.Create(new CorrelationOptions()),
                NullLogger<LateralMovementTracker>.Instance,
                store);
            var summary = await new DashboardSummaryService(store, tracker).GetAsync("alpha", "24h");

            Assert.Equal("unknown", summary.Telemetry.State);
            Assert.Null(summary.Telemetry.FreshnessSeconds);
            Assert.NotNull(summary.Telemetry.HeartbeatFreshnessSeconds);
            Assert.Contains("security_events_missing", summary.Telemetry.VisibilityGaps);
            Assert.Contains("network_connections_missing", summary.Telemetry.VisibilityGaps);
            Assert.Equal("elevated", summary.Posture.State);
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

    [Fact]
    public async Task Summary_Uses_Exact_Totals_And_Bounds_The_Action_Queue()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-dashboard-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);

        try
        {
            await store.InitializeAsync();
            await store.UpsertTenantAsync(new CustomerTenant
            {
                TenantId = "alpha",
                Name = "Alpha",
                CreatedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });
            await store.RegisterAgentAsync(new AgentRegistrationRequest
            {
                AgentId = "agent-alpha",
                TenantId = "alpha",
                ComputerName = "ALPHA-01"
            });

            var now = DateTimeOffset.UtcNow;
            Incident? critical = null;
            for (var index = 0; index < 130; index++)
            {
                var incident = new Incident
                {
                    TenantId = "alpha",
                    IncidentId = $"dashboard-{index:D3}",
                    Title = $"Measured incident {index}",
                    Severity = index == 0 ? Severity.Critical : Severity.Low,
                    Status = "Open",
                    SourceAgentId = "agent-alpha",
                    SourceHost = "ALPHA-01",
                    SourceIp = "10.10.0.10",
                    DestinationIp = $"10.20.{index / 250}.{index % 250 + 1}",
                    FirstSeenUtc = now.AddMinutes(-index - 1),
                    LastSeenUtc = now.AddMinutes(-index)
                };
                await store.UpsertIncidentAsync(incident, "alpha");
                if (index == 0) critical = incident;
            }
            await store.UpsertIncidentAsync(new Incident
            {
                TenantId = "alpha",
                IncidentId = "dashboard-midnight-boundary",
                Title = "UTC day boundary",
                Severity = Severity.Low,
                Status = "Open",
                SourceAgentId = "agent-alpha",
                DestinationIp = "10.30.0.1",
                FirstSeenUtc = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero),
                LastSeenUtc = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero)
            }, "alpha");
            await store.UpsertIncidentAsync(new Incident
            {
                TenantId = "alpha",
                IncidentId = "dashboard-future-clock-skew",
                Title = "Future clock skew",
                Severity = Severity.Low,
                Status = "Open",
                SourceAgentId = "agent-alpha",
                DestinationIp = "10.30.0.2",
                FirstSeenUtc = now.AddDays(1),
                LastSeenUtc = now.AddDays(1)
            }, "alpha");

            var tracker = new LateralMovementTracker(
                Options.Create(new CorrelationOptions()),
                NullLogger<LateralMovementTracker>.Instance,
                store);
            tracker.IngestIncidents([Assert.IsType<Incident>(critical)], "alpha");
            var service = new DashboardSummaryService(store, tracker);

            var summary = await service.GetAsync(" ALPHA ", "24h");

            Assert.Equal(132, summary.Counts.IncidentsTotal);
            Assert.Equal(132, summary.Counts.OpenIncidents);
            Assert.Equal(1, summary.Counts.CriticalOpen);
            Assert.Equal(133, summary.Counts.AffectedAssets);
            Assert.Equal("critical", summary.Posture.State);
            Assert.Equal(131, summary.Trends.Sum(bucket => bucket.Incidents));
            Assert.InRange(summary.ThreatQueue.Count, 1, 20);
            Assert.Contains(summary.ThreatQueue, item => item.CampaignId is not null);
            Assert.DoesNotContain(summary.ThreatQueue, item => item.Kind == "incident" && item.IncidentId == critical!.IncidentId);
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
