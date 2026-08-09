using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.Security;
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
                }, tenantId);
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
                }, tenantId);
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
            }, "default");

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

    [Fact]
    public async Task Reassignment_Does_Not_Move_History_And_CrossTenant_Incident_Id_Cannot_Overwrite()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-history-{Guid.NewGuid():N}.db");
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
                    Name = tenantId,
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }

            await store.RegisterAgentAsync(new AgentRegistrationRequest
            {
                AgentId = "agent-moving",
                TenantId = "alpha",
                ComputerName = "MOVING-01"
            });
            var originalTime = DateTimeOffset.UtcNow.AddMinutes(-2);
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "agent-moving",
                ComputerName = "MOVING-01",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "agent-moving",
                        ComputerName = "MOVING-01",
                        EventId = 4625,
                        TimestampUtc = originalTime,
                        EventRecordId = 101
                    }
                ]
            }, "alpha");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "shared-incident-id",
                Title = "alpha original",
                SourceAgentId = "agent-moving",
                Severity = Severity.High,
                FirstSeenUtc = originalTime,
                LastSeenUtc = originalTime
            }, "alpha");

            await store.AssignAgentToTenantAsync("beta", "agent-moving");
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "agent-moving",
                ComputerName = "MOVING-01",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "agent-moving",
                        ComputerName = "MOVING-01",
                        EventId = 4624,
                        TimestampUtc = originalTime.AddMinutes(1),
                        EventRecordId = 103
                    }
                ]
            }, "beta");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "beta-new-incident",
                Title = "beta new",
                SourceAgentId = "agent-moving",
                Severity = Severity.Low,
                FirstSeenUtc = originalTime.AddMinutes(1),
                LastSeenUtc = originalTime.AddMinutes(1)
            }, "beta");
            await store.UpsertIncidentAsync(new Incident
            {
                IncidentId = "shared-incident-id",
                Title = "beta overwrite attempt",
                SourceAgentId = "agent-moving",
                Severity = Severity.Critical,
                FirstSeenUtc = DateTimeOffset.UtcNow,
                LastSeenUtc = DateTimeOffset.UtcNow.AddMinutes(1)
            }, "beta");

            Assert.Equal(101, Assert.Single(await store.ListSecurityEventsAsync(10, "alpha")).EventRecordId);
            Assert.Equal(103, Assert.Single(await store.ListSecurityEventsAsync(10, "beta")).EventRecordId);
            var original = await store.GetIncidentAsync("shared-incident-id", "alpha");
            Assert.NotNull(original);
            Assert.Equal("alpha original", original!.Title);
            Assert.Equal(Severity.High, original.Severity);
            Assert.Equal(originalTime, original.LastSeenUtc);
            Assert.Null(await store.GetIncidentAsync("shared-incident-id", "beta"));
            Assert.Equal("beta new", (await store.GetIncidentAsync("beta-new-incident", "beta"))?.Title);

            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "syslog",
                ComputerName = "edge-router",
                SecurityEvents =
                [
                    new SecurityEventRecord
                    {
                        AgentId = "syslog",
                        ComputerName = "edge-router",
                        EventId = 0,
                        Channel = "Syslog",
                        TimestampUtc = DateTimeOffset.UtcNow,
                        EventRecordId = 102
                    }
                ]
            }, "default");
            Assert.Contains(await store.ListSecurityEventsAsync(10, "default"), item =>
                item.AgentId == "syslog" && item.TenantId == "default");
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
    public async Task Authenticated_Agent_Cannot_Spoof_Nested_Agent_Id()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-bind-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);
        var resolver = new IngestTenantResolver(store);
        var context = new DefaultHttpContext();
        context.Items[ApiKeyAuthMiddleware.AgentIdItem] = "authenticated-agent";
        var batch = new AgentIngestBatch
        {
            AgentId = "authenticated-agent",
            SecurityEvents = [new SecurityEventRecord { AgentId = "different-agent" }]
        };

        await Assert.ThrowsAsync<IngestIdentityException>(() => resolver.ResolveAndBindAsync(context, batch));
    }

    [Fact]
    public void Authenticated_Agent_Cannot_Spoof_Legacy_Heartbeat_Identity()
    {
        var context = new DefaultHttpContext();
        context.Items[ApiKeyAuthMiddleware.AgentIdItem] = "authenticated-agent";

        Assert.Throws<IngestIdentityException>(() =>
            IngestTenantResolver.ResolveBoundAgentId(context, "different-agent"));
        Assert.Equal(
            "authenticated-agent",
            IngestTenantResolver.ResolveBoundAgentId(context, "authenticated-agent"));
    }

    [Fact]
    public async Task Response_Actions_Are_Server_Id_And_Tenant_Bound_Through_Reassignment()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-action-tenant-{Guid.NewGuid():N}.db");
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
                    Name = tenantId,
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }
            await store.RegisterAgentAsync(new AgentRegistrationRequest
            {
                AgentId = "agent-alpha",
                TenantId = "alpha",
                ComputerName = "ALPHA-01"
            });
            await store.RegisterAgentAsync(new AgentRegistrationRequest
            {
                AgentId = "agent-beta",
                TenantId = "beta",
                ComputerName = "BETA-01"
            });

            var service = new ActionService(store, NullLogger<ActionService>.Instance);
            Assert.Null(await service.EnqueueForTenantAsync(new ResponseActionRequest
            {
                TargetAgentId = "agent-beta",
                ActionType = "CollectDiagnostics",
                Approved = true
            }, "alpha"));
            Assert.Null(await service.EnqueueForTenantAsync(new ResponseActionRequest
            {
                ActionType = "CollectDiagnostics",
                Approved = true
            }, "alpha"));

            var saved = await service.EnqueueForTenantAsync(new ResponseActionRequest
            {
                RequestId = "client-controlled-id",
                TargetAgentId = "agent-alpha",
                ActionType = "CollectDiagnostics",
                Approved = true
            }, "alpha");
            Assert.NotNull(saved);
            Assert.NotEqual("client-controlled-id", saved!.RequestId);
            Assert.Equal("alpha", saved.TenantId);
            Assert.NotNull(await service.GetForTenantAsync(saved.RequestId, "alpha"));
            Assert.Null(await service.GetForTenantAsync(saved.RequestId, "beta"));

            var legacy = new ResponseActionRequest
            {
                RequestId = "legacy-without-tenant",
                TargetAgentId = "agent-alpha",
                ActionType = "CollectDiagnostics",
                Approved = true
            };
            await store.SavePendingActionAsync(legacy, "agent-alpha");
            Assert.Null(await service.GetForTenantAsync(legacy.RequestId, "alpha"));

            // A queued action owned by the old tenant must not execute after the
            // endpoint is reassigned, even though the physical agent id is stable.
            await store.AssignAgentToTenantAsync("beta", "agent-alpha");
            Assert.Empty(await service.GetPendingForAgentAsync("agent-alpha"));

            var afterMove = await service.EnqueueForTenantAsync(new ResponseActionRequest
            {
                TargetAgentId = "agent-alpha",
                ActionType = "CollectDiagnostics",
                Approved = true
            }, "beta");
            Assert.NotNull(afterMove);
            Assert.Equal("beta", Assert.Single(await service.GetPendingForAgentAsync("agent-alpha")).TenantId);

            var concurrent = await service.EnqueueForTenantAsync(new ResponseActionRequest
            {
                TargetAgentId = "agent-alpha",
                ActionType = "CollectDiagnostics",
                Approved = true
            }, "beta");
            Assert.NotNull(concurrent);
            var secondStore = new SqliteCentralStore(
                Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
                NullLogger<SqliteCentralStore>.Instance);
            var claims = await Task.WhenAll(
                store.TakePendingActionsAsync("agent-alpha"),
                secondStore.TakePendingActionsAsync("agent-alpha"));
            Assert.Single(claims.SelectMany(items => items));
            Assert.Equal(concurrent!.RequestId, claims.SelectMany(items => items).Single().RequestId);
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
    public async Task CrossHost_Correlation_Does_Not_Use_Another_Tenants_Outbound_Process()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ntshield-outbound-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);

        try
        {
            await store.InitializeAsync();
            var now = DateTimeOffset.UtcNow;
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "alpha-origin",
                ComputerName = "ALPHA-ORIGIN",
                NetworkConnections =
                [
                    new NetworkConnectionRecord
                    {
                        AgentId = "alpha-origin",
                        ComputerName = "ALPHA-ORIGIN",
                        TimestampUtc = now,
                        LocalAddress = "10.0.0.10",
                        RemoteAddress = "10.0.0.20",
                        RemotePort = 445,
                        ProcessId = 777,
                        ProcessName = "alpha-secret.exe",
                        IsNew = true
                    }
                ]
            }, "alpha");

            Assert.Equal("alpha", Assert.Single(await store.FindOutboundAsync(
                "10.0.0.20", 445, now.AddMinutes(-1), now.AddMinutes(1), "alpha")).TenantId);
            Assert.Empty(await store.FindOutboundAsync(
                "10.0.0.20", 445, now.AddMinutes(-1), now.AddMinutes(1), "beta"));

            var batch = new AgentIngestBatch
            {
                AgentId = "beta-destination",
                ComputerName = "BETA-DEST",
                SecurityEvents = Enumerable.Range(1, 5).Select(index => new SecurityEventRecord
                {
                    AgentId = "beta-destination",
                    ComputerName = "BETA-DEST",
                    EventId = 4625,
                    TimestampUtc = now.AddSeconds(index),
                    SourceIp = "10.0.0.10",
                    DestinationIp = "10.0.0.20",
                    DestinationPort = 445,
                    EventRecordId = index
                }).ToList()
            };
            var correlator = new CrossHostCorrelator(
                store,
                Options.Create(new CorrelationOptions { TimestampToleranceSeconds = 120 }),
                NullLogger<CrossHostCorrelator>.Instance);

            var incident = Assert.Single(await correlator.CorrelateAsync(
                batch, CancellationToken.None, "beta"));
            Assert.Equal("beta", incident.TenantId);
            Assert.Null(incident.SourceAgentId);
            Assert.Null(incident.ProcessName);
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
    public void Csv_Export_Neutralizes_Spreadsheet_Formulas()
    {
        var report = new SecurityReportRecord
        {
            CustomerName = "=WEBSERVICE(\"https://example.invalid\")",
            PriorityIncidents =
            [
                new SecurityReportIncident
                {
                    IncidentId = "\t=cmd|' /C calc'!A0",
                    Title = "  +SUM(1,1)",
                    SourceIp = "\r@malicious",
                    DestinationIp = "\n-1+1"
                }
            ]
        };

        var csv = TenantReportService.RenderCsv(report);

        Assert.Contains("\"'=WEBSERVICE(\"\"https://example.invalid\"\")\"", csv);
        Assert.Contains("\"'\t=cmd|' /C calc'!A0\"", csv);
        Assert.Contains("\"'  +SUM(1,1)\"", csv);
        Assert.Contains("\"'\r@malicious\"", csv);
        Assert.Contains("\"'\n-1+1\"", csv);
    }
}
