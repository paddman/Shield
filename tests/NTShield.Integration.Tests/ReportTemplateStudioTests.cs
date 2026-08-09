using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.Services;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class ReportTemplateStudioTests
{
    [Fact]
    public async Task Custom_Templates_Are_Tenant_Isolated_And_BuiltIns_Are_ReadOnly()
    {
        var (store, path) = await CreateStoreAsync();
        try
        {
            await AddTenantAsync(store, "alpha");
            await AddTenantAsync(store, "beta");
            var service = new ReportTemplateService(store);

            var alphaBuiltIns = (await service.ListAsync("alpha")).Where(item => item.IsBuiltIn).ToList();
            Assert.True(alphaBuiltIns.Count >= 5);
            Assert.All(alphaBuiltIns, item => Assert.Equal("alpha", item.TenantId));
            await Assert.ThrowsAsync<ReportTemplateReadOnlyException>(() =>
                service.UpdateAsync("alpha", ReportTemplateService.DefaultTemplateId, ValidTemplate("change")));
            await Assert.ThrowsAsync<ReportTemplateReadOnlyException>(() =>
                service.DeleteAsync("alpha", ReportTemplateService.DefaultTemplateId));

            var created = await service.CreateAsync("alpha", ValidTemplate("Alpha custom"));
            Assert.Equal("alpha", created.TenantId);
            Assert.False(created.IsBuiltIn);
            Assert.Null(await service.GetAsync("beta", created.TemplateId));
            Assert.DoesNotContain(await service.ListAsync("beta"), item => item.TemplateId == created.TemplateId);

            var updated = await service.UpdateAsync("alpha", created.TemplateId, ValidTemplate("Alpha v2"));
            Assert.NotNull(updated);
            Assert.Equal(2, updated!.Version);
            Assert.Equal("Alpha v2", updated.Name);

            var stale = ValidTemplate("Stale overwrite");
            stale.Version = 1;
            var conflict = await Assert.ThrowsAsync<ReportTemplateVersionConflictException>(() =>
                service.UpdateAsync("alpha", created.TemplateId, stale));
            Assert.Equal(2, conflict.CurrentVersion);
            Assert.Equal("Alpha v2", (await service.GetAsync("alpha", created.TemplateId))?.Name);

            var duplicate = await service.DuplicateAsync(
                "alpha", ReportTemplateService.DefaultTemplateId, "Executive customer copy");
            Assert.NotNull(duplicate);
            Assert.False(duplicate!.IsBuiltIn);
            Assert.Equal("Executive customer copy", duplicate.Name);
            Assert.False(await service.DeleteAsync("beta", duplicate.TemplateId));
            Assert.True(await service.DeleteAsync("alpha", duplicate.TemplateId));

            var longName = await service.CreateAsync("alpha", ValidTemplate(new string('N', 100)));
            var longNameCopy = await service.DuplicateAsync("alpha", longName.TemplateId, null);
            Assert.NotNull(longNameCopy);
            Assert.Equal(100, longNameCopy!.Name.Length);
            Assert.EndsWith(" Copy", longNameCopy.Name);

            var alphaShared = ValidTemplate("Alpha shared");
            alphaShared.TemplateId = "tpl-shared-composite";
            alphaShared.TenantId = "alpha";
            var betaShared = ValidTemplate("Beta shared");
            betaShared.TemplateId = "tpl-shared-composite";
            betaShared.TenantId = "beta";
            await store.UpsertReportTemplateAsync("alpha", alphaShared);
            await store.UpsertReportTemplateAsync("beta", betaShared);
            Assert.Equal("Alpha shared", (await store.GetReportTemplateAsync("alpha", "tpl-shared-composite"))?.Name);
            Assert.Equal("Beta shared", (await store.GetReportTemplateAsync("beta", "tpl-shared-composite"))?.Name);
            Assert.True(await store.DeleteReportTemplateAsync("alpha", "tpl-shared-composite"));
            Assert.NotNull(await store.GetReportTemplateAsync("beta", "tpl-shared-composite"));
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task Validation_Rejects_Executable_Sources_Unsupported_Types_And_Unbounded_Layouts()
    {
        var (store, path) = await CreateStoreAsync();
        try
        {
            await AddTenantAsync(store, "alpha");
            var service = new ReportTemplateService(store);

            var query = ValidTemplate("Query attempt");
            query.Blocks[0].DataSourceId = "SELECT * FROM incidents";
            await Assert.ThrowsAsync<TopologyValidationException>(() => service.CreateAsync("alpha", query));

            var html = ValidTemplate("HTML attempt");
            html.Blocks[0].Type = "html";
            html.Blocks[0].DataSourceId = null;
            await Assert.ThrowsAsync<TopologyValidationException>(() => service.CreateAsync("alpha", html));

            var css = ValidTemplate("CSS attempt");
            css.Theme.BackgroundColor = "#fff;background:url(javascript:alert(1))";
            await Assert.ThrowsAsync<TopologyValidationException>(() => service.CreateAsync("alpha", css));

            var oversized = ValidTemplate("Too many blocks");
            oversized.Blocks = Enumerable.Range(0, 25).Select(index => new ReportTemplateBlock
            {
                BlockId = $"divider-{index}",
                Type = "divider",
                Limit = 1
            }).ToList();
            await Assert.ThrowsAsync<TopologyValidationException>(() => service.CreateAsync("alpha", oversized));

            var catalog = service.ListDataSources();
            Assert.Equal(8, catalog.Count);
            Assert.DoesNotContain(catalog, item => item.DataSourceId.Contains("query", StringComparison.OrdinalIgnoreCase));
            var metrics = Assert.Single(catalog, item => item.DataSourceId == "report.metrics");
            Assert.Contains("defenseScore", metrics.MetricKeys);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task Concurrent_Updates_From_The_Same_Version_Do_Not_Silently_Overwrite()
    {
        var (store, path) = await CreateStoreAsync();
        try
        {
            await AddTenantAsync(store, "alpha");
            var service = new ReportTemplateService(store);
            var created = await service.CreateAsync("alpha", ValidTemplate("Version one"));
            var first = ReportTemplateService.DeepClone(created);
            var second = ReportTemplateService.DeepClone(created);
            first.Name = "First editor";
            second.Name = "Second editor";

            static async Task<(ReportTemplateDefinition? Value, Exception? Error)> CaptureAsync(
                ReportTemplateService service,
                string templateId,
                ReportTemplateDefinition input)
            {
                try
                {
                    return (await service.UpdateAsync("alpha", templateId, input), null);
                }
                catch (Exception ex)
                {
                    return (null, ex);
                }
            }

            var results = await Task.WhenAll(
                CaptureAsync(service, created.TemplateId, first),
                CaptureAsync(service, created.TemplateId, second));
            var winner = Assert.Single(results, result => result.Value is not null);
            var loser = Assert.Single(results, result => result.Error is not null);
            var conflict = Assert.IsType<ReportTemplateVersionConflictException>(loser.Error);
            Assert.Equal(2, conflict.CurrentVersion);

            var stored = await service.GetAsync("alpha", created.TemplateId);
            Assert.NotNull(stored);
            Assert.Equal(2, stored!.Version);
            Assert.Equal(winner.Value!.Name, stored.Name);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task Generated_Report_Renders_From_Immutable_Snapshot_And_Escapes_Plain_Text()
    {
        var (store, path) = await CreateStoreAsync();
        try
        {
            await AddTenantAsync(store, "alpha");
            var templates = new ReportTemplateService(store);
            var input = ValidTemplate("Dark snapshot");
            input.Theme = new ReportTemplateTheme
            {
                Preset = "midnight",
                PrimaryColor = "#F9FAFB",
                AccentColor = "#38BDF8",
                BackgroundColor = "#111827",
                TextColor = "#F9FAFB",
                FontFamily = "system"
            };
            input.Blocks.Add(new ReportTemplateBlock
            {
                BlockId = "analyst-note",
                Type = "text",
                Width = "full",
                Style = "card",
                Limit = 1,
                Text = "<script>alert('x')</script><img src=x onerror=alert(1)>"
            });
            var custom = await templates.CreateAsync("alpha", input);
            var tracker = new LateralMovementTracker(
                Options.Create(new CorrelationOptions()),
                NullLogger<LateralMovementTracker>.Instance,
                store);
            var reports = new TenantReportService(store, tracker, templates);

            await Assert.ThrowsAsync<TopologyValidationException>(() =>
                reports.GenerateAsync("alpha", new CreateSecurityReportRequest
                {
                    TemplateId = custom.TemplateId,
                    PeriodStartUtc = DateTimeOffset.UtcNow.AddDays(-1),
                    PeriodEndUtc = DateTimeOffset.UtcNow
                }));

            var report = await reports.GenerateAsync("alpha", new CreateSecurityReportRequest
            {
                TemplateId = custom.TemplateId,
                TemplateVersion = custom.Version,
                Title = "<img src=x onerror=alert(2)> Customer report",
                PeriodStartUtc = DateTimeOffset.UtcNow.AddDays(-1),
                PeriodEndUtc = DateTimeOffset.UtcNow
            });
            Assert.Equal(custom.TemplateId, report.TemplateId);
            Assert.Equal("Dark snapshot", report.TemplateSnapshot?.Name);

            var changed = ValidTemplate("Changed after generation");
            changed.Theme.AccentColor = "#FF0000";
            var changedTemplate = await templates.UpdateAsync("alpha", custom.TemplateId, changed);
            Assert.NotNull(changedTemplate);
            var generationConflict = await Assert.ThrowsAsync<ReportTemplateVersionConflictException>(() =>
                reports.GenerateAsync("alpha", new CreateSecurityReportRequest
                {
                    TemplateId = custom.TemplateId,
                    TemplateVersion = custom.Version,
                    PeriodStartUtc = DateTimeOffset.UtcNow.AddDays(-1),
                    PeriodEndUtc = DateTimeOffset.UtcNow
                }));
            Assert.Equal(changedTemplate!.Version, generationConflict.CurrentVersion);

            var html = TenantReportService.RenderHtml(report);
            Assert.Contains("--background:#111827", html);
            Assert.Contains("--accent:#38BDF8", html);
            Assert.Contains("--surface:#1F2937", html);
            Assert.Contains("--muted:#CBD5E1", html);
            Assert.Contains("--border:#475569", html);
            Assert.Contains("class=\"report-chrome\"", html);
            Assert.Contains("class=\"report-identity\"", html);
            Assert.DoesNotContain("--accent:#FF0000", html);
            Assert.Contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;", html);
            Assert.Contains("&lt;img src=x onerror=alert(2)&gt; Customer report", html);
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("onclick=", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("background:#fff", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("background:var(--surface)", html);
            Assert.DoesNotContain("color:#687386", html, StringComparison.OrdinalIgnoreCase);

            var midGrayReport = ReportTemplateService.DeepClone(report.TemplateSnapshot!);
            midGrayReport.Theme.PrimaryColor = "#999999";
            report.TemplateSnapshot = midGrayReport;
            Assert.Contains("--chrome-text:#111827", TenantReportService.RenderHtml(report));

            var midnightPreset = ReportTemplateService.DeepClone(report.TemplateSnapshot!);
            midnightPreset.Theme = new ReportTemplateTheme
            {
                Preset = "midnight",
                PrimaryColor = "#0F172A",
                AccentColor = "#8B5CF6",
                BackgroundColor = "#0F172A",
                TextColor = "#F8FAFC",
                FontFamily = "system"
            };
            report.TemplateSnapshot = midnightPreset;
            var midnightHtml = TenantReportService.RenderHtml(report);
            Assert.Contains("--primary:#0F172A", midnightHtml);
            Assert.Contains("--heading:#F8FAFC", midnightHtml);
            Assert.Contains("color:var(--heading)", midnightHtml);

            var noChromeReport = ReportTemplateService.DeepClone(custom);
            noChromeReport.Page.ShowHeader = false;
            report.TemplateSnapshot = noChromeReport;
            var noChromeHtml = TenantReportService.RenderHtml(report);
            Assert.DoesNotContain("class=\"report-chrome\"", noChromeHtml);
            Assert.Contains("class=\"report-identity\"", noChromeHtml);
            Assert.Contains("&lt;img src=x onerror=alert(2)&gt; Customer report", noChromeHtml);

            var stored = await store.GetReportAsync("alpha", report.ReportId);
            Assert.Equal("Dark snapshot", stored?.TemplateSnapshot?.Name);

            var legacy = new SecurityReportRecord
            {
                ReportId = "legacy",
                Title = "<script>legacy()</script>",
                CustomerName = "Legacy"
            };
            var legacyHtml = TenantReportService.RenderHtml(legacy);
            Assert.Contains("&lt;script&gt;legacy()&lt;/script&gt;", legacyHtml);
            Assert.DoesNotContain("<script", legacyHtml, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("onclick=", legacyHtml, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task Generated_Snapshot_Preserves_Allowlisted_Detail_Up_To_Template_Limits()
    {
        var (store, path) = await CreateStoreAsync();
        try
        {
            await AddTenantAsync(store, "alpha");
            var now = DateTimeOffset.UtcNow;
            await store.SaveBatchAsync(new AgentIngestBatch
            {
                AgentId = "agent-alpha",
                ComputerName = "alpha-host",
                SecurityEvents = Enumerable.Range(1, 20).Select(index => new SecurityEventRecord
                {
                    AgentId = "agent-alpha",
                    ComputerName = "alpha-host",
                    EventId = 5_000 + index,
                    EventRecordId = index,
                    TimestampUtc = now.AddMinutes(-index),
                    SourceIp = $"203.0.113.{index}",
                    Channel = "Security"
                }).ToList()
            }, "alpha");
            foreach (var index in Enumerable.Range(1, 15))
            {
                await store.UpsertIncidentAsync(new Incident
                {
                    IncidentId = $"detail-{index}",
                    TenantId = "alpha",
                    Title = $"Incident {index}",
                    Severity = NTShield.Shared.Enums.Severity.High,
                    FirstSeenUtc = now.AddHours(-1),
                    LastSeenUtc = now.AddMinutes(-index),
                    Status = "Open"
                }, "alpha");
            }

            var templates = new ReportTemplateService(store);
            var tracker = new LateralMovementTracker(
                Options.Create(new CorrelationOptions()),
                NullLogger<LateralMovementTracker>.Instance,
                store);
            var reports = new TenantReportService(store, tracker, templates);
            var report = await reports.GenerateAsync("alpha", new CreateSecurityReportRequest
            {
                TemplateId = "builtin-technical",
                PeriodStartUtc = now.AddDays(-1),
                PeriodEndUtc = now.AddMinutes(1)
            });

            Assert.Equal(20, report.TopSourceIps.Count);
            Assert.Equal(20, report.TopEventIds.Count);
            Assert.Equal(15, report.PriorityIncidents.Count);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    private static ReportTemplateDefinition ValidTemplate(string name) => new()
    {
        Name = name,
        Description = "Declarative test template",
        Theme = new ReportTemplateTheme(),
        Page = new ReportTemplatePage(),
        Blocks =
        [
            new ReportTemplateBlock
            {
                BlockId = "identity",
                Type = "header",
                DataSourceId = "report.identity",
                Limit = 1
            },
            new ReportTemplateBlock
            {
                BlockId = "metrics",
                Type = "metrics",
                DataSourceId = "report.metrics",
                Limit = 4,
                MetricKeys = ["defenseScore", "incidents", "critical", "onlineAgents"]
            }
        ]
    };

    private static async Task<(SqliteCentralStore Store, string Path)> CreateStoreAsync()
    {
        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), $"ntshield-template-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = path }),
            NullLogger<SqliteCentralStore>.Instance);
        await store.InitializeAsync();
        return (store, path);
    }

    private static Task AddTenantAsync(SqliteCentralStore store, string tenantId) =>
        store.UpsertTenantAsync(new CustomerTenant
        {
            TenantId = tenantId,
            Name = tenantId.ToUpperInvariant(),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });

    private static void DeleteDatabase(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var file = path + suffix;
            if (File.Exists(file)) File.Delete(file);
        }
    }
}
