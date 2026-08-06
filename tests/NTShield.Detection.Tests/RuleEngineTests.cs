using NTShield.Core.Configuration;
using NTShield.Detection;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Detection.Tests;

public class RuleEngineTests
{
    private static RuleEngine CreateEngine(Action<DetectionOptions>? configure = null)
    {
        var opt = new DetectionOptions
        {
            Enabled = true,
            RulesPath = FindRulesPath(),
            AllowlistPath = FindAllowlistPath()
        };
        configure?.Invoke(opt);
        var detection = Options.Create(opt);
        var agent = Options.Create(new AgentOptions
        {
            AgentId = "test-agent",
            ComputerName = "DEST-HOST"
        });
        return new RuleEngine(detection, agent, NullLogger<RuleEngine>.Instance);
    }

    private static string FindRulesPath()
    {
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "config", "rules.json")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "rules.json")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "rules", "default-rules.json"))
        };
        return candidates.First(File.Exists);
    }

    private static string FindAllowlistPath()
    {
        var p = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "allowlist.json"));
        return File.Exists(p) ? p : "allowlist.json";
    }

    private static List<SecurityEventRecord> Failures(string sourceIp, IEnumerable<string> users, int copiesPerUser = 3)
    {
        var now = DateTimeOffset.UtcNow;
        var list = new List<SecurityEventRecord>();
        var id = 1L;
        foreach (var user in users)
        {
            for (var i = 0; i < copiesPerUser; i++)
            {
                list.Add(new SecurityEventRecord
                {
                    EventId = 4625,
                    TimestampUtc = now.AddSeconds(-id),
                    SourceIp = sourceIp,
                    Username = user,
                    ComputerName = "10.0.105.190",
                    AgentId = "dest",
                    LogonType = 8,
                    LogonProcess = "Advapi",
                    EventRecordId = id++
                });
            }
        }

        return list;
    }

    [Fact]
    public async Task SlidingWindow_Ignores_Events_Outside_Window()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var now = DateTimeOffset.UtcNow;
        var events = Failures("10.0.105.35", Enumerable.Range(0, 8).Select(i => $"u{i}"), 3);
        // push all outside 5 minute window
        foreach (var e in events)
        {
            e.TimestampUtc = now.AddMinutes(-30);
        }

        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.DoesNotContain(alerts, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
    }

    [Fact]
    public async Task DistinctUsernameDetection_Triggers_InternalPasswordSpray()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var users = new[] { "123", "admin", "admin1", "administrator", "guest", "root", "www", "wwwroot", "db", "web", "data" };
        // 11 users * 2 = 22 events (>=20) with 11 distinct
        var events = Failures("10.0.105.35", users, 2);
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed && a.DistinctUserCount >= 5);
    }

    [Fact]
    public async Task FailedThenSuccess_Correlation()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var now = DateTimeOffset.UtcNow;
        var events = Failures("10.0.105.35", new[] { "jdoe" }, 8);
        events.Add(new SecurityEventRecord
        {
            EventId = 4624,
            TimestampUtc = now.AddMinutes(-1),
            SourceIp = "10.0.105.35",
            Username = "jdoe",
            ComputerName = "10.0.105.190",
            AgentId = "dest",
            EventRecordId = 9999
        });
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "SPRAY_THEN_SUCCESS" && !a.Suppressed);
    }

    [Fact]
    public async Task DuplicateEventHandling_DoesNotDoubleCountAcrossEvaluations()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var users = Enumerable.Range(0, 6).Select(i => $"user{i}");
        var events = Failures("10.0.105.35", users, 4); // 24 events
        var first = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        var second = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(first, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
        // Same event keys suppressed from re-count; may still fire if other rules, but spray window uses deduped empty-ish set
        Assert.DoesNotContain(second, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
    }

    [Fact]
    public async Task Allowlist_Suppresses_SourceIp()
    {
        var engine = CreateEngine(o => o.AllowlistSourceIps = ["10.0.105.35"]);
        await engine.InitializeAsync(CancellationToken.None);
        var users = Enumerable.Range(0, 8).Select(i => $"u{i}");
        var events = Failures("10.0.105.35", users, 3);
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.DoesNotContain(alerts, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
    }

    [Fact]
    public async Task Cooldown_Suppresses_Repeat()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var users = Enumerable.Range(0, 8).Select(i => $"u{i}");
        var events = Failures("10.0.105.35", users, 3);
        var a1 = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        // new event keys so dedup doesn't empty the set
        foreach (var e in events)
        {
            e.EventRecordId += 10_000;
            e.TimestampUtc = DateTimeOffset.UtcNow.AddSeconds(-e.EventRecordId % 50);
        }

        var a2 = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(a1, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
        Assert.DoesNotContain(a2, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);
    }

    [Fact]
    public async Task SuspiciousAccountNames_RequiresVolume_NotNameAlone()
    {
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var now = DateTimeOffset.UtcNow;
        var low = new List<SecurityEventRecord>
        {
            new()
            {
                EventId = 4625,
                TimestampUtc = now,
                SourceIp = "10.0.1.1",
                Username = "admin",
                ComputerName = "DEST",
                AgentId = "a",
                EventRecordId = 1
            }
        };
        var lowAlerts = await engine.EvaluateAsync(low, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.DoesNotContain(lowAlerts, a => a.RuleId == "SUSPICIOUS_ACCOUNT_NAMES" && !a.Suppressed);

        var high = Enumerable.Range(0, 6).Select(i => new SecurityEventRecord
        {
            EventId = 4625,
            TimestampUtc = now.AddSeconds(-i),
            SourceIp = "10.0.1.1",
            Username = "admin",
            ComputerName = "DEST",
            AgentId = "a",
            EventRecordId = 10 + i
        }).ToList();
        var highAlerts = await engine.EvaluateAsync(high, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(highAlerts, a => a.RuleId == "SUSPICIOUS_ACCOUNT_NAMES" && !a.Suppressed);
    }

    [Fact]
    public async Task MalformedEventXml_DoesNotThrow_InCollectorPath()
    {
        // Engine itself accepts empty fields
        var engine = CreateEngine();
        await engine.InitializeAsync(CancellationToken.None);
        var events = new List<SecurityEventRecord>
        {
            new()
            {
                EventId = 4625,
                TimestampUtc = DateTimeOffset.UtcNow,
                RawXml = "<not-valid",
                SourceIp = "1.2.3.4",
                Username = "x",
                ComputerName = "h",
                AgentId = "a",
                EventRecordId = 1
            }
        };
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.NotNull(alerts);
    }
}
