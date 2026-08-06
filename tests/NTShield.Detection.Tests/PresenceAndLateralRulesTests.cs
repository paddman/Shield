using NTShield.Core.Configuration;
using NTShield.Detection;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Detection.Tests;

public class PresenceAndLateralRulesTests
{
    private static async Task<RuleEngine> CreateAsync()
    {
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "rules.json"));
        var engine = new RuleEngine(
            Options.Create(new DetectionOptions { RulesPath = path }),
            Options.Create(new AgentOptions { AgentId = "t", ComputerName = "H1" }),
            NullLogger<RuleEngine>.Instance);
        await engine.InitializeAsync(CancellationToken.None);
        return engine;
    }

    [Fact]
    public async Task NewServiceInstalled_Presence_Alerts()
    {
        var engine = await CreateAsync();
        var now = DateTimeOffset.UtcNow;
        var events = new List<SecurityEventRecord>
        {
            new()
            {
                EventId = 7045,
                TimestampUtc = now,
                ComputerName = "H1",
                AgentId = "t",
                ServiceName = "EvilSvc",
                ProcessPath = @"C:\Temp\evil.exe",
                EventRecordId = 1,
                RawXml = "<Event/>"
            }
        };
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "NEW_SERVICE_INSTALLED" && !a.Suppressed);
    }

    [Fact]
    public async Task ExplicitCredentials_Requires_MinCount()
    {
        var engine = await CreateAsync();
        var now = DateTimeOffset.UtcNow;
        var one = new List<SecurityEventRecord>
        {
            new()
            {
                EventId = 4648,
                TimestampUtc = now,
                SourceIp = "10.0.0.1",
                Username = "admin",
                ComputerName = "H1",
                AgentId = "t",
                EventRecordId = 1
            }
        };
        var low = await engine.EvaluateAsync(one, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.DoesNotContain(low, a => a.RuleId == "EXPLICIT_CREDENTIALS_LATERAL" && !a.Suppressed);

        var many = Enumerable.Range(0, 4).Select(i => new SecurityEventRecord
        {
            EventId = 4648,
            TimestampUtc = now.AddSeconds(-i),
            SourceIp = "10.0.0.1",
            Username = "admin",
            ComputerName = "H1",
            AgentId = "t",
            EventRecordId = 10 + i
        }).ToList();
        var high = await engine.EvaluateAsync(many, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(high, a => a.RuleId == "EXPLICIT_CREDENTIALS_LATERAL" && !a.Suppressed);
    }

    [Fact]
    public async Task LateralAuthPortFanOut_Network_Rule()
    {
        var engine = await CreateAsync();
        var now = DateTimeOffset.UtcNow;
        var conns = Enumerable.Range(1, 10).Select(i => new NetworkConnectionRecord
        {
            TimestampUtc = now.AddSeconds(-i),
            ComputerName = "H1",
            AgentId = "t",
            LocalAddress = "10.0.105.35",
            RemoteAddress = $"10.0.105.{100 + i}",
            RemotePort = 445,
            ProcessId = 1684,
            ProcessName = "svchost.exe",
            IsNew = true,
            ConnectionKey = $"k{i}"
        }).ToList();

        var alerts = await engine.EvaluateAsync(Array.Empty<SecurityEventRecord>(), conns, CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId is "LATERAL_AUTH_PORT_SCAN" or "MULTIPLE_INTERNAL_TARGETS");
    }
}
