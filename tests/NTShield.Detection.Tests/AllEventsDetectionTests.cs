using NTShield.Core.Configuration;
using NTShield.Detection;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Detection.Tests;

public class AllEventsDetectionTests
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

    private static SecurityEventRecord Ev(int id, long rid, string? path = null, string? xml = null, int? dport = null)
    {
        return new SecurityEventRecord
        {
            EventId = id,
            EventRecordId = rid,
            TimestampUtc = DateTimeOffset.UtcNow.AddSeconds(-rid % 50),
            ComputerName = "H1",
            AgentId = "t",
            ProcessPath = path,
            RawXml = xml ?? $"<Event><Data Name=\"NewProcessName\">{path}</Data></Event>",
            DestinationPort = dport,
            SourceIp = "10.0.0.5",
            Username = "user1"
        };
    }

    [Fact]
    public async Task ProcessFromTempPath_4688_Alerts()
    {
        var engine = await CreateAsync();
        var events = new List<SecurityEventRecord>
        {
            Ev(4688, 1, @"C:\Users\Public\evil.exe")
        };
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "PROCESS_FROM_TEMP_PATH" && !a.Suppressed);
    }

    [Fact]
    public async Task Lolbins_4688_Alerts()
    {
        var engine = await CreateAsync();
        var events = new List<SecurityEventRecord>
        {
            Ev(4688, 2, @"C:\Windows\System32\powershell.exe",
                @"<Event><Data>powershell.exe -nop -w hidden -enc AAAA</Data></Event>")
        };
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId is "LOLBINS_PROCESS_CREATION" or "SUSPICIOUS_CMDLINE_TOKENS");
    }

    [Fact]
    public async Task SpecialPrivileges_4672_Presence()
    {
        var engine = await CreateAsync();
        var alerts = await engine.EvaluateAsync(
            [Ev(4672, 3)],
            Array.Empty<NetworkConnectionRecord>(),
            CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "SPECIAL_PRIVILEGES_ASSIGNED" && !a.Suppressed);
    }

    [Fact]
    public async Task WfpBlocked_5157_Volume()
    {
        var engine = await CreateAsync();
        var events = Enumerable.Range(0, 35).Select(i => Ev(5157, 100 + i, dport: 445)).ToList();
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "WFP_CONNECTION_BLOCKED" && !a.Suppressed);
    }

    [Fact]
    public async Task RulesCover_AllCollectedEventIds()
    {
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "rules.json"));
        var json = await File.ReadAllTextAsync(path);
        int[] required = [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 5156, 5157, 7045];
        foreach (var id in required)
        {
            Assert.True(json.Contains(id.ToString(), StringComparison.Ordinal),
                $"rules.json should reference event {id}");
        }
    }
}
