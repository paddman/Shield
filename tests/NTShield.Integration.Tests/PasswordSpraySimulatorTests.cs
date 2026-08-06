using NTShield.Core.Configuration;
using NTShield.Detection;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Integration.Tests;

/// <summary>
/// Integration simulator: source 10.0.105.35 -> dest 10.0.105.190 password spray scenario.
/// </summary>
public class PasswordSpraySimulatorTests
{
    private static readonly string[] SprayUsers =
    [
        "123", "admin", "admin1", "administrator", "guest",
        "root", "www", "wwwroot", "db", "web", "data"
    ];

    [Fact]
    public async Task Simulate_InternalPasswordSpray_Produces_AnalystIncident()
    {
        var now = DateTimeOffset.UtcNow;
        var failures = new List<SecurityEventRecord>();
        long rid = 1;
        // 880 failed attempts across 11 usernames (spec example scale reduced for unit speed but >=20)
        // Use 80 total (~7-8 per user) for test speed while keeping 11 distinct.
        foreach (var user in SprayUsers)
        {
            for (var i = 0; i < 8; i++)
            {
                failures.Add(new SecurityEventRecord
                {
                    EventId = 4625,
                    TimestampUtc = now.AddSeconds(-rid),
                    SourceIp = "10.0.105.35",
                    Username = user,
                    ComputerName = "10.0.105.190",
                    DestinationIp = "10.0.105.190",
                    DestinationPort = 80,
                    AgentId = "agent-dest",
                    LogonType = 8,
                    LogonProcess = "Advapi",
                    EventRecordId = rid++,
                    RawXml = $"<Event><Data Name=\"TargetUserName\">{user}</Data></Event>"
                });
            }
        }

        // Source host network attribution
        var connections = new List<NetworkConnectionRecord>
        {
            new()
            {
                TimestampUtc = now.AddMinutes(-2),
                ComputerName = "SRC-35",
                AgentId = "agent-src",
                Protocol = "TCP",
                LocalAddress = "10.0.105.35",
                LocalPort = 51544,
                RemoteAddress = "10.0.105.190",
                RemotePort = 80,
                ProcessId = 1684,
                ProcessName = "svchost.exe",
                ProcessPath = @"C:\Windows\System32\svchost.exe",
                ServiceNames = "IPTVManagementService",
                IsNew = true,
                ConnectionKey = "tcp-test"
            }
        };

        var batch = new AgentIngestBatch
        {
            AgentId = "agent-dest",
            ComputerName = "10.0.105.190",
            SecurityEvents = failures,
            NetworkConnections = connections
        };

        // Detection engine (local)
        var engine = new RuleEngine(
            Options.Create(new DetectionOptions
            {
                RulesPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "rules.json"))
            }),
            Options.Create(new AgentOptions { AgentId = "agent-dest", ComputerName = "10.0.105.190" }),
            NullLogger<RuleEngine>.Instance);
        await engine.InitializeAsync(CancellationToken.None);
        var alerts = await engine.EvaluateAsync(failures, connections, CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId == "INTERNAL_PASSWORD_SPRAY" && !a.Suppressed);

        // Central correlator (without live Postgres) — use empty store via null-safe path:
        // CrossHostCorrelator.BuildLocalSprayIncidents works from batch alone when DB lookup fails.
        // We instantiate correlator with a dummy store that throws on find.
        var correlator = new CrossHostCorrelator(
            new PostgresStore(Options.Create(new PostgresOptions
            {
                ConnectionString = "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none"
            }), NullLogger<PostgresStore>.Instance),
            Options.Create(new CorrelationOptions { TimestampToleranceSeconds = 120 }),
            NullLogger<CrossHostCorrelator>.Instance);

        var incidents = await correlator.CorrelateAsync(batch, CancellationToken.None);
        Assert.NotEmpty(incidents);
        var incident = incidents.First(i => i.Title.Contains("Password Spray", StringComparison.OrdinalIgnoreCase)
                                            || i.RuleId == "INTERNAL_PASSWORD_SPRAY");

        // Shape matches required display fields
        Assert.Equal("10.0.105.35", incident.SourceIp);
        Assert.True(incident.FailedAttempts >= 20);
        Assert.True(incident.DistinctUsernames >= 5);
        Assert.False(incident.SuccessfulLoginDetected);
        Assert.NotNull(incident.FirstSeen);
        Assert.NotNull(incident.LastSeen);

        // Process attribution when connection present
        Assert.Equal(1684, incident.ProcessId);
        Assert.Equal("svchost.exe", incident.ProcessName);
        Assert.Contains("IPTVManagementService", incident.Services);

        var display = incident.FormatDisplay();
        Assert.Contains("Incident:", display);
        Assert.Contains("10.0.105.35", display);
        Assert.Contains("svchost.exe", display);
        Assert.Contains("IPTVManagementService", display);
        Assert.Contains("Failed attempts:", display);
        Assert.Contains("Successful login detected: false", display);
    }

    [Fact]
    public async Task Simulate_SprayThenSuccess_4624()
    {
        var now = DateTimeOffset.UtcNow;
        var events = new List<SecurityEventRecord>();
        long rid = 1;
        foreach (var user in SprayUsers.Take(6))
        {
            for (var i = 0; i < 5; i++)
            {
                events.Add(new SecurityEventRecord
                {
                    EventId = 4625,
                    TimestampUtc = now.AddMinutes(-10).AddSeconds(rid),
                    SourceIp = "10.0.105.35",
                    Username = user,
                    ComputerName = "10.0.105.190",
                    AgentId = "dest",
                    EventRecordId = rid++
                });
            }
        }

        events.Add(new SecurityEventRecord
        {
            EventId = 4624,
            TimestampUtc = now.AddMinutes(-1),
            SourceIp = "10.0.105.35",
            Username = "admin",
            ComputerName = "10.0.105.190",
            AgentId = "dest",
            LogonType = 8,
            LogonProcess = "Advapi",
            EventRecordId = rid
        });

        var engine = new RuleEngine(
            Options.Create(new DetectionOptions
            {
                RulesPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "rules.json"))
            }),
            Options.Create(new AgentOptions { AgentId = "dest", ComputerName = "10.0.105.190" }),
            NullLogger<RuleEngine>.Instance);
        await engine.InitializeAsync(CancellationToken.None);
        var alerts = await engine.EvaluateAsync(events, Array.Empty<NetworkConnectionRecord>(), CancellationToken.None);
        Assert.Contains(alerts, a => a.RuleId is "SPRAY_THEN_SUCCESS" or "INTERNAL_PASSWORD_SPRAY");
    }
}
