using NTShield.Server.AI;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class TelemetryFeatureBuilderTests
{
    [Fact]
    public void Builds_stable_numeric_features_without_raw_event_content()
    {
        var features = new TelemetryFeatureBuilder().Build(new AgentIngestBatch
        {
            AgentId = "agent-1",
            SecurityEvents =
            [
                new SecurityEventRecord { EventId = 4625, SourceIp = "203.0.113.10", Username = "alice" },
                new SecurityEventRecord { EventId = 4624, SourceIp = "10.0.0.4", Username = "alice", LogonType = 10 },
                new SecurityEventRecord { EventId = 4688, TargetUserName = "svc" }
            ],
            NetworkConnections =
            [
                new NetworkConnectionRecord { RemoteAddress = "198.51.100.20", RemotePort = 443, IsNew = true },
                new NetworkConnectionRecord { RemoteAddress = "10.0.0.5", RemotePort = 445 }
            ],
            Processes = [new ProcessRecord { ProcessName = "powershell.exe", CommandLine = "secret" }],
            Alerts = [new DetectionAlert { Severity = Severity.High }]
        });

        Assert.Equal(3, features["security_events"]);
        Assert.Equal(2, features["unique_source_addresses"]);
        Assert.Equal(1, features["unique_external_source_addresses"]);
        Assert.Equal(1, features["unique_external_remote_addresses"]);
        Assert.Equal(1, features["failed_logons"]);
        Assert.Equal(1, features["privileged_logons"]);
        Assert.Equal(1, features["high_or_critical_alerts"]);
        Assert.DoesNotContain(features.Keys, key => key.Contains("secret", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(features.Keys, key => key.Contains("powershell", StringComparison.OrdinalIgnoreCase));
    }
}
