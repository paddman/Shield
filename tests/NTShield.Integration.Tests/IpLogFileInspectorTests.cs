using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Agent;
using NTShield.Core.Configuration;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class IpLogFileInspectorTests
{
    [Fact]
    public async Task ExtractsIpEvidenceAndRaisesAuthBurstWithoutUploadingRawLine()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ntshield-iplog-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "auth.log");
            await File.WriteAllLinesAsync(path, Enumerable.Range(1, 12)
                .Select(i => $"2026-08-07T12:00:{i:00}Z Failed password for invalid user from 203.0.113.50 port 22 status=401 secret=do-not-upload"));

            var options = new IpLogFileInspectorOptions
            {
                Paths = [path],
                AuthFailureBurstMin = 10,
                MaxEventsPerCycle = 50
            };
            var agent = new AgentOptions { AgentId = "agent-test", ComputerName = "TEST-HOST" };
            var inspector = new IpLogFileInspector(
                Options.Create(options),
                Options.Create(agent),
                NullLogger<IpLogFileInspector>.Instance);

            var result = await inspector.ScanAsync(CancellationToken.None);

            Assert.Equal(12, result.Events.Count);
            Assert.Contains(result.Events, item => item.SourceIp == "203.0.113.50");
            Assert.DoesNotContain(result.Events, item => item.RawXml.Contains("do-not-upload", StringComparison.Ordinal));
            var alert = Assert.Single(result.Alerts);
            Assert.Equal("IP_LOG_AUTH_FAILURE_BURST", alert.RuleId);
            Assert.Equal("203.0.113.50", alert.SourceIp);
            Assert.Equal(12, alert.EventCount);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task ReadsOnlyNewContentAfterInitialScan()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ntshield-iplog-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "firewall.log");
            await File.WriteAllTextAsync(path, "allow src=192.0.2.10 dst=198.51.100.20\n");
            var inspector = new IpLogFileInspector(
                Options.Create(new IpLogFileInspectorOptions { Paths = [path] }),
                Options.Create(new AgentOptions { AgentId = "agent-test", ComputerName = "TEST-HOST" }),
                NullLogger<IpLogFileInspector>.Instance);

            var first = await inspector.ScanAsync(CancellationToken.None);
            var second = await inspector.ScanAsync(CancellationToken.None);
            await File.AppendAllTextAsync(path, "denied src=192.0.2.11 dst=198.51.100.21 status=403\n");
            var third = await inspector.ScanAsync(CancellationToken.None);

            Assert.Single(first.Events);
            Assert.Empty(second.Events);
            Assert.Single(third.Events);
            Assert.Equal("192.0.2.11", third.Events[0].SourceIp);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
