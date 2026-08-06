using NTShield.Core.Compatibility;
using NTShield.Core.Configuration;
using NTShield.Core.Identity;
using Xunit;

namespace NTShield.Core.Tests;

public class WindowsCompatibilityTests
{
    [Fact]
    public void BuildReport_ReturnsPopulatedReport()
    {
        var report = WindowsCompatibility.BuildReport();
        Assert.False(string.IsNullOrWhiteSpace(report.OsVersion));
        Assert.False(string.IsNullOrWhiteSpace(report.Notes));
    }

    [Fact]
    public void EnsureAgentId_IsStable()
    {
        var options = new AgentOptions { ComputerName = "TEST-HOST-A" };
        var a = AgentIdentity.EnsureAgentId(options);
        var b = AgentIdentity.EnsureAgentId(options);
        Assert.Equal(a, b);
        Assert.False(string.IsNullOrWhiteSpace(a));
    }

    [Fact]
    public void EnsureAgentId_PreservesConfiguredId()
    {
        var options = new AgentOptions { AgentId = "fixed-id-123", ComputerName = "X" };
        var id = AgentIdentity.EnsureAgentId(options);
        Assert.Equal("fixed-id-123", id);
    }
}
