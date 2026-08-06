using NTShield.Core.Configuration;
using NTShield.Core.Security;
using NTShield.Response;
using NTShield.Response.Firewall;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using NTShield.Storage.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Integration.Tests;

public class ResponseAndQueueTests
{
    [Fact]
    public async Task DetectOnly_Default_DoesNot_Block_Without_Approval()
    {
        var agent = Options.Create(new AgentOptions { AgentId = "a", ComputerName = "h", DetectOnly = true });
        var resp = Options.Create(new ResponseOptions { DetectOnly = true, LogOnlyMode = true });
        var executor = new LocalResponseExecutor(
            resp, agent,
            new RuntimePolicyState(),
            new FirewallBlocker(NullLogger<FirewallBlocker>.Instance),
            NullLogger<LocalResponseExecutor>.Instance);

        var result = await executor.ExecuteRequestAsync(new ResponseActionRequest
        {
            ActionType = "TerminateProcess",
            ProcessId = 1,
            Requester = "operator",
            Reason = "test",
            Approved = false
        }, CancellationToken.None);

        Assert.Equal("PendingApproval", result.Status);
        Assert.False(string.IsNullOrEmpty(result.RequestId));
        Assert.False(string.IsNullOrEmpty(result.AuditLog));
    }

    [Fact]
    public async Task Rollback_Fields_Present_On_Action_Record()
    {
        var agent = Options.Create(new AgentOptions { AgentId = "a", ComputerName = "h" });
        var resp = Options.Create(new ResponseOptions { DetectOnly = false, LogOnlyMode = false });
        var executor = new LocalResponseExecutor(
            resp, agent,
            new RuntimePolicyState(),
            new FirewallBlocker(NullLogger<FirewallBlocker>.Instance),
            NullLogger<LocalResponseExecutor>.Instance);

        var alertResult = await executor.ExecuteAsync(new DetectionAlert
        {
            RuleId = "X",
            Title = "t",
            AlertId = "1"
        }, CancellationToken.None);

        Assert.Equal("LogOnly", alertResult.ActionType);
        Assert.Equal("Completed", alertResult.Status);
        Assert.NotNull(alertResult.RequestId);
        Assert.NotNull(alertResult.Requester);
        Assert.NotNull(alertResult.AuditLog);
    }

    [Fact]
    public async Task OfflineQueue_Enforces_Limit_And_Persists()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nts-q-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var store = new SqliteLocalStore(
            Options.Create(new StorageOptions { DatabaseFileName = "q.db", OfflineQueueLimit = 50 }),
            Options.Create(new AgentOptions { AgentId = "a", ComputerName = "h", DataDirectory = dir }),
            NullLogger<SqliteLocalStore>.Instance);
        await store.InitializeAsync(CancellationToken.None);

        for (var i = 0; i < 60; i++)
        {
            await store.EnqueueOutboundAsync(QueueItemType.Heartbeat, $"{{\"i\":{i}}}", CancellationToken.None);
        }

        var depth = await store.GetOutboundQueueDepthAsync(CancellationToken.None);
        Assert.True(depth <= 50);
    }

    [Fact]
    public void Arbitrary_Shell_Not_Allowlisted()
    {
        Assert.False(EventDataSanitizer.IsAllowlistedCommand("cmd /c del /f C:\\Windows"));
    }
}
