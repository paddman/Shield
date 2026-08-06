using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using NTShield.Storage.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace NTShield.Integration.Tests;

public class SqliteLocalStoreTests
{
    [Fact]
    public async Task SaveAndQuery_SecurityEvents_Works()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nts-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        var agent = Options.Create(new AgentOptions
        {
            AgentId = "itest",
            ComputerName = "ITEST",
            DataDirectory = dir
        });
        var storage = Options.Create(new StorageOptions
        {
            DatabaseFileName = "test.db",
            RetentionDays = 7
        });

        await using var store = new SqliteLocalStore(storage, agent, NullLogger<SqliteLocalStore>.Instance);
        await store.InitializeAsync(CancellationToken.None);

        var evt = new SecurityEventRecord
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            ComputerName = "ITEST",
            AgentId = "itest",
            EventId = 4625,
            Channel = "Security",
            Username = "admin",
            SourceIp = "10.0.105.35",
            RawXml = "<Event/>",
            EventRecordId = 42
        };

        await store.SaveSecurityEventsAsync([evt], CancellationToken.None);
        var found = await store.QuerySecurityEventsAsync(
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddHours(1),
            4625,
            CancellationToken.None);

        Assert.Single(found);
        Assert.Equal("admin", found[0].Username);
        Assert.Equal("10.0.105.35", found[0].SourceIp);

        await store.SetStateAsync("k", "v");
        Assert.Equal("v", await store.GetStateAsync("k"));

        var depth = await store.GetOutboundQueueDepthAsync(CancellationToken.None);
        Assert.True(depth >= 1);
    }

    [Fact]
    public async Task Dpapi_Secret_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nts-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var agent = Options.Create(new AgentOptions { AgentId = "s", ComputerName = "S", DataDirectory = dir });
        var storage = Options.Create(new StorageOptions { DatabaseFileName = "sec.db" });
        await using var store = new SqliteLocalStore(storage, agent, NullLogger<SqliteLocalStore>.Instance);
        await store.InitializeAsync(CancellationToken.None);

        await store.ProtectSecretAsync("mtls-password", "p@ssw0rd!", CancellationToken.None);
        var plain = await store.UnprotectSecretAsync("mtls-password", CancellationToken.None);
        Assert.Equal("p@ssw0rd!", plain);
    }
}
