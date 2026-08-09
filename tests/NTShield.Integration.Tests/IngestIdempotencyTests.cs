using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.Services;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class IngestIdempotencyTests
{
    [Fact]
    public void Busy_claim_is_non_success_with_retry_after_for_status_code_driven_agents()
    {
        var context = new DefaultHttpContext();
        var result = IngestHttpResponseMapper.ToHttpResult(new IngestResponse
        {
            Accepted = false,
            Duplicate = true,
            Message = "idempotency key is already processing; retry"
        }, context.Response);

        var statusResult = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, statusResult.StatusCode);
        Assert.Equal("2", context.Response.Headers.RetryAfter);
        Assert.False(statusResult.StatusCode is >= 200 and < 300);
    }

    [Fact]
    public async Task Concurrent_claims_for_same_tenant_agent_and_key_have_one_owner()
    {
        var (store, databasePath) = await CreateStoreAsync();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var claims = await Task.WhenAll(
                store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "owner-a", now, now.AddMinutes(2)),
                store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "owner-b", now, now.AddMinutes(2)));

            Assert.Single(claims, state => state == IngestIdempotencyClaimState.Acquired);
            Assert.Single(claims, state => state == IngestIdempotencyClaimState.InProgress);
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task Same_key_hash_is_independent_across_tenants_and_authenticated_agents()
    {
        var (store, databasePath) = await CreateStoreAsync();
        try
        {
            var now = DateTimeOffset.UtcNow;

            Assert.Equal(IngestIdempotencyClaimState.Acquired,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "owner-a", now, now.AddMinutes(2)));
            Assert.Equal(IngestIdempotencyClaimState.Acquired,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-b", "agent-a", HashA, "owner-b", now, now.AddMinutes(2)));
            Assert.Equal(IngestIdempotencyClaimState.Acquired,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-b", HashA, "owner-c", now, now.AddMinutes(2)));
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task Expired_claim_can_be_recovered_without_allowing_stale_owner_to_commit()
    {
        var (store, databasePath) = await CreateStoreAsync();
        try
        {
            var started = DateTimeOffset.UtcNow;
            Assert.Equal(IngestIdempotencyClaimState.Acquired,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "stale-owner", started, started.AddSeconds(1)));

            var reclaimedAt = started.AddSeconds(2);
            Assert.Equal(IngestIdempotencyClaimState.Acquired,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "new-owner", reclaimedAt, reclaimedAt.AddMinutes(2)));

            Assert.False(await store.CompleteIngestIdempotencyClaimAsync(
                "tenant-a", "agent-a", HashA, "stale-owner", reclaimedAt));
            await store.ReleaseIngestIdempotencyClaimAsync(
                "tenant-a", "agent-a", HashA, "stale-owner");
            Assert.Equal(IngestIdempotencyClaimState.InProgress,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "third-owner", reclaimedAt, reclaimedAt.AddMinutes(2)));

            Assert.True(await store.CompleteIngestIdempotencyClaimAsync(
                "tenant-a", "agent-a", HashA, "new-owner", reclaimedAt));
            Assert.Equal(IngestIdempotencyClaimState.Completed,
                await store.TryClaimIngestIdempotencyAsync(
                    "tenant-a", "agent-a", HashA, "third-owner", reclaimedAt, reclaimedAt.AddMinutes(2)));
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task Failed_processing_releases_claim_and_successful_retry_is_deduplicated()
    {
        var (store, databasePath) = await CreateStoreAsync();
        try
        {
            var ingest = CreateIngestService(store);
            const string rawKey = "retry-after-processing-failure";
            var invalid = new AgentIngestBatch
            {
                AgentId = "agent-a",
                ComputerName = "host-a",
                IdempotencyKey = rawKey,
                SecurityEvents = [null!]
            };

            var failed = await ingest.IngestAsync(invalid, CancellationToken.None, "tenant-a");
            Assert.False(failed.Accepted);

            var valid = new AgentIngestBatch
            {
                AgentId = "agent-a",
                ComputerName = "host-a",
                IdempotencyKey = rawKey
            };
            var retry = await ingest.IngestAsync(valid, CancellationToken.None, "tenant-a");
            var duplicate = await ingest.IngestAsync(valid, CancellationToken.None, "tenant-a");

            Assert.True(retry.Accepted);
            Assert.False(retry.Duplicate);
            Assert.True(duplicate.Accepted);
            Assert.True(duplicate.Duplicate);
            Assert.Equal(0, duplicate.ReceivedCount);

            await using var connection = new SqliteConnection($"Data Source={databasePath}");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT key_hash FROM ingest_idempotency_claims WHERE tenant_id='tenant-a' AND agent_id='agent-a'";
            var persistedKey = Assert.IsType<string>(await command.ExecuteScalarAsync());
            Assert.Equal(64, persistedKey.Length);
            Assert.DoesNotContain(rawKey, persistedKey, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task Raw_idempotency_key_is_not_persisted_in_temporal_outbox()
    {
        var (store, databasePath) = await CreateStoreAsync();
        try
        {
            var temporal = new TemporalAttackChainService(
                store,
                NullLogger<TemporalAttackChainService>.Instance);
            var ingest = CreateIngestService(store, temporal);
            const string rawKey = "transport-secret-must-not-enter-evidence";

            var response = await ingest.IngestAsync(new AgentIngestBatch
            {
                AgentId = "agent-a",
                ComputerName = "host-a",
                IdempotencyKey = rawKey
            }, CancellationToken.None, "tenant-a");

            Assert.True(response.Accepted);
            var work = Assert.Single(await store.LeaseTemporalCorrelationWorkAsync(
                "test-worker", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1), 10));
            Assert.DoesNotContain(rawKey, work.WorkId, StringComparison.Ordinal);
            Assert.DoesNotContain(rawKey, work.PayloadJson, StringComparison.Ordinal);
            var envelope = JsonSerializer.Deserialize<TemporalCorrelationEnvelope>(
                work.PayloadJson, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.NotNull(envelope);
            Assert.Null(envelope.Batch.IdempotencyKey);
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    private const string HashA =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static IngestService CreateIngestService(
        SqliteCentralStore store,
        TemporalAttackChainService? temporal = null)
    {
        var correlationOptions = Options.Create(new CorrelationOptions
        {
            TimestampToleranceSeconds = 120
        });
        return new IngestService(
            store,
            new CrossHostCorrelator(
                store,
                correlationOptions,
                NullLogger<CrossHostCorrelator>.Instance),
            new LateralMovementTracker(
                correlationOptions,
                NullLogger<LateralMovementTracker>.Instance,
                store),
            NullLogger<IngestService>.Instance,
            temporal: temporal);
    }

    private static async Task<(SqliteCentralStore Store, string DatabasePath)> CreateStoreAsync()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(), $"ntshield-idempotency-{Guid.NewGuid():N}.db");
        var store = new SqliteCentralStore(
            Options.Create(new SqliteCentralOptions { DatabasePath = databasePath }),
            NullLogger<SqliteCentralStore>.Instance);
        await store.InitializeAsync();
        return (store, databasePath);
    }

    private static void DeleteDatabase(string databasePath)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var path = databasePath + suffix;
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
