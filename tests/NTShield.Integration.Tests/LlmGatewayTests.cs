using System.Net.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Data;
using NTShield.Server.LLM;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class LlmGatewayTests
{
    [Fact]
    public async Task Token_Is_Stored_Hashed_And_Can_Be_Revoked()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ntshield-llm-{Guid.NewGuid():N}.db");
        try
        {
            var gateway = CreateGateway(path);
            await gateway.InitializeAsync();

            var issued = await gateway.CreateTokenAsync("Linux agent", 30);
            Assert.StartsWith("ntllm_", issued.Token);
            Assert.DoesNotContain(issued.Token, issued.Summary.TokenPrefix);
            Assert.NotNull(await gateway.AuthenticateTokenAsync(issued.Token));

            var listed = await gateway.ListTokensAsync();
            var summary = Assert.Single(listed);
            Assert.Equal(issued.Summary.TokenId, summary.TokenId);
            Assert.Equal(1, summary.RequestCount);

            Assert.True(await gateway.RevokeTokenAsync(summary.TokenId));
            Assert.Null(await gateway.AuthenticateTokenAsync(issued.Token));
            Assert.False(await gateway.RevokeTokenAsync(summary.TokenId));
        }
        finally
        {
            TryDelete(path);
            TryDelete(path + "-wal");
            TryDelete(path + "-shm");
        }
    }

    [Fact]
    public async Task Expired_Token_Is_Rejected()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ntshield-llm-{Guid.NewGuid():N}.db");
        try
        {
            var gateway = CreateGateway(path);
            await gateway.InitializeAsync();
            var issued = await gateway.CreateTokenAsync("Short-lived agent", 1);
            await using (var conn = new SqliteConnection($"Data Source={path}"))
            {
                await conn.OpenAsync();
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = "UPDATE llm_tokens SET expires_utc=$expired WHERE token_id=$id";
                cmd.Parameters.AddWithValue("$expired", DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"));
                cmd.Parameters.AddWithValue("$id", issued.Summary.TokenId);
                await cmd.ExecuteNonQueryAsync();
            }

            Assert.Null(await gateway.AuthenticateTokenAsync(issued.Token));
        }
        finally
        {
            TryDelete(path);
            TryDelete(path + "-wal");
            TryDelete(path + "-shm");
        }
    }

    private static LlmGatewayService CreateGateway(string path) =>
        new(
            Options.Create(new LlmGatewayOptions
            {
                Enabled = true,
                BaseUrl = "http://127.0.0.1:8000/v1"
            }),
            Options.Create(new SqliteCentralOptions { DatabasePath = path }),
            new TestHttpClientFactory(),
            NullLogger<LlmGatewayService>.Instance);

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Best effort cleanup for a test database still held by SQLite.
        }
    }

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }
}
