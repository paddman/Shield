using System.Net.Http;
using System.IO.Compression;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
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

    [Fact]
    public async Task Proxy_Buffers_Decompressed_Body_And_Sends_Actual_Content_Length()
    {
        var payload = Encoding.UTF8.GetBytes("""{"model":"qwen3.5:9b","messages":[]}""");
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(payload, encodedContentLength: 12);

        await gateway.ProxyAsync(context, "chat/completions");

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(payload.LongLength, handler.ContentLength);
        Assert.Equal(payload, handler.Body);
    }

    [Fact]
    public async Task Proxy_Through_RequestDecompression_Sends_Decompressed_Length()
    {
        var payload = Encoding.UTF8.GetBytes(
            $$"""{"model":"qwen3.5:9b","messages":[{"role":"user","content":"{{new string('x', 4096)}}"}]}""");
        var compressed = Gzip(payload);
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(compressed, compressed.LongLength);
        context.Request.Headers.ContentEncoding = "gzip";

        await BuildDecompressionPipeline(gateway)(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.True(compressed.Length < payload.Length);
        Assert.Equal(payload.LongLength, handler.ContentLength);
        Assert.Equal(payload, handler.Body);
    }

    [Fact]
    public async Task Proxy_Through_RequestDecompression_Rejects_Malformed_Gzip()
    {
        var body = Encoding.UTF8.GetBytes("not-a-gzip-stream");
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(body, body.LongLength);
        context.Request.Headers.ContentEncoding = "gzip";

        await BuildDecompressionPipeline(gateway)(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.Equal(0, handler.RequestCount);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        Assert.Contains("invalid_compressed_request_body", await reader.ReadToEndAsync());
    }

    [Fact]
    public async Task Proxy_Through_RequestDecompression_Rejects_Malformed_Brotli()
    {
        var body = Encoding.UTF8.GetBytes("not-a-brotli-stream");
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(body, body.LongLength);
        context.Request.Headers.ContentEncoding = "br";

        await BuildDecompressionPipeline(gateway)(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.Equal(0, handler.RequestCount);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        Assert.Contains("invalid_compressed_request_body", await reader.ReadToEndAsync());
    }

    [Fact]
    public async Task Proxy_Through_RequestDecompression_Rejects_Decompressed_Body_Over_Server_Limit()
    {
        var payload = Encoding.UTF8.GetBytes(new string('x', 4096));
        var compressed = Gzip(payload);
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(compressed, compressed.LongLength);
        context.Request.Headers.ContentEncoding = "gzip";
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(new TestRequestBodySizeFeature
        {
            MaxRequestBodySize = 512
        });

        await BuildDecompressionPipeline(gateway)(context);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Equal(0, handler.RequestCount);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        Assert.Contains("llm_request_too_large", await reader.ReadToEndAsync());
    }

    [Fact]
    public async Task Proxy_Rejects_Request_That_Exceeds_Buffer_Limit()
    {
        var handler = new RecordingHandler();
        var gateway = CreateGateway("unused.db", new HandlerHttpClientFactory(handler));
        var context = CreateProxyContext(Encoding.UTF8.GetBytes("123456789"), encodedContentLength: 9);
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(new TestRequestBodySizeFeature
        {
            MaxRequestBodySize = 8
        });

        await gateway.ProxyAsync(context, "chat/completions");

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Equal(0, handler.RequestCount);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        Assert.Contains("llm_request_too_large", await reader.ReadToEndAsync());
    }

    private static LlmGatewayService CreateGateway(string path, IHttpClientFactory? httpClientFactory = null) =>
        new(
            Options.Create(new LlmGatewayOptions
            {
                Enabled = true,
                BaseUrl = "http://127.0.0.1:8000/v1"
            }),
            Options.Create(new SqliteCentralOptions { DatabasePath = path }),
            httpClientFactory ?? new TestHttpClientFactory(),
            NullLogger<LlmGatewayService>.Instance);

    private static DefaultHttpContext CreateProxyContext(byte[] body, long encodedContentLength)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = encodedContentLength;
        context.Request.Body = new MemoryStream(body);
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static RequestDelegate BuildDecompressionPipeline(LlmGatewayService gateway)
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddRequestDecompression()
            .BuildServiceProvider();
        var app = new ApplicationBuilder(services);
        app.UseRequestDecompression();
        app.Run(context => gateway.ProxyAsync(context, "chat/completions"));
        return app.Build();
    }

    private static byte[] Gzip(byte[] payload)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(payload);
        return output.ToArray();
    }

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

    private sealed class HandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public long? ContentLength { get; private set; }
        public byte[] Body { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            ContentLength = request.Content?.Headers.ContentLength;
            Body = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class TestRequestBodySizeFeature : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly => false;
        public long? MaxRequestBodySize { get; set; }
    }
}
