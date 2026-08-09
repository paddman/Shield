using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NTShield.Server.Data;
using NTShield.Server.Security;

namespace NTShield.Server.LLM;

public sealed record LlmTokenSummary(
    string TokenId,
    string Name,
    string TokenPrefix,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ExpiresUtc,
    DateTimeOffset? RevokedUtc,
    DateTimeOffset? LastUsedUtc,
    long RequestCount);

public sealed record IssuedLlmToken(LlmTokenSummary Summary, string Token);

public sealed record LlmTokenAuthentication(string TokenId, string Name);

public sealed record LlmGatewayStatus(
    bool Enabled,
    string ProxyBaseUrl,
    string UpstreamBaseUrl,
    string Model,
    int ActiveTokenCount,
    bool? UpstreamReachable,
    IReadOnlyList<string> UpstreamModels,
    string? UpstreamError);

public sealed record LlmTokenCreateRequest(string? Name, int? ExpiresInDays);

/// <summary>
/// Durable token registry and constrained OpenAI-compatible reverse proxy.
/// Only token hashes are stored; upstream credentials stay in server configuration.
/// </summary>
public sealed class LlmGatewayService
{
    private const long MaxBufferedRequestBodyBytes = 20L * 1024 * 1024;
    private static readonly HashSet<string> AllowedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "models",
        "chat/completions",
        "completions",
        "embeddings"
    };

    private readonly LlmGatewayOptions _options;
    private readonly string _databasePath;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<LlmGatewayService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _initialized;

    public LlmGatewayService(
        IOptions<LlmGatewayOptions> options,
        IOptions<SqliteCentralOptions> sqlite,
        IHttpClientFactory httpClientFactory,
        ILogger<LlmGatewayService> logger)
    {
        _options = options.Value;
        _databasePath = sqlite.Value.DatabasePath;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public string ProxyBaseUrl => "/api/v1/llm/v1";

    public async Task InitializeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_initialized)
                return;

            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                CREATE TABLE IF NOT EXISTS llm_tokens (
                    token_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_utc TEXT NOT NULL,
                    expires_utc TEXT,
                    revoked_utc TEXT,
                    last_used_utc TEXT,
                    request_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS ix_llm_tokens_active
                    ON llm_tokens(revoked_utc, expires_utc, created_utc DESC);
                """;
            await cmd.ExecuteNonQueryAsync();
            _initialized = true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<LlmTokenSummary>> ListTokensAsync()
    {
        await EnsureInitializedAsync();
        var result = new List<LlmTokenSummary>();
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT token_id, name, token_prefix, created_utc, expires_utc,
                   revoked_utc, last_used_utc, request_count
            FROM llm_tokens
            ORDER BY created_utc DESC;
            """;
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            result.Add(ReadSummary(reader));
        }

        return result;
    }

    public async Task<IssuedLlmToken> CreateTokenAsync(string? requestedName, int? requestedLifetimeDays)
    {
        await EnsureInitializedAsync();
        var name = string.IsNullOrWhiteSpace(requestedName)
            ? "LLM Agent"
            : requestedName.Trim()[..Math.Min(requestedName.Trim().Length, 120)];
        var lifetimeDays = requestedLifetimeDays ?? _options.DefaultTokenLifetimeDays;
        lifetimeDays = Math.Clamp(lifetimeDays, 1, Math.Max(1, _options.MaxTokenLifetimeDays));

        var token = $"ntllm_{Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()}";
        var tokenId = Guid.NewGuid().ToString("N");
        var tokenPrefix = token[..Math.Min(18, token.Length)] + "…";
        var created = DateTimeOffset.UtcNow;
        var expires = created.AddDays(lifetimeDays);

        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO llm_tokens
                    (token_id, token_hash, token_prefix, name, created_utc, expires_utc)
                VALUES ($id, $hash, $prefix, $name, $created, $expires);
                """;
            cmd.Parameters.AddWithValue("$id", tokenId);
            cmd.Parameters.AddWithValue("$hash", SecretBootstrapper.HashApiKey(token));
            cmd.Parameters.AddWithValue("$prefix", tokenPrefix);
            cmd.Parameters.AddWithValue("$name", name);
            cmd.Parameters.AddWithValue("$created", created.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", expires.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally
        {
            _gate.Release();
        }

        var summary = new LlmTokenSummary(tokenId, name, tokenPrefix, created, expires, null, null, 0);
        return new IssuedLlmToken(summary, token);
    }

    public async Task<bool> RevokeTokenAsync(string tokenId)
    {
        await EnsureInitializedAsync();
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "UPDATE llm_tokens SET revoked_utc=$now WHERE token_id=$id AND revoked_utc IS NULL;";
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$id", tokenId);
            return await cmd.ExecuteNonQueryAsync() > 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<LlmTokenAuthentication?> AuthenticateTokenAsync(string? token)
    {
        if (!_options.Enabled || string.IsNullOrWhiteSpace(token))
            return null;

        await EnsureInitializedAsync();
        var now = DateTimeOffset.UtcNow;
        await _gate.WaitAsync();
        try
        {
            await using var conn = Open();
            await using var update = conn.CreateCommand();
            update.CommandText =
                """
                UPDATE llm_tokens
                SET last_used_utc=$now, request_count=request_count+1
                WHERE token_hash=$hash
                  AND revoked_utc IS NULL
                  AND (expires_utc IS NULL OR expires_utc > $now);
                """;
            update.Parameters.AddWithValue("$now", now.ToString("O"));
            update.Parameters.AddWithValue("$hash", SecretBootstrapper.HashApiKey(token.Trim()));
            if (await update.ExecuteNonQueryAsync() == 0)
                return null;

            await using var select = conn.CreateCommand();
            select.CommandText = "SELECT token_id, name FROM llm_tokens WHERE token_hash=$hash LIMIT 1;";
            select.Parameters.AddWithValue("$hash", SecretBootstrapper.HashApiKey(token.Trim()));
            await using var reader = await select.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
                return null;
            return new LlmTokenAuthentication(reader.GetString(0), reader.GetString(1));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<LlmGatewayStatus> GetStatusAsync()
    {
        await EnsureInitializedAsync();
        var active = 0;
        await using (var conn = Open())
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText =
                "SELECT COUNT(*) FROM llm_tokens WHERE revoked_utc IS NULL AND (expires_utc IS NULL OR expires_utc > $now);";
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            active = Convert.ToInt32(await cmd.ExecuteScalarAsync());
        }

        return new LlmGatewayStatus(
            _options.Enabled,
            ProxyBaseUrl,
            _options.BaseUrl.TrimEnd('/'),
            _options.Model,
            active,
            null,
            Array.Empty<string>(),
            null);
    }

    public async Task<LlmGatewayStatus> TestUpstreamAsync()
    {
        var status = await GetStatusAsync();
        if (!_options.Enabled)
            return status with { UpstreamReachable = false, UpstreamError = "gateway_disabled" };

        try
        {
            var started = Stopwatch.GetTimestamp();
            using var client = CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, BuildUpstreamUri("models", ""));
            AddUpstreamHeaders(request);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

            // Some OpenAI-compatible services expose only chat completions and
            // return 404 for /models. Probe the configured chat route with an
            // empty message list so no model generation is started.
            if (response.StatusCode == HttpStatusCode.NotFound && !string.IsNullOrWhiteSpace(_options.Model))
            {
                using var chatRequest = new HttpRequestMessage(
                    HttpMethod.Post,
                    BuildUpstreamUri("chat/completions", ""));
                AddUpstreamHeaders(chatRequest);
                chatRequest.Content = new StringContent(
                    JsonSerializer.Serialize(new { model = _options.Model, messages = Array.Empty<object>() }),
                    System.Text.Encoding.UTF8,
                    "application/json");

                using var chatResponse = await client.SendAsync(
                    chatRequest,
                    HttpCompletionOption.ResponseHeadersRead);
                var chatStatus = (int)chatResponse.StatusCode;
                if (chatStatus is >= 400 and < 500 && chatResponse.StatusCode != HttpStatusCode.Unauthorized &&
                    chatResponse.StatusCode != HttpStatusCode.Forbidden && chatResponse.StatusCode != HttpStatusCode.NotFound)
                {
                    _logger.LogInformation(
                        "LLM upstream chat endpoint reachable; /models is not implemented status={Status} latencyMs={Latency}",
                        chatStatus,
                        Stopwatch.GetElapsedTime(started).TotalMilliseconds);
                    return status with
                    {
                        UpstreamReachable = true,
                        UpstreamModels = new[] { _options.Model },
                        UpstreamError = null
                    };
                }
            }

            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var document = await JsonDocument.ParseAsync(stream);
            var models = document.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array
                ? data.EnumerateArray()
                    .Select(item => item.TryGetProperty("id", out var id) ? id.GetString() : null)
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Cast<string>()
                    .Take(50)
                    .ToArray()
                : Array.Empty<string>();
            _logger.LogInformation("LLM upstream health check succeeded status={Status} models={Count} latencyMs={Latency}",
                (int)response.StatusCode, models.Length, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            return status with { UpstreamReachable = true, UpstreamModels = models, UpstreamError = null };
        }
        catch (Exception ex)
        {
            _logger.LogWarning("LLM upstream health check failed: {Error}", ex.Message);
            return status with { UpstreamReachable = false, UpstreamError = ex.Message[..Math.Min(300, ex.Message.Length)] };
        }
    }

    public async Task ProxyAsync(HttpContext http, string? relativePath)
    {
        if (!_options.Enabled)
        {
            await WriteErrorAsync(http, StatusCodes.Status503ServiceUnavailable, "llm_gateway_disabled");
            return;
        }

        var path = (relativePath ?? "").Trim('/');
        if (!AllowedPaths.Contains(path))
        {
            await WriteErrorAsync(http, StatusCodes.Status404NotFound, "llm_route_not_allowed");
            return;
        }

        if (path == "models" && !HttpMethods.IsGet(http.Request.Method))
        {
            await WriteErrorAsync(http, StatusCodes.Status405MethodNotAllowed, "models_get_only");
            return;
        }

        if (path != "models" && !HttpMethods.IsPost(http.Request.Method))
        {
            await WriteErrorAsync(http, StatusCodes.Status405MethodNotAllowed, "llm_inference_post_only");
            return;
        }

        try
        {
            using var client = CreateClient();
            using var upstreamRequest = new HttpRequestMessage(new HttpMethod(http.Request.Method),
                BuildUpstreamUri(path, http.Request.QueryString.Value));
            AddUpstreamHeaders(upstreamRequest);

            if (HttpMethods.IsPost(http.Request.Method))
            {
                // Request decompression runs before this proxy. Buffer the
                // resulting stream with a hard ceiling so the upstream receives
                // the decompressed byte count rather than the original encoded
                // Content-Length. SOC-Qwen rejects chunked request bodies.
                byte[]? requestBody;
                try
                {
                    requestBody = await ReadBoundedRequestBodyAsync(http, http.RequestAborted);
                }
                catch (InvalidDataException ex)
                {
                    _logger.LogWarning("LLM proxy rejected malformed compressed request body: {Error}", ex.Message);
                    await WriteErrorAsync(
                        http,
                        StatusCodes.Status400BadRequest,
                        "invalid_compressed_request_body");
                    return;
                }
                catch (BadHttpRequestException ex) when (
                    ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
                {
                    _logger.LogWarning("LLM proxy rejected decompressed request over the server limit: {Error}", ex.Message);
                    await WriteErrorAsync(
                        http,
                        StatusCodes.Status413PayloadTooLarge,
                        "llm_request_too_large");
                    return;
                }
                catch (InvalidOperationException ex)
                {
                    // Brotli/deflate decoder failures can surface as
                    // InvalidOperationException while the decompression stream is
                    // read. Size overruns are handled above as HTTP 413.
                    _logger.LogWarning("LLM proxy rejected malformed compressed request body: {Error}", ex.Message);
                    await WriteErrorAsync(
                        http,
                        StatusCodes.Status400BadRequest,
                        "invalid_compressed_request_body");
                    return;
                }
                if (requestBody is null)
                {
                    await WriteErrorAsync(
                        http,
                        StatusCodes.Status413PayloadTooLarge,
                        "llm_request_too_large");
                    return;
                }

                upstreamRequest.Content = new ByteArrayContent(requestBody);
                upstreamRequest.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
                    string.IsNullOrWhiteSpace(http.Request.ContentType) ? "application/json" : http.Request.ContentType);
                upstreamRequest.Content.Headers.ContentLength = requestBody.LongLength;
            }

            using var upstreamResponse = await client.SendAsync(
                upstreamRequest,
                HttpCompletionOption.ResponseHeadersRead,
                http.RequestAborted);
            http.Response.StatusCode = (int)upstreamResponse.StatusCode;
            foreach (var header in upstreamResponse.Headers)
                http.Response.Headers[header.Key] = header.Value.ToArray();
            foreach (var header in upstreamResponse.Content.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    continue;
                http.Response.Headers[header.Key] = header.Value.ToArray();
            }

            await using var stream = await upstreamResponse.Content.ReadAsStreamAsync(http.RequestAborted);
            await stream.CopyToAsync(http.Response.Body, http.RequestAborted);
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
        {
            // Client disconnected; there is no response left to write.
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning("LLM upstream timed out: {Error}", ex.Message);
            await WriteErrorAsync(http, StatusCodes.Status504GatewayTimeout, "llm_upstream_timeout");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("LLM upstream unavailable: {Error}", ex.Message);
            await WriteErrorAsync(http, StatusCodes.Status502BadGateway, "llm_upstream_unreachable");
        }
    }

    private static async Task<byte[]?> ReadBoundedRequestBodyAsync(
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var serverLimit = http.Features.Get<IHttpMaxRequestBodySizeFeature>()?.MaxRequestBodySize;
        var limit = serverLimit.HasValue
            ? Math.Min(serverLimit.Value, MaxBufferedRequestBodyBytes)
            : MaxBufferedRequestBodyBytes;
        if (limit < 0)
            limit = MaxBufferedRequestBodyBytes;

        await using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        long total = 0;
        while (true)
        {
            var read = await http.Request.Body.ReadAsync(chunk, cancellationToken);
            if (read == 0)
                break;

            total += read;
            if (total > limit)
                return null;

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        return buffer.ToArray();
    }

    private HttpClient CreateClient()
    {
        var client = _httpClientFactory.CreateClient("llm-gateway");
        client.Timeout = TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 5, 600));
        return client;
    }

    private void AddUpstreamHeaders(HttpRequestMessage request)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("NTShield-LLM-Gateway/1.0");
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
    }

    private Uri BuildUpstreamUri(string path, string? query)
    {
        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var uri = $"{baseUrl}/{path}";
        if (!string.IsNullOrWhiteSpace(query))
            uri += query.StartsWith('?') ? query : $"?{query}";
        return new Uri(uri, UriKind.Absolute);
    }

    private SqliteConnection Open()
    {
        var dir = Path.GetDirectoryName(_databasePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString());
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private async Task EnsureInitializedAsync()
    {
        if (!_initialized)
            await InitializeAsync();
    }

    private static LlmTokenSummary ReadSummary(SqliteDataReader reader)
    {
        return new LlmTokenSummary(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            DateTimeOffset.Parse(reader.GetString(3)),
            ParseNullableDate(reader, 4),
            ParseNullableDate(reader, 5),
            ParseNullableDate(reader, 6),
            reader.GetInt64(7));
    }

    private static DateTimeOffset? ParseNullableDate(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTimeOffset.Parse(reader.GetString(ordinal));

    private static async Task WriteErrorAsync(HttpContext http, int code, string error)
    {
        if (http.Response.HasStarted)
            return;
        http.Response.StatusCode = code;
        http.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(http.Response.Body, new { error });
    }
}
