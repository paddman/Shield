using System.IO.Compression;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Core.Reliability;
using NTShield.Shared.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Transport;

public sealed class HttpsTransportClient : ITransportClient, IDisposable
{
    private readonly CentralServerOptions _options;
    private readonly ILogger<HttpsTransportClient> _logger;
    private readonly HttpClient _http;
    private readonly HttpClientHandler _handler;
    private readonly ExponentialBackoff _backoff = new();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public HttpsTransportClient(
        IOptions<CentralServerOptions> options,
        ILogger<HttpsTransportClient> logger)
    {
        _options = options.Value;
        _logger = logger;
        _handler = CreateHandler(_options);
        var baseUrl = string.IsNullOrWhiteSpace(_options.Url) ? "https://localhost:7443" : _options.Url;
        _http = new HttpClient(_handler)
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(Math.Max(5, _options.TimeoutSeconds))
        };
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NTShield-Agent/1.0");
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            SetApiKey(_options.ApiKey);
    }

    public void SetApiKey(string? apiKey)
    {
        _http.DefaultRequestHeaders.Remove("X-NTShield-Api-Key");
        if (!string.IsNullOrWhiteSpace(apiKey))
            _http.DefaultRequestHeaders.TryAddWithoutValidation("X-NTShield-Api-Key", apiKey.Trim());
    }

    public async Task<AgentRegistrationResponse?> RegisterAsync(AgentRegistrationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.PostAsJsonAsync("api/v1/agents/register", request, JsonOptions, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Register failed: {Status} {Body}", response.StatusCode, body);
                return null;
            }

            var reg = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>(JsonOptions, cancellationToken);
            if (reg?.Accepted == true && !string.IsNullOrWhiteSpace(reg.AgentApiKey))
            {
                SetApiKey(reg.AgentApiKey);
                _options.ApiKey = reg.AgentApiKey;
            }

            _backoff.Reset();
            return reg;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Register error to {Base}", _http.BaseAddress);
            return null;
        }
    }

    private static HttpClientHandler CreateHandler(CentralServerOptions options)
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        };

        if (options.AllowUntrustedServerCertificate)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        if (options.EnableMtls && !string.IsNullOrWhiteSpace(options.ClientCertificatePath))
        {
            if (!File.Exists(options.ClientCertificatePath))
            {
                throw new FileNotFoundException("Client certificate not found", options.ClientCertificatePath);
            }

            var cert = string.IsNullOrEmpty(options.ClientCertificatePassword)
                ? X509CertificateLoader.LoadPkcs12FromFile(options.ClientCertificatePath, null)
                : X509CertificateLoader.LoadPkcs12FromFile(options.ClientCertificatePath, options.ClientCertificatePassword);
            handler.ClientCertificates.Add(cert);
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        }

        return handler;
    }

    public async Task<bool> IsReachableAsync(CancellationToken cancellationToken)
    {
        // Single short probe — never stack two long HttpClient timeouts (was freezing AgentWorker).
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (!cancellationToken.CanBeCanceled)
            {
                linked.CancelAfter(TimeSpan.FromSeconds(5));
            }

            using var response = await _http.GetAsync("api/v1/health", linked.Token);
            if (response.IsSuccessStatusCode)
            {
                _backoff.Reset();
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Central health check failed base={Base}", _http.BaseAddress);
        }

        _logger.LogWarning("Central server unreachable at {Base} (queue stays local)", _http.BaseAddress);
        _ = _backoff.NextDelay();
        return false;
    }

    public async Task<IngestResponse?> SendBatchAsync(AgentIngestBatch batch, CancellationToken cancellationToken)
    {
        try
        {
            batch.IdempotencyKey ??= Guid.NewGuid().ToString("N");
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/ingest")
            {
                Content = CreateJsonContent(batch)
            };
            request.Headers.TryAddWithoutValidation("Idempotency-Key", batch.IdempotencyKey);

            using var response = await _http.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Ingest failed: {Status} {Body}", response.StatusCode, body);
                return null;
            }

            _backoff.Reset();
            return await response.Content.ReadFromJsonAsync<IngestResponse>(JsonOptions, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send ingest batch");
            return null;
        }
    }

    public async Task<HeartbeatResponse?> SendHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.PostAsJsonAsync("api/v1/agents/heartbeat", heartbeat, JsonOptions, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Heartbeat failed: {Status} {Body}", response.StatusCode, body);
                return null;
            }

            var hb = await response.Content.ReadFromJsonAsync<HeartbeatResponse>(JsonOptions, cancellationToken);
            if (hb is not null)
            {
                heartbeat.ClockSkewSeconds = hb.ClockSkewSeconds;
                if (ClockSkew.IsSignificant(TimeSpan.FromSeconds(hb.ClockSkewSeconds)))
                {
                    _logger.LogWarning("Clock skew vs server: {Seconds}s", hb.ClockSkewSeconds);
                }

                if (hb.PendingActions.Count > 0)
                {
                    _logger.LogWarning("Central delivered {Count} pending action(s)", hb.PendingActions.Count);
                }
            }

            _backoff.Reset();
            _logger.LogInformation("Heartbeat OK to {Base} agent={AgentId}", _http.BaseAddress, heartbeat.AgentId);
            return hb;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Heartbeat error to {Base} (offline mode continues)", _http.BaseAddress);
            return null;
        }
    }

    private static ByteArrayContent CreateJsonContent<T>(T value)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        // Prefer plain JSON for reliability. Central also accepts gzip (RequestDecompression),
        // but older Central builds returned 400 on Content-Encoding: gzip — that made Agent/Dashboard look disconnected.
        var plain = new ByteArrayContent(json);
        plain.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return plain;
    }

    public void Dispose()
    {
        _http.Dispose();
        _handler.Dispose();
    }
}
