using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace NTShield.Server.AI;

/// <summary>
/// Fail-open Central-side bridge for Phase 1 anomaly observations.
/// Only bounded numeric features are sent upstream; raw events, commands,
/// usernames and IP addresses stay in Central.
/// </summary>
public sealed class AiAnomalyProxyService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly AiAnomalyOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AiAnomalyProxyService> _logger;

    public AiAnomalyProxyService(
        IOptions<AiAnomalyOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<AiAnomalyProxyService> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured =>
        _options.Enabled && Uri.TryCreate(_options.BaseUrl, UriKind.Absolute, out var uri) &&
        (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));

    public async Task<AiAnomalyObservationResponse?> ObserveAsync(
        string centralTenantId,
        string assetId,
        IReadOnlyDictionary<string, double> features,
        DateTimeOffset timestampUtc,
        CancellationToken cancellationToken)
    {
        if (!IsConfigured || string.IsNullOrWhiteSpace(assetId) || features.Count == 0)
            return null;

        var brainTenantId = ResolveBrainTenantId(centralTenantId);
        var endpoint = $"{_options.BaseUrl.TrimEnd('/')}/v1/anomaly/observe";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(new
            {
                assetId,
                features,
                learn = _options.Learn,
                timestampUtc
            }, options: JsonOptions)
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("X-NTShield-Tenant", brainTenantId);
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            request.Headers.TryAddWithoutValidation("X-NTShield-Api-Key", _options.ApiKey);

        try
        {
            using var client = _httpClientFactory.CreateClient("ai-anomaly");
            client.Timeout = TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 30));
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "AI anomaly observation failed status={Status} tenant={TenantId} asset={AssetId}",
                    (int)response.StatusCode,
                    centralTenantId,
                    assetId);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<AiAnomalyObservationResponse>(
                JsonOptions,
                cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("AI anomaly observation timed out tenant={TenantId} asset={AssetId}",
                centralTenantId, assetId);
            return null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("AI anomaly service unreachable tenant={TenantId} asset={AssetId}: {Error}",
                centralTenantId, assetId, ex.Message);
            return null;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning("AI anomaly returned invalid response tenant={TenantId} asset={AssetId}: {Error}",
                centralTenantId, assetId, ex.Message);
            return null;
        }
    }

    private string ResolveBrainTenantId(string centralTenantId)
    {
        if (string.Equals(_options.TenantId.Trim(), "{tenant}", StringComparison.OrdinalIgnoreCase))
            return string.IsNullOrWhiteSpace(centralTenantId) ? "default" : centralTenantId.Trim();

        return string.IsNullOrWhiteSpace(_options.TenantId) ? "default" : _options.TenantId.Trim();
    }
}

public sealed class AiAnomalyObservationResponse
{
    public string AssetId { get; set; } = string.Empty;
    public string State { get; set; } = "learning";
    public double Score { get; set; }
    public double Confidence { get; set; }
    public int BaselineSamples { get; set; }
    public string Model { get; set; } = string.Empty;
    public List<AiAnomalyRiskSignal> Contributors { get; set; } = [];
}

public sealed class AiAnomalyRiskSignal
{
    public string Name { get; set; } = string.Empty;
    public double ScoreDelta { get; set; }
    public string Reason { get; set; } = string.Empty;
    public List<string> EvidenceRefs { get; set; } = [];
}
