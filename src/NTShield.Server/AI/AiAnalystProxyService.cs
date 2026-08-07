using System.Net.Http.Headers;
using Microsoft.Extensions.Options;

namespace NTShield.Server.AI;

public sealed class AiAnalystProxyException : Exception
{
    public AiAnalystProxyException(int statusCode, string error)
        : base(error)
    {
        StatusCode = statusCode;
        Error = error;
    }

    public int StatusCode { get; }
    public string Error { get; }
}

/// <summary>
/// Narrow Central-side proxy for the Brain incident analysis endpoint.
/// No upstream LLM secret is exposed to the web client.
/// </summary>
public sealed class AiAnalystProxyService
{
    private readonly AiAnalystOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AiAnalystProxyService> _logger;

    public AiAnalystProxyService(
        IOptions<AiAnalystOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<AiAnalystProxyService> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured =>
        _options.Enabled && Uri.TryCreate(_options.BaseUrl, UriKind.Absolute, out var uri) &&
        (string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase));

    public string TenantId => string.IsNullOrWhiteSpace(_options.TenantId) ? "default" : _options.TenantId.Trim();

    public async Task<string> AnalyzeIncidentAsync(
        string incidentId,
        string tenantId,
        CancellationToken cancellationToken)
    {
        if (!IsConfigured)
            throw new AiAnalystProxyException(StatusCodes.Status503ServiceUnavailable, "ai_analyst_not_configured");

        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var endpoint = $"{baseUrl}/v1/central/incidents/{Uri.EscapeDataString(incidentId)}/analyze";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("X-NTShield-Tenant", tenantId);
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            request.Headers.TryAddWithoutValidation("X-NTShield-Api-Key", _options.ApiKey);

        try
        {
            using var client = _httpClientFactory.CreateClient("ai-analyst");
            client.Timeout = TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 5, 300));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("AI Analyst proxy failed status={Status} incident={IncidentId}",
                    (int)response.StatusCode, incidentId);
                throw new AiAnalystProxyException((int)response.StatusCode, ExtractError(body));
            }

            return body;
        }
        catch (AiAnalystProxyException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AiAnalystProxyException(StatusCodes.Status504GatewayTimeout, "ai_analyst_timeout");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("AI Analyst proxy unreachable incident={IncidentId}: {Error}", incidentId, ex.Message);
            throw new AiAnalystProxyException(StatusCodes.Status502BadGateway, "ai_analyst_unreachable");
        }
    }

    private static string ExtractError(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "ai_analyst_failed";
        return body.Length > 300 ? body[..300] : body;
    }
}
