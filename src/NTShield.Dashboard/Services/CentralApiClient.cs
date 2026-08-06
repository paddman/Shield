using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Dashboard.Services;

public sealed class CentralApiClient : IDisposable
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    public string BaseUrl { get; private set; }
    public string? ApiKey { get; private set; }

    public CentralApiClient(string baseUrl, string? apiKey = null)
    {
        BaseUrl = baseUrl.TrimEnd('/');
        ApiKey = apiKey;
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(BaseUrl + "/"),
            Timeout = TimeSpan.FromSeconds(15)
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NTShield-Dashboard/1.0");
        SetApiKey(apiKey);
    }

    public void SetBaseUrl(string baseUrl)
    {
        BaseUrl = baseUrl.TrimEnd('/');
        _http.BaseAddress = new Uri(BaseUrl + "/");
    }

    /// <summary>Operator API key (X-NTShield-Api-Key) — required when Central Security:RequireAuth=true.</summary>
    public void SetApiKey(string? apiKey)
    {
        ApiKey = apiKey;
        _http.DefaultRequestHeaders.Remove("X-NTShield-Api-Key");
        if (!string.IsNullOrWhiteSpace(apiKey))
            _http.DefaultRequestHeaders.TryAddWithoutValidation("X-NTShield-Api-Key", apiKey.Trim());
    }

    public async Task<bool> HealthAsync(CancellationToken ct = default)
    {
        var info = await GetHealthInfoAsync(ct);
        return info.Ok;
    }

    /// <summary>Health + Central product version from /api/v1/health</summary>
    public async Task<(bool Ok, string? Version, string? Product)> GetHealthInfoAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("api/v1/health", ct);
            if (!resp.IsSuccessStatusCode)
            {
                using var resp2 = await _http.GetAsync("health", ct);
                if (!resp2.IsSuccessStatusCode) return (false, null, null);
                var body2 = await resp2.Content.ReadAsStringAsync(ct);
                return (true, ParseVersion(body2), ParseProduct(body2));
            }

            var body = await resp.Content.ReadAsStringAsync(ct);
            return (true, ParseVersion(body), ParseProduct(body));
        }
        catch
        {
            return (false, null, null);
        }
    }

    private static string? ParseVersion(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("version", out var v)) return v.GetString();
            if (root.TryGetProperty("productVersion", out var pv)) return pv.GetString();
        }
        catch { /* ignore */ }
        return null;
    }

    private static string? ParseProduct(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("product", out var p)) return p.GetString();
        }
        catch { /* ignore */ }
        return null;
    }

    public async Task<List<Incident>> GetIncidentsAsync(int take = 100, CancellationToken ct = default)
    {
        try
        {
            var list = await _http.GetFromJsonAsync<List<Incident>>($"api/v1/incidents?take={take}", JsonOptions, ct);
            return list ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<List<ThreatCampaign>> GetThreatsAsync(int take = 100, CancellationToken ct = default)
    {
        try
        {
            var list = await _http.GetFromJsonAsync<List<ThreatCampaign>>($"api/v1/threats?take={take}", JsonOptions, ct);
            return list ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<List<ThreatCatalogEntry>> GetCatalogAsync(CancellationToken ct = default)
    {
        try
        {
            var list = await _http.GetFromJsonAsync<List<ThreatCatalogEntry>>("api/v1/threats/catalog", JsonOptions, ct);
            return list ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<List<object>> GetAgentsAsync(CancellationToken ct = default)
    {
        try
        {
            var list = await _http.GetFromJsonAsync<List<JsonElement>>("api/v1/agents", JsonOptions, ct);
            return list?.Cast<object>().ToList() ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<AgentInventoryItem?> GetAgentDetailAsync(string agentId, int metricsTake = 60, CancellationToken ct = default)
    {
        try
        {
            return await _http.GetFromJsonAsync<AgentInventoryItem>(
                $"api/v1/agents/{Uri.EscapeDataString(agentId)}?metrics={metricsTake}", JsonOptions, ct);
        }
        catch
        {
            return null;
        }
    }

    public async Task<List<AgentMetricsSample>> GetAgentMetricsAsync(string agentId, int take = 60, CancellationToken ct = default)
    {
        try
        {
            var list = await _http.GetFromJsonAsync<List<AgentMetricsSample>>(
                $"api/v1/agents/{Uri.EscapeDataString(agentId)}/metrics?take={take}", JsonOptions, ct);
            return list ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<ThreatCampaign?> GetThreatAsync(string id, CancellationToken ct = default)
    {
        try
        {
            return await _http.GetFromJsonAsync<ThreatCampaign>($"api/v1/threats/{id}", JsonOptions, ct);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Queue an approved response action for an agent (delivered on next heartbeat).
    /// </summary>
    public async Task<(bool Ok, string Message, ResponseActionRequest? Saved)> PostActionAsync(
        ResponseActionRequest request,
        CancellationToken ct = default)
    {
        try
        {
            request.Approved = true;
            request.ApprovalId ??= Guid.NewGuid().ToString("N");
            request.Requester = string.IsNullOrWhiteSpace(request.Requester)
                ? "dashboard-operator"
                : request.Requester;

            using var resp = await _http.PostAsJsonAsync("api/v1/actions", request, JsonOptions, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                return (false, $"{(int)resp.StatusCode}: {body}", null);
            }

            var saved = JsonSerializer.Deserialize<ResponseActionRequest>(body, JsonOptions);
            return (true, "queued for agent (next heartbeat)", saved ?? request);
        }
        catch (Exception ex)
        {
            return (false, ex.Message, null);
        }
    }

    public void Dispose() => _http.Dispose();
}
