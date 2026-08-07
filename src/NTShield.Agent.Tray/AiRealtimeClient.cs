using System.Globalization;
using System.Net;
using System.Text.Json;

namespace NTShield.Agent.Tray;

internal sealed class AiConsoleConfig
{
    public bool Enabled { get; set; } = true;
    public string BrainUrl { get; set; } = "http://127.0.0.1:8088";
    public string TenantId { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public int RefreshSeconds { get; set; } = 5;

    public static AiConsoleConfig Load(string installDir)
    {
        var config = new AiConsoleConfig();
        try
        {
            var path = Path.Combine(installDir, "appsettings.json");
            if (File.Exists(path))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("AiConsole", out var section))
                {
                    config.Enabled = GetBool(section, "Enabled", config.Enabled);
                    config.BrainUrl = GetString(section, "BrainUrl") ?? config.BrainUrl;
                    config.TenantId = GetString(section, "TenantId") ?? config.TenantId;
                    config.ApiKey = GetString(section, "ApiKey") ?? config.ApiKey;
                    config.RefreshSeconds = GetInt(section, "RefreshSeconds", config.RefreshSeconds);
                }
            }
        }
        catch
        {
            // Keep safe defaults when appsettings is unavailable or malformed.
        }

        config.BrainUrl = Environment.GetEnvironmentVariable("NTSHIELD_BRAIN_URL") ?? config.BrainUrl;
        config.TenantId = Environment.GetEnvironmentVariable("NTSHIELD_BRAIN_TENANT") ?? config.TenantId;
        config.ApiKey = Environment.GetEnvironmentVariable("NTSHIELD_BRAIN_API_KEY") ?? config.ApiKey;
        config.RefreshSeconds = Math.Clamp(config.RefreshSeconds, 3, 60);
        return config;
    }

    private static string? GetString(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool GetBool(JsonElement parent, string name, bool fallback) =>
        parent.TryGetProperty(name, out var value) &&
        value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;

    private static int GetInt(JsonElement parent, string name, int fallback) =>
        parent.TryGetProperty(name, out var value) && value.TryGetInt32(out var number)
            ? number
            : fallback;
}

internal sealed class AiRealtimeSnapshot
{
    public bool BrainReachable { get; init; }
    public bool LlmReachable { get; init; }
    public bool CredentialsConfigured { get; init; }
    public string BrainUrl { get; init; } = string.Empty;
    public string LlmModel { get; init; } = "—";
    public string StatusMessage { get; init; } = string.Empty;
    public DateTimeOffset FetchedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<AiAnalysisItem> Analyses { get; init; } = [];
}

internal sealed class AiAnalysisItem
{
    public string IncidentId { get; init; } = string.Empty;
    public string Classification { get; init; } = "Unclassified";
    public string SummaryThai { get; init; } = string.Empty;
    public string SummaryEnglish { get; init; } = string.Empty;
    public string Model { get; init; } = "deterministic-fallback";
    public string AnalysisMode { get; init; } = "single";
    public int RiskScore { get; init; }
    public double Confidence { get; init; }
    public DateTimeOffset? CreatedAtUtc { get; init; }
    public bool DeterministicFallback { get; init; }
    public int LlmCalls { get; init; }
    public IReadOnlyList<string> AttackChain { get; init; } = [];
    public IReadOnlyList<string> MitreTechniques { get; init; } = [];
    public IReadOnlyList<string> RecommendedActions { get; init; } = [];
    public IReadOnlyList<string> Evidence { get; init; } = [];
    public IReadOnlyList<string> Unknowns { get; init; } = [];
}

internal sealed class AiRealtimeClient : IDisposable
{
    private readonly AiConsoleConfig _config;
    private readonly HttpClient _http;

    public AiRealtimeClient(AiConsoleConfig config)
    {
        _config = config;
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
    }

    public async Task<AiRealtimeSnapshot> ReadAsync(CancellationToken cancellationToken)
    {
        var baseUrl = (_config.BrainUrl ?? string.Empty).Trim().TrimEnd('/');
        if (!_config.Enabled)
        {
            return Offline(baseUrl, "AI console is disabled in configuration.");
        }

        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out _))
        {
            return Offline(baseUrl, "Brain URL is invalid.");
        }

        try
        {
            using var health = await _http.GetAsync(baseUrl + "/health", cancellationToken);
            if (!health.IsSuccessStatusCode)
            {
                return Offline(baseUrl, $"Brain returned HTTP {(int)health.StatusCode}.");
            }

            using var healthDoc = JsonDocument.Parse(await health.Content.ReadAsStringAsync(cancellationToken));
            var healthRoot = healthDoc.RootElement;
            var llm = healthRoot.TryGetProperty("llm", out var llmElement)
                ? llmElement
                : default;
            var llmReachable = GetBool(llm, "reachable", false);
            var model = GetString(llm, "model") ?? "—";

            if (string.IsNullOrWhiteSpace(_config.TenantId) || string.IsNullOrWhiteSpace(_config.ApiKey))
            {
                return new AiRealtimeSnapshot
                {
                    BrainReachable = true,
                    LlmReachable = llmReachable,
                    CredentialsConfigured = false,
                    BrainUrl = baseUrl,
                    LlmModel = model,
                    StatusMessage = "Brain online; configure tenant/API key to read AI analyses.",
                    Analyses = []
                };
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, baseUrl + "/v1/analyses?limit=50");
            request.Headers.TryAddWithoutValidation("X-NTShield-Tenant", _config.TenantId);
            request.Headers.TryAddWithoutValidation("X-NTShield-Api-Key", _config.ApiKey);
            using var analysesResponse = await _http.SendAsync(request, cancellationToken);
            if (!analysesResponse.IsSuccessStatusCode)
            {
                var message = analysesResponse.StatusCode == HttpStatusCode.Unauthorized
                    ? "Brain online; tenant/API key rejected."
                    : $"Brain analysis endpoint returned HTTP {(int)analysesResponse.StatusCode}.";
                return new AiRealtimeSnapshot
                {
                    BrainReachable = true,
                    LlmReachable = llmReachable,
                    CredentialsConfigured = true,
                    BrainUrl = baseUrl,
                    LlmModel = model,
                    StatusMessage = message,
                    Analyses = []
                };
            }

            using var analysesDoc = JsonDocument.Parse(await analysesResponse.Content.ReadAsStringAsync(cancellationToken));
            var analyses = analysesDoc.RootElement.ValueKind == JsonValueKind.Array
                ? analysesDoc.RootElement.EnumerateArray().Select(ParseAnalysis).ToList()
                : [];
            return new AiRealtimeSnapshot
            {
                BrainReachable = true,
                LlmReachable = llmReachable,
                CredentialsConfigured = true,
                BrainUrl = baseUrl,
                LlmModel = model,
                StatusMessage = analyses.Count == 0
                    ? "Brain online; no AI analysis has been recorded yet."
                    : $"Brain online; {analyses.Count} recent AI analyses loaded.",
                Analyses = analyses
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Offline(baseUrl, "Brain unreachable: " + ex.Message);
        }
    }

    public void Dispose() => _http.Dispose();

    private static AiRealtimeSnapshot Offline(string baseUrl, string message) => new()
    {
        BrainUrl = baseUrl,
        StatusMessage = message,
        CredentialsConfigured = false,
        Analyses = []
    };

    private static AiAnalysisItem ParseAnalysis(JsonElement item)
    {
        var evidence = item.TryGetProperty("evidence", out var evidenceElement) &&
                       evidenceElement.ValueKind == JsonValueKind.Array
            ? evidenceElement.EnumerateArray()
                .Select(value => GetString(value, "refId") ?? GetString(value, "ref_id") ?? value.ToString())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToList()
            : [];
        var actions = item.TryGetProperty("recommendedActions", out var actionElement) &&
                      actionElement.ValueKind == JsonValueKind.Array
            ? actionElement.EnumerateArray()
                .Select(value =>
                {
                    var action = GetString(value, "action") ?? "action";
                    var reason = GetString(value, "reason");
                    return string.IsNullOrWhiteSpace(reason) ? action : $"{action}: {reason}";
                })
                .ToList()
            : [];
        return new AiAnalysisItem
        {
            IncidentId = GetString(item, "incidentId") ?? GetString(item, "incident_id") ?? "—",
            Classification = GetString(item, "classification") ?? "Unclassified",
            SummaryThai = GetString(item, "summaryTh") ?? GetString(item, "summary_th") ?? string.Empty,
            SummaryEnglish = GetString(item, "summaryEn") ?? GetString(item, "summary_en") ?? string.Empty,
            Model = GetString(item, "model") ?? "deterministic-fallback",
            AnalysisMode = GetString(item, "analysisMode") ?? GetString(item, "analysis_mode") ?? "single",
            RiskScore = GetInt(item, "riskScore", 0),
            Confidence = GetDouble(item, "confidence", 0),
            CreatedAtUtc = GetTime(item, "createdAtUtc") ?? GetTime(item, "created_at_utc"),
            DeterministicFallback = GetBool(item, "deterministicFallback", false),
            LlmCalls = GetInt(item, "llmCalls", 0),
            AttackChain = GetStringList(item, "attackChain", "attack_chain"),
            MitreTechniques = GetStringList(item, "mitreTechniques", "mitre_techniques"),
            RecommendedActions = actions,
            Evidence = evidence,
            Unknowns = GetStringList(item, "unknowns")
        };
    }

    private static string? GetString(JsonElement parent, string name) =>
        parent.ValueKind != JsonValueKind.Undefined &&
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool GetBool(JsonElement parent, string name, bool fallback) =>
        parent.ValueKind != JsonValueKind.Undefined &&
        parent.TryGetProperty(name, out var value) &&
        value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;

    private static int GetInt(JsonElement parent, string name, int fallback) =>
        parent.ValueKind != JsonValueKind.Undefined &&
        parent.TryGetProperty(name, out var value) && value.TryGetInt32(out var number)
            ? number
            : fallback;

    private static double GetDouble(JsonElement parent, string name, double fallback) =>
        parent.ValueKind != JsonValueKind.Undefined &&
        parent.TryGetProperty(name, out var value) && value.TryGetDouble(out var number)
            ? number
            : fallback;

    private static DateTimeOffset? GetTime(JsonElement parent, string name)
    {
        var value = GetString(parent, name);
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time)
            ? time
            : null;
    }

    private static IReadOnlyList<string> GetStringList(JsonElement parent, params string[] names)
    {
        foreach (var name in names)
        {
            if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
                continue;
            return value.EnumerateArray()
                .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .ToList()!;
        }

        return [];
    }
}
