using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;

namespace NTShield.Server.Capture;

/// <summary>
/// Adapter for a server-configured capture bridge. The bridge owns vendor-specific
/// Arkime, MinIO and Squid APIs and exposes the bounded contract documented by NTShield.
/// </summary>
public sealed class HttpCaptureProviderAdapter : ICaptureProviderAdapter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly CaptureProviderOptions _provider;
    private readonly CaptureControlOptions _control;
    private readonly IHttpClientFactory _httpClientFactory;

    public HttpCaptureProviderAdapter(
        CaptureProviderOptions provider,
        CaptureControlOptions control,
        IHttpClientFactory httpClientFactory)
    {
        _provider = provider;
        _control = control;
        _httpClientFactory = httpClientFactory;
        BaseUri = ValidateBaseUri(provider.BaseUrl);
        Capabilities = new HashSet<string>(provider.Capabilities ?? [], StringComparer.OrdinalIgnoreCase);
    }

    private Uri BaseUri { get; }
    public string ProviderId => _provider.Id;
    public string Kind => _provider.Kind;
    public bool FailOpen => _provider.FailOpen;
    public IReadOnlySet<string> Capabilities { get; }

    public async Task<CaptureProviderHealth> ProbeAsync(CancellationToken cancellationToken)
    {
        try
        {
            var health = await SendAsync<CaptureProviderHealth>(
                HttpMethod.Get,
                _provider.HealthPath,
                body: null,
                cancellationToken);
            health.ProviderId = ProviderId;
            health.Kind = Kind;
            health.CheckedAtUtc = DateTimeOffset.UtcNow;
            health.FailOpen = FailOpen;
            health.CapacityBytes = health.CapacityBytes > 0 ? health.CapacityBytes : _provider.CapacityBytes;
            health.MaxSustainableIngressMbps = health.MaxSustainableIngressMbps > 0
                ? health.MaxSustainableIngressMbps
                : _provider.MaxSustainableIngressMbps;
            health.Capabilities = Capabilities.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToList();
            health.ActiveVisibilityGapReasonCodes = (health.ActiveVisibilityGapReasonCodes ?? [])
                .Where(CaptureGapReasonCodes.ProviderReported.Contains)
                .Distinct(StringComparer.Ordinal)
                .Take(20)
                .ToList();
            if (health.StoragePressure == CaptureStoragePressureState.Critical)
            {
                health.StorageCriticalMetadataOnly = true;
                if (!health.ActiveVisibilityGapReasonCodes.Contains(CaptureGapReasonCodes.StorageCriticalMetadataOnly, StringComparer.Ordinal))
                    health.ActiveVisibilityGapReasonCodes.Add(CaptureGapReasonCodes.StorageCriticalMetadataOnly);
            }
            return health;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            return new CaptureProviderHealth
            {
                ProviderId = ProviderId,
                Kind = Kind,
                State = CaptureProviderState.Unavailable,
                CheckedAtUtc = DateTimeOffset.UtcNow,
                CapacityBytes = _provider.CapacityBytes,
                MaxSustainableIngressMbps = _provider.MaxSustainableIngressMbps,
                StatusCode = ex is TaskCanceledException ? "probe_timeout" : "probe_failed",
                FailOpen = FailOpen,
                Capabilities = Capabilities.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToList()
            };
        }
    }

    public Task<CaptureProviderSessionPage> FetchSessionMetadataAsync(
        string? cursor,
        int take,
        CancellationToken cancellationToken)
    {
        var uri = QueryHelpers.AddQueryString(_provider.SessionsPath, "take", take.ToString());
        if (!string.IsNullOrWhiteSpace(cursor)) uri = QueryHelpers.AddQueryString(uri, "cursor", cursor);
        return SendAsync<CaptureProviderSessionPage>(HttpMethod.Get, uri, null, cancellationToken);
    }

    public Task ApplyPolicyAsync(CapturePolicy policy, CancellationToken cancellationToken) =>
        SendNoContentAsync(HttpMethod.Put, _provider.PolicyPath, policy, cancellationToken);

    public Task DeletePolicyAsync(string tenantId, string policyId, CancellationToken cancellationToken)
    {
        var path = $"{_provider.PolicyPath.TrimEnd('/')}/{Uri.EscapeDataString(policyId)}";
        path = QueryHelpers.AddQueryString(path, "tenantId", tenantId);
        return SendNoContentAsync(HttpMethod.Delete, path, new { }, cancellationToken);
    }

    public Task<ProviderAccessGrant> CreateSessionAccessAsync(
        ProviderSessionAccessRequest request,
        CancellationToken cancellationToken) =>
        SendAsync<ProviderAccessGrant>(HttpMethod.Post, _provider.AccessPath, request, cancellationToken);

    public Task<ProviderAccessGrant> CreateTlsArtifactAccessAsync(
        ProviderTlsArtifactAccessRequest request,
        CancellationToken cancellationToken) =>
        SendAsync<ProviderAccessGrant>(HttpMethod.Post, _provider.AccessPath, request, cancellationToken);

    public Task<TlsDecodedPreview> GetTlsPreviewAsync(
        ProviderTlsPreviewRequest request,
        CancellationToken cancellationToken) =>
        SendAsync<TlsDecodedPreview>(HttpMethod.Post, _provider.TlsPreviewPath, request, cancellationToken);

    public Task<ProviderExportResult> StartExportAsync(
        ProviderExportRequest request,
        CancellationToken cancellationToken) =>
        SendAsync<ProviderExportResult>(HttpMethod.Post, _provider.ExportPath, request, cancellationToken);

    public Task<ProviderAccessGrant> CreateExportAccessAsync(
        ProviderExportAccessRequest request,
        CancellationToken cancellationToken) =>
        SendAsync<ProviderAccessGrant>(HttpMethod.Post, $"{_provider.ExportPath.TrimEnd('/')}/access", request, cancellationToken);

    public Task RevokeAccessGrantAsync(string grantId, CancellationToken cancellationToken) =>
        SendNoContentAsync(
            HttpMethod.Post,
            _provider.RevokeAccessPath,
            new { grantId },
            cancellationToken);

    public Task DeletePayloadAsync(
        string tenantId,
        string payloadReference,
        CancellationToken cancellationToken) =>
        SendNoContentAsync(
            HttpMethod.Post,
            _provider.DeletePayloadPath,
            new { tenantId, payloadReference },
            cancellationToken);

    private async Task SendNoContentAsync(
        HttpMethod method,
        string path,
        object body,
        CancellationToken cancellationToken)
    {
        using var timeout = CreateTimeout(cancellationToken);
        using var response = await SendCoreAsync(method, path, body, timeout.Token);
        response.EnsureSuccessStatusCode();
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var timeout = CreateTimeout(cancellationToken);
        using var response = await SendCoreAsync(method, path, body, timeout.Token);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > _control.MaxProviderResponseBytes)
            throw new InvalidDataException("Capture provider response exceeded the configured limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var bounded = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token);
            if (read == 0) break;
            if (bounded.Length + read > _control.MaxProviderResponseBytes)
                throw new InvalidDataException("Capture provider response exceeded the configured limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
        }
        bounded.Position = 0;
        return await JsonSerializer.DeserializeAsync<T>(bounded, JsonOptions, timeout.Token)
               ?? throw new InvalidDataException($"Capture provider returned an invalid {typeof(T).Name} response.");
    }

    private async Task<HttpResponseMessage> SendCoreAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        var requestUri = Resolve(path);
        using var request = new HttpRequestMessage(method, requestUri);
        if (!string.IsNullOrWhiteSpace(_provider.ApiKey))
            request.Headers.TryAddWithoutValidation("X-NTShield-Provider-Key", _provider.ApiKey);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);

        return await _httpClientFactory.CreateClient(CaptureServiceCollectionExtensions.ProviderClientName)
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    }

    private Uri Resolve(string path)
    {
        var resolved = new Uri(BaseUri, path);
        if (!string.Equals(resolved.Scheme, BaseUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(resolved.Host, BaseUri.Host, StringComparison.OrdinalIgnoreCase) ||
            resolved.Port != BaseUri.Port)
        {
            throw new InvalidOperationException("Capture provider path escaped its configured origin.");
        }
        return resolved;
    }

    private static Uri ValidateBaseUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new InvalidOperationException("Capture provider BaseUrl must be an absolute HTTP(S) URL.");
        if (uri.Scheme == Uri.UriSchemeHttp &&
            !string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) &&
            !(System.Net.IPAddress.TryParse(uri.Host, out var address) && System.Net.IPAddress.IsLoopback(address)))
            throw new InvalidOperationException("Plain HTTP capture providers are allowed only on loopback; use HTTPS for remote providers.");
        return uri;
    }

    private CancellationTokenSource CreateTimeout(CancellationToken cancellationToken)
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_control.ProviderRequestTimeoutSeconds, 1, 120)));
        return timeout;
    }
}

public interface ICaptureProviderResolver
{
    IReadOnlyCollection<ICaptureProviderAdapter> All { get; }
    ICaptureProviderAdapter GetRequired(string providerId);
}

public sealed class CaptureProviderRegistry : ICaptureProviderResolver
{
    private readonly IReadOnlyDictionary<string, ICaptureProviderAdapter> _providers;

    public CaptureProviderRegistry(
        Microsoft.Extensions.Options.IOptions<CaptureControlOptions> options,
        IHttpClientFactory httpClientFactory)
    {
        if (!options.Value.Enabled)
        {
            _providers = new Dictionary<string, ICaptureProviderAdapter>(StringComparer.OrdinalIgnoreCase);
            return;
        }
        var enabled = (options.Value.Providers ?? []).Where(item => item.Enabled).ToList();
        var duplicate = enabled.GroupBy(item => item.Id, StringComparer.OrdinalIgnoreCase).FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null) throw new InvalidOperationException($"Duplicate capture provider id: {duplicate.Key}.");
        _providers = enabled.ToDictionary(
            item => item.Id,
            item => (ICaptureProviderAdapter)new HttpCaptureProviderAdapter(item, options.Value, httpClientFactory),
            StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyCollection<ICaptureProviderAdapter> All => _providers.Values.ToArray();

    public ICaptureProviderAdapter GetRequired(string providerId) =>
        _providers.TryGetValue(providerId, out var provider)
            ? provider
            : throw new CaptureValidationException($"Unknown or disabled capture provider '{providerId}'.");
}
