using Microsoft.Extensions.Options;
using NTShield.Server.Services;

namespace NTShield.Server.Capture;

public sealed class CaptureHealthService
{
    private readonly ICaptureControlStore _store;
    private readonly CaptureControlOptions _options;

    public CaptureHealthService(
        ICaptureControlStore store,
        IOptions<CaptureControlOptions> options)
    {
        _store = store;
        _options = options.Value;
    }

    public async Task<CaptureHealthSummary> GetSummaryAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var visibleProviderIds = _options.Providers.Where(item =>
                item.Enabled && (item.TenantIds.Count == 0 || item.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase)))
            .Select(item => item.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var providers = (await _store.ListProviderHealthAsync(cancellationToken))
            .Where(item => visibleProviderIds.Contains(item.ProviderId)).ToList();
        var configuredWithoutSnapshot = _options.Providers
            .Where(item => visibleProviderIds.Contains(item.Id) && providers.All(health =>
                !string.Equals(health.ProviderId, item.Id, StringComparison.OrdinalIgnoreCase)))
            .Select(item => new CaptureProviderHealth
            {
                ProviderId = item.Id,
                Kind = item.Kind,
                State = CaptureProviderState.Unknown,
                CheckedAtUtc = default,
                CapacityBytes = item.CapacityBytes,
                MaxSustainableIngressMbps = item.MaxSustainableIngressMbps,
                StatusCode = "not_yet_probed",
                FailOpen = true,
                Capabilities = item.Capabilities.ToList()
            });
        providers.AddRange(configuredWithoutSnapshot);
        var gaps = await _store.ListVisibilityGapsAsync(tenantId, openOnly: true, take: 500, cancellationToken);
        return new CaptureHealthSummary
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Providers = providers.OrderBy(item => item.ProviderId, StringComparer.OrdinalIgnoreCase).ToList(),
            OpenVisibilityGaps = gaps.Count,
            TrafficFailOpen = true
        };
    }

    public Task<IReadOnlyList<VisibilityGap>> ListGapsAsync(
        string tenantId,
        bool openOnly,
        int take,
        CancellationToken cancellationToken = default) =>
        _store.ListVisibilityGapsAsync(
            TopologyService.NormalizeTenantId(tenantId),
            openOnly,
            Math.Clamp(take, 1, 200),
            cancellationToken);
}
