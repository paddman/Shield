using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Capture;

internal static class CaptureProviderTenantAssignment
{
    public static void Ensure(CaptureControlOptions options, string providerId, string tenantId)
    {
        var configured = options.Providers.FirstOrDefault(item =>
            item.Enabled && string.Equals(item.Id, providerId, StringComparison.OrdinalIgnoreCase));
        if (configured is null || !configured.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(
                $"Capture provider '{providerId}' is not assigned to the session tenant.");
    }
}

public sealed class CaptureControlInitializer : BackgroundService
{
    private readonly ICaptureControlStore _store;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureControlInitializer> _logger;

    public CaptureControlInitializer(
        ICaptureControlStore store,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureControlInitializer> logger)
    {
        _store = store;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _store.InitializeAsync(stoppingToken);
                return;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Capture control store initialization failed; retrying without blocking web startup");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }
}

public sealed class CaptureProviderHealthWorker : BackgroundService
{
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureProviderHealthWorker> _logger;

    public CaptureProviderHealthWorker(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureProviderHealthWorker> logger)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Clamp(_options.HealthProbeIntervalSeconds, 5, 600)));
        do
        {
            foreach (var provider in _providers.All)
            {
                try
                {
                    var health = await provider.ProbeAsync(stoppingToken);
                    if (health.StoragePressure == CaptureStoragePressureState.Critical)
                    {
                        health.StorageCriticalMetadataOnly = true;
                        if (!health.ActiveVisibilityGapReasonCodes.Contains(
                                CaptureGapReasonCodes.StorageCriticalMetadataOnly,
                                StringComparer.Ordinal))
                            health.ActiveVisibilityGapReasonCodes.Add(CaptureGapReasonCodes.StorageCriticalMetadataOnly);
                    }
                    health.ActiveVisibilityGapReasonCodes = (health.ActiveVisibilityGapReasonCodes ?? [])
                        .Where(CaptureGapReasonCodes.ProviderReported.Contains)
                        .Distinct(StringComparer.Ordinal)
                        .Take(20)
                        .ToList();
                    await _store.UpsertProviderHealthAsync(health, stoppingToken);
                    if (health.State == CaptureProviderState.Healthy)
                    {
                        await CloseHealthGapsAsync(provider, health.CheckedAtUtc, stoppingToken);
                    }
                    else
                    {
                        await RecordProviderGapAsync(provider, health.StatusCode ?? health.State.ToString().ToLowerInvariant(), stoppingToken);
                    }
                    await SynchronizeReportedGapsAsync(provider, health, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Capture provider health probe failed provider={Provider}; traffic remains fail-open", provider.ProviderId);
                    await RecordProviderGapAsync(provider, "probe_exception", stoppingToken);
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RecordProviderGapAsync(
        ICaptureProviderAdapter provider,
        string detailCode,
        CancellationToken cancellationToken)
    {
        var configured = _options.Providers.First(item =>
            string.Equals(item.Id, provider.ProviderId, StringComparison.OrdinalIgnoreCase));
        var tenants = configured.TenantIds.Count > 0 ? configured.TenantIds : ["default"];
        foreach (var tenant in tenants)
        {
            var tenantId = Services.TopologyService.NormalizeTenantId(tenant);
            if (await _store.GetOpenVisibilityGapAsync(
                    tenantId, provider.ProviderId, CaptureGapReasonCodes.ProviderUnavailable, cancellationToken) is not null)
                continue;
            await _store.CreateVisibilityGapAsync(new VisibilityGap
            {
                GapId = Guid.NewGuid().ToString("N"),
                TenantId = tenantId,
                ProviderId = provider.ProviderId,
                Reason = CaptureGapReasonCodes.ProviderUnavailable,
                DetailCode = detailCode,
                StartedAtUtc = DateTimeOffset.UtcNow,
                FailOpen = true
            }, cancellationToken);
        }
    }

    private async Task CloseHealthGapsAsync(
        ICaptureProviderAdapter provider,
        DateTimeOffset endedAtUtc,
        CancellationToken cancellationToken)
    {
        var configured = _options.Providers.First(item =>
            string.Equals(item.Id, provider.ProviderId, StringComparison.OrdinalIgnoreCase));
        var tenants = configured.TenantIds.Count > 0 ? configured.TenantIds : ["default"];
        foreach (var tenant in tenants)
        {
            await _store.CloseVisibilityGapsAsync(
                Services.TopologyService.NormalizeTenantId(tenant),
                provider.ProviderId,
                CaptureGapReasonCodes.ProviderUnavailable,
                endedAtUtc,
                cancellationToken);
        }
    }

    private async Task SynchronizeReportedGapsAsync(
        ICaptureProviderAdapter provider,
        CaptureProviderHealth health,
        CancellationToken cancellationToken)
    {
        var configured = _options.Providers.First(item =>
            string.Equals(item.Id, provider.ProviderId, StringComparison.OrdinalIgnoreCase));
        var tenants = configured.TenantIds.Count > 0 ? configured.TenantIds : ["default"];
        var active = health.ActiveVisibilityGapReasonCodes.ToHashSet(StringComparer.Ordinal);
        foreach (var tenant in tenants)
        {
            var tenantId = Services.TopologyService.NormalizeTenantId(tenant);
            foreach (var reason in CaptureGapReasonCodes.ProviderReported)
            {
                if (active.Contains(reason))
                {
                    if (await _store.GetOpenVisibilityGapAsync(
                            tenantId, provider.ProviderId, reason, cancellationToken) is null)
                    {
                        await _store.CreateVisibilityGapAsync(new VisibilityGap
                        {
                            GapId = Guid.NewGuid().ToString("N"),
                            TenantId = tenantId,
                            ProviderId = provider.ProviderId,
                            Reason = reason,
                            DetailCode = reason,
                            StartedAtUtc = health.CheckedAtUtc,
                            FailOpen = true
                        }, cancellationToken);
                    }
                }
                else
                {
                    await _store.CloseVisibilityGapsAsync(
                        tenantId, provider.ProviderId, reason, health.CheckedAtUtc, cancellationToken);
                }
            }
        }
    }
}

public sealed class CaptureProviderSyncWorker : BackgroundService
{
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureSessionService _sessions;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureProviderSyncWorker> _logger;

    public CaptureProviderSyncWorker(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        CaptureSessionService sessions,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureProviderSyncWorker> logger)
    {
        _store = store;
        _providers = providers;
        _sessions = sessions;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Clamp(_options.ProviderSyncIntervalSeconds, 5, 600)));
        do
        {
            foreach (var provider in _providers.All.Where(item => item.Capabilities.Contains("metadata")))
            {
                try
                {
                    var cursor = await _store.GetProviderCursorAsync(provider.ProviderId, stoppingToken);
                    var page = await provider.FetchSessionMetadataAsync(cursor, _options.MaxSessionsPerQuery, stoppingToken);
                    page.Items ??= [];
                    if (page.Items.Count > _options.MaxSessionsPerQuery)
                        throw new InvalidDataException("Capture provider returned too many session records.");
                    if (!string.IsNullOrWhiteSpace(page.NextCursor) && page.NextCursor.Length > 2048)
                        throw new InvalidDataException("Capture provider cursor exceeded the configured bound.");
                    if (page.Items.Count > 0 &&
                        (string.IsNullOrWhiteSpace(page.NextCursor) ||
                         string.Equals(page.NextCursor, cursor, StringComparison.Ordinal)))
                        throw new InvalidDataException("Capture provider must advance its cursor when returning session records.");
                    var quarantined = new List<CaptureProviderQuarantineEntry>();
                    foreach (var item in page.Items)
                    {
                        try
                        {
                            if (item is null)
                                throw new CaptureValidationException("Capture provider returned a null session item.");
                            await _sessions.IngestProviderSessionAsync(provider.ProviderId, item, stoppingToken);
                        }
                        catch (Exception ex) when (ex is CaptureValidationException or Services.TopologyValidationException or
                                                   ArgumentException or FormatException or OverflowException or NullReferenceException)
                        {
                            var rejected = Quarantine(provider.ProviderId, item, ex);
                            quarantined.Add(rejected);
                            _logger.LogWarning(
                                "Rejected malformed capture metadata provider={Provider} quarantine={Quarantine} reason={Reason}",
                                provider.ProviderId, rejected.QuarantineId, rejected.ReasonCode);
                        }
                    }
                    if (page.Items.Count > 0 || !string.Equals(page.NextCursor, cursor, StringComparison.Ordinal))
                        await _store.CommitProviderSyncPageAsync(
                            provider.ProviderId, page.NextCursor ?? cursor, quarantined, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Capture metadata synchronization failed provider={Provider}; traffic remains fail-open", provider.ProviderId);
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private CaptureProviderQuarantineEntry Quarantine(
        string providerId,
        CaptureProviderSession? item,
        Exception exception)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(item);
        var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var quarantineId = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{providerId}:{sha}"))).ToLowerInvariant();
        var configured = _options.Providers.First(candidate =>
            string.Equals(candidate.Id, providerId, StringComparison.OrdinalIgnoreCase));
        var fallbackTenant = Services.TopologyService.NormalizeTenantId(configured.TenantIds[0]);
        var tenantId = fallbackTenant;
        try
        {
            var candidate = Services.TopologyService.NormalizeTenantId(item?.TenantId!);
            if (configured.TenantIds.Contains(candidate, StringComparer.OrdinalIgnoreCase)) tenantId = candidate;
        }
        catch (Exception ex) when (ex is Services.TopologyValidationException or NullReferenceException)
        {
            // Audit the rejection under an assigned tenant without retaining unsafe input.
        }
        var sessionHint = !string.IsNullOrWhiteSpace(item?.SessionId) &&
                          Regex.IsMatch(item.SessionId, "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
            ? item.SessionId
            : null;
        return new CaptureProviderQuarantineEntry
        {
            QuarantineId = quarantineId,
            ProviderId = providerId,
            TenantId = tenantId,
            SessionIdHint = sessionHint,
            ItemSha256 = sha,
            ReasonCode = exception.Message.Contains("not assigned", StringComparison.OrdinalIgnoreCase)
                ? "provider_tenant_assignment_rejected"
                : "invalid_provider_session",
            ReceivedAtUtc = DateTimeOffset.UtcNow
        };
    }
}

public sealed class CapturePolicyReconcileWorker : BackgroundService
{
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CapturePolicyReconcileWorker> _logger;

    public CapturePolicyReconcileWorker(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options,
        ILogger<CapturePolicyReconcileWorker> logger)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        var owner = $"capture-policy-dispatch:{Environment.ProcessId}:{Guid.NewGuid():N}";
        var dispatchLeaseSeconds = Math.Clamp(
            Math.Max(
                _options.PolicyDispatchLeaseSeconds,
                _options.ProviderMutationLockWaitSeconds + _options.ProviderRequestTimeoutSeconds + 10),
            30,
            900);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Clamp(
            _options.PolicyReconcileIntervalSeconds, 15, 3600)));
        do
        {
            for (var index = 0; index < 100; index++)
            {
                var now = DateTimeOffset.UtcNow;
                var dispatch = await _store.TryClaimNextPolicyDispatchAsync(
                    owner,
                    now,
                    now.AddSeconds(dispatchLeaseSeconds),
                    stoppingToken);
                if (dispatch is null) break;
                await DispatchDesiredPolicyAsync(dispatch, owner, stoppingToken);
            }
            foreach (var configured in _options.Providers.Where(item => item.Enabled))
            {
                var provider = _providers.GetRequired(configured.Id);
                foreach (var rawTenantId in configured.TenantIds)
                {
                    var tenantId = Services.TopologyService.NormalizeTenantId(rawTenantId);
                    var policies = await _store.ListPoliciesAsync(tenantId, stoppingToken);
                    foreach (var policy in policies.Where(item =>
                                 string.Equals(item.ProviderId, provider.ProviderId, StringComparison.OrdinalIgnoreCase)))
                    {
                        try
                        {
                            var providerLease = await TryAcquireProviderLeaseAsync(
                                provider.ProviderId, stoppingToken);
                            if (providerLease is null) continue;
                            await using var providerLeaseScope = providerLease;
                            var current = await _store.GetPolicyAsync(
                                tenantId, policy.PolicyId, stoppingToken);
                            if (current is null || current.Version != policy.Version ||
                                !string.Equals(current.ProviderId, provider.ProviderId, StringComparison.OrdinalIgnoreCase))
                                continue;
                            await provider.ApplyPolicyAsync(current, stoppingToken);
                            await _store.CloseVisibilityGapsAsync(
                                tenantId,
                                provider.ProviderId,
                                CaptureGapReasonCodes.PolicyApplyFailed,
                                DateTimeOffset.UtcNow,
                                stoppingToken);
                        }
                        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                        {
                            return;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex,
                                "Capture policy reconciliation failed tenant={Tenant} provider={Provider} policy={Policy}; traffic remains fail-open",
                                tenantId, provider.ProviderId, policy.PolicyId);
                            if (await _store.GetOpenVisibilityGapAsync(
                                    tenantId, provider.ProviderId, CaptureGapReasonCodes.PolicyApplyFailed, stoppingToken) is null)
                            {
                                await _store.CreateVisibilityGapAsync(new VisibilityGap
                                {
                                    GapId = Guid.NewGuid().ToString("N"),
                                    TenantId = tenantId,
                                    ProviderId = provider.ProviderId,
                                    Reason = CaptureGapReasonCodes.PolicyApplyFailed,
                                    DetailCode = "reconcile_failed",
                                    StartedAtUtc = DateTimeOffset.UtcNow,
                                    FailOpen = true
                                }, stoppingToken);
                            }
                        }
                    }
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task DispatchDesiredPolicyAsync(
        CapturePolicyDispatch dispatch,
        string owner,
        CancellationToken cancellationToken)
    {
        var reason = dispatch.Kind == CapturePolicyDispatchKind.Delete
            ? CaptureGapReasonCodes.PolicyDeleteFailed
            : CaptureGapReasonCodes.PolicyApplyFailed;
        try
        {
            var providerLease = await TryAcquireProviderLeaseAsync(
                dispatch.ProviderId, cancellationToken);
            if (providerLease is null)
            {
                await _store.ReleasePolicyDispatchAsync(
                    dispatch,
                    owner,
                    DateTimeOffset.UtcNow.AddSeconds(1),
                    "mutation_busy",
                    cancellationToken);
                return;
            }
            await using var providerLeaseScope = providerLease;
            var current = await _store.GetPolicyAsync(
                dispatch.TenantId, dispatch.PolicyId, cancellationToken);
            var superseded = dispatch.Kind switch
            {
                CapturePolicyDispatchKind.Apply => current is null ||
                    current.Version != dispatch.DesiredVersion ||
                    !string.Equals(current.ProviderId, dispatch.ProviderId, StringComparison.OrdinalIgnoreCase),
                CapturePolicyDispatchKind.Delete => current is not null,
                _ => true
            };
            if (!superseded)
            {
                CaptureProviderTenantAssignment.Ensure(
                    _options, dispatch.ProviderId, dispatch.TenantId);
                var provider = _providers.GetRequired(dispatch.ProviderId);
                if (dispatch.Kind == CapturePolicyDispatchKind.Apply)
                    await provider.ApplyPolicyAsync(current!, cancellationToken);
                else
                    await provider.DeletePolicyAsync(dispatch.TenantId, dispatch.PolicyId, cancellationToken);
                await _store.CloseVisibilityGapsAsync(
                    dispatch.TenantId, dispatch.ProviderId, reason, DateTimeOffset.UtcNow, cancellationToken);
            }
            if (!await _store.CompletePolicyDispatchAsync(dispatch.DispatchId, owner, cancellationToken))
                throw new InvalidOperationException("Capture policy dispatch lease was lost before completion.");
            await TryAuditDispatchAsync(dispatch, superseded ? "superseded" : "success", null, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await _store.ReleasePolicyDispatchAsync(
                dispatch, owner, DateTimeOffset.UtcNow, "worker_stopping", CancellationToken.None);
            throw;
        }
        catch (Exception ex)
        {
            var delaySeconds = Math.Min(300, 1 << Math.Min(dispatch.AttemptCount, 8));
            await _store.ReleasePolicyDispatchAsync(
                dispatch,
                owner,
                DateTimeOffset.UtcNow.AddSeconds(delaySeconds),
                ex is InvalidDataException ? "invalid_provider_data" : "provider_unavailable",
                cancellationToken);
            _logger.LogWarning(ex,
                "Capture desired policy dispatch failed tenant={Tenant} provider={Provider} policy={Policy}; traffic remains fail-open",
                dispatch.TenantId, dispatch.ProviderId, dispatch.PolicyId);
            if (await _store.GetOpenVisibilityGapAsync(
                    dispatch.TenantId, dispatch.ProviderId, reason, cancellationToken) is null)
            {
                await _store.CreateVisibilityGapAsync(new VisibilityGap
                {
                    GapId = Guid.NewGuid().ToString("N"),
                    TenantId = dispatch.TenantId,
                    ProviderId = dispatch.ProviderId,
                    Reason = reason,
                    DetailCode = "desired_state_dispatch_failed",
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    FailOpen = true
                }, cancellationToken);
            }
            await TryAuditDispatchAsync(dispatch, "degraded", "provider_unavailable", cancellationToken);
        }
    }

    private async Task<IAsyncDisposable?> TryAcquireProviderLeaseAsync(
        string providerId,
        CancellationToken cancellationToken)
    {
        var resource = $"provider:{providerId.ToLowerInvariant()}";
        var owner = $"capture-provider-side-effect:{Environment.ProcessId}:{Guid.NewGuid():N}";
        var deadline = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(
            _options.ProviderMutationLockWaitSeconds, 1, 60));
        var leaseSeconds = Math.Clamp(
            Math.Max(_options.ProviderMutationLeaseSeconds, _options.ProviderRequestTimeoutSeconds + 10),
            15,
            300);
        while (true)
        {
            var now = DateTimeOffset.UtcNow;
            if (await _store.TryAcquireProviderMutationLeaseAsync(
                    resource, owner, now, now.AddSeconds(leaseSeconds), cancellationToken))
                return new ProviderMutationLease(_store, resource, owner);
            if (now >= deadline) return null;
            await Task.Delay(50, cancellationToken);
        }
    }

    private sealed class ProviderMutationLease(
        ICaptureControlStore store,
        string resource,
        string owner) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() =>
            await store.ReleaseProviderMutationLeaseAsync(resource, owner, CancellationToken.None);
    }

    private async Task TryAuditDispatchAsync(
        CapturePolicyDispatch dispatch,
        string result,
        string? detail,
        CancellationToken cancellationToken)
    {
        try
        {
            await _store.AppendAuditAsync(new CaptureAuditEntry
            {
                TenantId = dispatch.TenantId,
                TimestampUtc = DateTimeOffset.UtcNow,
                Actor = "system:capture-policy-dispatch",
                Action = dispatch.Kind == CapturePolicyDispatchKind.Apply
                    ? "capture.policy.apply"
                    : "capture.policy.delete.apply",
                Target = dispatch.PolicyId,
                Result = result,
                DetailCode = detail
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Capture policy dispatch audit failed dispatch={Dispatch}", dispatch.DispatchId);
        }
    }
}

public sealed class CaptureExportWorker : BackgroundService
{
    private static readonly System.Text.RegularExpressions.Regex Sha256Pattern =
        new("^[a-fA-F0-9]{64}$", System.Text.RegularExpressions.RegexOptions.Compiled);
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureExportWorker> _logger;

    public CaptureExportWorker(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureExportWorker> logger)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        var owner = $"capture-export:{Environment.ProcessId}:{Guid.NewGuid():N}";
        var leaseSeconds = Math.Clamp(
            Math.Max(_options.ExportClaimLeaseSeconds, _options.ProviderRequestTimeoutSeconds * 3),
            60,
            900);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        do
        {
            var now = DateTimeOffset.UtcNow;
            var job = await _store.TryClaimNextExportJobAsync(
                owner, now, now.AddSeconds(leaseSeconds), stoppingToken);
            if (job is null) continue;
            try
            {
                if (job.ExpiresAtUtc <= DateTimeOffset.UtcNow)
                {
                    job.Status = CaptureJobStatus.Expired;
                    job.ErrorCode = "job_expired";
                }
                else
                {
                    if (job.SessionIds.Count is < 1 || job.SessionIds.Count > _options.MaxExportSessions ||
                        job.SessionIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != job.SessionIds.Count ||
                        (job.Format != "pcap" && job.Format != "pcapng"))
                        throw new InvalidDataException("Export job metadata is invalid.");
                    var references = new List<string>();
                    foreach (var sessionId in job.SessionIds.Take(_options.MaxExportSessions))
                    {
                        var session = await _store.GetSessionAsync(job.TenantId, sessionId, stoppingToken)
                                      ?? throw new InvalidDataException("Export session metadata is missing.");
                        try
                        {
                            CaptureSessionService.EnsurePayloadWithinRetention(session);
                        }
                        catch (CaptureValidationException ex)
                        {
                            throw new InvalidDataException("Export payload retention has expired.", ex);
                        }
                        if (!session.PayloadAvailable || string.IsNullOrWhiteSpace(session.PayloadReference))
                            throw new InvalidDataException("Export payload is no longer available.");
                        if (!string.Equals(session.ProviderId, job.ProviderId, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("Export provider mismatch.");
                        CaptureProviderTenantAssignment.Ensure(
                            _options, session.ProviderId, session.TenantId);
                        references.Add(session.PayloadReference);
                    }
                    var provider = _providers.GetRequired(job.ProviderId);
                    var result = await provider.StartExportAsync(new ProviderExportRequest
                    {
                        TenantId = job.TenantId,
                        JobId = job.JobId,
                        PayloadReferences = references,
                        Format = job.Format,
                        ExpiresAtUtc = job.ExpiresAtUtc
                    }, stoppingToken);
                    if (string.IsNullOrWhiteSpace(result.OutputReference) || result.OutputReference.Length > 1024)
                        throw new InvalidDataException("Capture provider returned an invalid export reference.");
                    if (string.IsNullOrWhiteSpace(result.OutputSha256) || !Sha256Pattern.IsMatch(result.OutputSha256))
                        throw new InvalidDataException("Capture provider export is missing a SHA-256 manifest checksum.");
                    if (result.StorageTier == CaptureStorageTier.MetadataOnly)
                        throw new InvalidDataException("Capture provider export is missing its storage tier.");
                    if (string.IsNullOrWhiteSpace(result.EncryptionKeyVersion) ||
                        string.IsNullOrWhiteSpace(result.StoragePoolId))
                        throw new InvalidDataException("Capture provider export is missing its logical KMS key version or storage pool id.");
                    job.OutputReference = result.OutputReference;
                    job.OutputSha256 = result.OutputSha256.ToLowerInvariant();
                    job.EncryptionKeyVersion = string.IsNullOrWhiteSpace(result.EncryptionKeyVersion)
                        ? null
                        : CaptureSessionService.ValidateId(result.EncryptionKeyVersion, "encryption key version");
                    job.StorageTier = result.StorageTier;
                    job.StoragePoolId = string.IsNullOrWhiteSpace(result.StoragePoolId)
                        ? null
                        : CaptureSessionService.ValidateId(result.StoragePoolId, "storage pool id");
                    job.Status = CaptureJobStatus.Completed;
                    job.ErrorCode = null;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                job.Status = CaptureJobStatus.Queued;
                job.UpdatedAtUtc = DateTimeOffset.UtcNow;
                await _store.TryUpdateClaimedExportJobAsync(job, owner, CancellationToken.None);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Capture export dispatch failed job={Job} provider={Provider}", job.JobId, job.ProviderId);
                job.Status = job.AttemptCount < 3 ? CaptureJobStatus.Queued : CaptureJobStatus.Failed;
                job.ErrorCode = ex is InvalidDataException ? "invalid_provider_data" : "provider_unavailable";
            }
            job.UpdatedAtUtc = DateTimeOffset.UtcNow;
            if (!await _store.TryUpdateClaimedExportJobAsync(job, owner, stoppingToken))
            {
                _logger.LogWarning("Capture export lease was lost before status commit job={Job}", job.JobId);
                continue;
            }
            try
            {
                await _store.AppendAuditAsync(new CaptureAuditEntry
                {
                    TenantId = job.TenantId,
                    TimestampUtc = job.UpdatedAtUtc,
                    Actor = "system:capture-export-worker",
                    Action = "capture.export.dispatch",
                    Target = job.JobId,
                    Result = job.Status == CaptureJobStatus.Completed ? "success" : job.Status.ToString().ToLowerInvariant(),
                    DetailCode = job.ErrorCode
                }, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Capture export status audit failed job={Job}", job.JobId);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

public sealed class CaptureRetentionWorker : BackgroundService
{
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureRetentionWorker> _logger;

    public CaptureRetentionWorker(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureRetentionWorker> logger)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_options.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(Math.Clamp(_options.RetentionSweepIntervalMinutes, 1, 1440)));
        do
        {
            var expired = await _store.ListExpiredSessionsAsync(200, stoppingToken);
            foreach (var session in expired)
            {
                try
                {
                    await _store.AppendAuditAsync(new CaptureAuditEntry
                    {
                        TenantId = session.TenantId,
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Actor = "system:capture-retention-worker",
                        Action = "capture.session.expire",
                        Target = session.SessionId,
                        Result = "attempt",
                        DetailCode = "provider_delete_pending"
                    }, stoppingToken);
                    if (session.PayloadAvailable && !string.IsNullOrWhiteSpace(session.PayloadReference))
                    {
                        CaptureProviderTenantAssignment.Ensure(
                            _options, session.ProviderId, session.TenantId);
                        var provider = _providers.GetRequired(session.ProviderId);
                        if (!provider.Capabilities.Contains("retention"))
                            throw new InvalidOperationException("Provider does not support retention deletion.");
                        await provider.DeletePayloadAsync(session.TenantId, session.PayloadReference, stoppingToken);
                    }
                    if (session.Tls?.DecryptedArtifactAvailable == true &&
                        !string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactReference) &&
                        (!string.Equals(
                             session.Tls.DecryptedArtifactReference,
                             session.PayloadReference,
                             StringComparison.Ordinal) ||
                         !string.Equals(
                             session.Tls.DecryptedArtifactProviderId,
                             session.ProviderId,
                             StringComparison.OrdinalIgnoreCase)))
                    {
                        CaptureProviderTenantAssignment.Ensure(
                            _options, session.Tls.DecryptedArtifactProviderId!, session.TenantId);
                        var tlsProvider = _providers.GetRequired(session.Tls.DecryptedArtifactProviderId!);
                        if (!tlsProvider.Capabilities.Contains("retention"))
                            throw new InvalidOperationException("TLS provider does not support retention deletion.");
                        await tlsProvider.DeletePayloadAsync(
                            session.TenantId, session.Tls.DecryptedArtifactReference, stoppingToken);
                    }
                    await _store.DeleteSessionAsync(session.TenantId, session.SessionId, stoppingToken);
                    await _store.AppendAuditAsync(new CaptureAuditEntry
                    {
                        TenantId = session.TenantId,
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Actor = "system:capture-retention-worker",
                        Action = "capture.session.expire",
                        Target = session.SessionId,
                        Result = "success",
                        DetailCode = session.PayloadAvailable || session.Tls?.DecryptedArtifactAvailable == true
                            ? "provider_payload_deleted"
                            : "metadata_deleted"
                    }, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    // Keep the opaque reference so deletion can be retried; never silently orphan payload.
                    _logger.LogWarning(ex, "Capture retention deletion failed session={Session} provider={Provider}", session.SessionId, session.ProviderId);
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
