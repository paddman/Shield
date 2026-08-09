using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NTShield.Server.Services;

namespace NTShield.Server.Capture;

public sealed class CaptureValidationException : Exception
{
    public CaptureValidationException(string message) : base(message) { }
}

public sealed class CaptureVersionConflictException : Exception
{
    public CaptureVersionConflictException(int? currentVersion)
        : base("The capture policy changed after it was read.") => CurrentVersion = currentVersion;

    public int? CurrentVersion { get; }
}

public sealed class CaptureCapacityRejectedException : Exception
{
    public CaptureCapacityRejectedException(CaptureAdmissionResult result)
        : base("The enabled capture policy exceeds provider admission limits.") => Result = result;

    public CaptureAdmissionResult Result { get; }
}

public readonly record struct CaptureActorContext(string Actor, string? SourceIp);

public sealed class CaptureCapacityService
{
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;

    public CaptureCapacityService(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
    }

    public async Task<CaptureAdmissionResult> EvaluateAsync(
        string tenantId,
        CapturePolicy candidate,
        CancellationToken cancellationToken = default)
    {
        var provider = _providers.GetRequired(candidate.ProviderId);
        var providerConfig = _options.Providers.First(item =>
            string.Equals(item.Id, provider.ProviderId, StringComparison.OrdinalIgnoreCase));
        if (!providerConfig.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase))
            throw new CaptureValidationException(
                $"Provider '{provider.ProviderId}' is not assigned to tenant '{tenantId}'.");
        var health = (await _store.ListProviderHealthAsync(cancellationToken)).FirstOrDefault(item =>
            string.Equals(item.ProviderId, provider.ProviderId, StringComparison.OrdinalIgnoreCase));
        var stale = health is null ||
                    DateTimeOffset.UtcNow - health.CheckedAtUtc > TimeSpan.FromSeconds(_options.ProviderHealthStaleSeconds);

        var tenantPolicies = (await _store.ListPoliciesAsync(tenantId, cancellationToken))
            .Where(item => item.Enabled &&
                           string.Equals(item.ProviderId, candidate.ProviderId, StringComparison.OrdinalIgnoreCase) &&
                           !string.Equals(item.PolicyId, candidate.PolicyId, StringComparison.OrdinalIgnoreCase))
            .Append(candidate)
            .Where(item => item.Enabled)
            .ToList();
        var providerPolicies = new List<CapturePolicy>();
        foreach (var assignedTenant in providerConfig.TenantIds
                     .Select(TopologyService.NormalizeTenantId)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            providerPolicies.AddRange((await _store.ListPoliciesAsync(assignedTenant, cancellationToken))
                .Where(item => item.Enabled &&
                               string.Equals(item.ProviderId, candidate.ProviderId, StringComparison.OrdinalIgnoreCase) &&
                               !(string.Equals(assignedTenant, tenantId, StringComparison.OrdinalIgnoreCase) &&
                                 string.Equals(item.PolicyId, candidate.PolicyId, StringComparison.OrdinalIgnoreCase))));
        }
        if (candidate.Enabled) providerPolicies.Add(candidate);

        var ingress = providerPolicies.Sum(item => item.EstimatedIngressMbps);
        var tenantRetained = tenantPolicies.Aggregate(0m, (total, item) => total + EstimateRetainedBytes(item));
        var providerRetained = providerPolicies.Aggregate(0m, (total, item) => total + EstimateRetainedBytes(item));
        var providerCapacity = PositiveMinimum(health?.CapacityBytes ?? 0, providerConfig.CapacityBytes);
        var admittedProviderCapacity = providerCapacity > 0
            ? decimal.Floor(providerCapacity * Math.Clamp(_options.CapacityAdmissionPercent, 1m, 100m) / 100m)
            : 0m;
        var admittedTenantCapacity = _options.DefaultTenantCapacityBytes > 0
            ? decimal.Floor(_options.DefaultTenantCapacityBytes *
                            Math.Clamp(_options.CapacityAdmissionPercent, 1m, 100m) / 100m)
            : 0m;
        var maxIngress = PositiveMinimumDecimal(
            health?.MaxSustainableIngressMbps ?? 0m,
            providerConfig.MaxSustainableIngressMbps);
        var used = Math.Max(0, health?.UsedBytes ?? 0);
        var packetCaptureRequested = providerPolicies.Any(item =>
            item.Enabled && item.Mode != CaptureMode.MetadataOnly);

        var result = new CaptureAdmissionResult
        {
            Admitted = true,
            ProviderId = provider.ProviderId,
            ProjectedIngressMbps = ingress,
            ProjectedRetainedBytes = ClampToLong(providerRetained),
            TenantProjectedRetainedBytes = ClampToLong(tenantRetained),
            ProviderProjectedRetainedBytes = ClampToLong(providerRetained),
            CapacityBytes = providerCapacity,
            AvailableBytes = ClampToLong(Math.Max(0m, admittedProviderCapacity - used)),
            ProviderState = health?.State ?? CaptureProviderState.Unknown,
            ProviderHealthStale = stale
        };

        if (packetCaptureRequested && providerCapacity <= 0)
            result.Reasons.Add("provider_retention_capacity_unknown");
        if (packetCaptureRequested && admittedTenantCapacity <= 0m)
            result.Reasons.Add("tenant_retention_capacity_unknown");
        if (packetCaptureRequested && maxIngress <= 0m)
            result.Reasons.Add("provider_ingress_capacity_unknown");
        else if (maxIngress > 0m && ingress > maxIngress)
            result.Reasons.Add("provider_ingress_capacity_exceeded");
        if (admittedTenantCapacity > 0m && tenantRetained > admittedTenantCapacity)
            result.Reasons.Add("tenant_retention_capacity_exceeded");
        if (admittedProviderCapacity > 0m && providerRetained + used > admittedProviderCapacity)
            result.Reasons.Add("provider_retention_capacity_exceeded");
        if (_options.RequireFreshProviderHealthForActivation && stale)
            result.Reasons.Add("fresh_provider_health_required");
        else if (stale)
            result.Warnings.Add("provider_health_stale_static_capacity_used");
        if (health?.State is CaptureProviderState.Degraded or CaptureProviderState.Unavailable)
            result.Warnings.Add("provider_degraded_policy_will_fail_open");
        if (health?.StorageCriticalMetadataOnly == true && candidate.Mode != CaptureMode.MetadataOnly)
            result.Reasons.Add(CaptureGapReasonCodes.StorageCriticalMetadataOnly);
        if (!provider.FailOpen)
            result.Reasons.Add("provider_must_be_fail_open");
        result.Admitted = result.Reasons.Count == 0;
        return result;
    }

    private static decimal EstimateRetainedBytes(CapturePolicy policy)
    {
        if (policy.Mode == CaptureMode.MetadataOnly || policy.EstimatedIngressMbps <= 0m) return 0m;
        var sampledMbps = policy.EstimatedIngressMbps * policy.SamplingPercent / 100m;
        return sampledMbps * 125_000m * 86_400m * policy.StorageLifecycle.ExpireAfterDays;
    }

    private static long PositiveMinimum(params long[] values)
    {
        var positive = values.Where(item => item > 0).ToArray();
        return positive.Length == 0 ? 0 : positive.Min();
    }

    private static decimal PositiveMinimumDecimal(params decimal[] values)
    {
        var positive = values.Where(item => item > 0m).ToArray();
        return positive.Length == 0 ? 0m : positive.Min();
    }

    private static long ClampToLong(decimal value) =>
        value >= long.MaxValue ? long.MaxValue : value <= 0 ? 0 : decimal.ToInt64(decimal.Floor(value));
}

public sealed class CapturePolicyService
{
    private static readonly Regex IdPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.Compiled);
    private static readonly Regex DomainPattern = new("^(?:\\*\\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", RegexOptions.Compiled);
    private static readonly Regex BpfPattern = new("^[A-Za-z0-9_.:/()\\[\\]\\s<>=!&|+*-]+$", RegexOptions.Compiled);
    private static readonly HashSet<string> Protocols = new(StringComparer.OrdinalIgnoreCase)
        { "tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "any" };
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureCapacityService _capacity;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CapturePolicyService> _logger;
    private readonly SemaphoreSlim _mutationLock = new(1, 1);

    public CapturePolicyService(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        CaptureCapacityService capacity,
        IOptions<CaptureControlOptions> options,
        ILogger<CapturePolicyService> logger)
    {
        _store = store;
        _providers = providers;
        _capacity = capacity;
        _options = options.Value;
        _logger = logger;
    }

    public Task<IReadOnlyList<CapturePolicy>> ListAsync(string tenantId, CancellationToken cancellationToken = default) =>
        _store.ListPoliciesAsync(NormalizeTenant(tenantId), cancellationToken);

    public Task<CapturePolicy?> GetAsync(string tenantId, string policyId, CancellationToken cancellationToken = default) =>
        _store.GetPolicyAsync(NormalizeTenant(tenantId), ValidateId(policyId, "policy id"), cancellationToken);

    public async Task<CaptureAdmissionResult> SimulateAsync(
        string tenantId,
        CapturePolicy candidate,
        CancellationToken cancellationToken = default)
    {
        tenantId = NormalizeTenant(tenantId);
        var copy = Clone(candidate);
        copy.TenantId = tenantId;
        if (string.IsNullOrWhiteSpace(copy.PolicyId)) copy.PolicyId = $"simulation-{Guid.NewGuid():N}";
        Validate(copy);
        return await _capacity.EvaluateAsync(tenantId, copy, cancellationToken);
    }

    public async Task<CapturePolicy> CreateAsync(
        string tenantId,
        CapturePolicy input,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = NormalizeTenant(tenantId);
        await _mutationLock.WaitAsync(cancellationToken);
        try
        {
            if ((await _store.ListPoliciesAsync(tenantId, cancellationToken)).Count >= _options.MaxPoliciesPerTenant)
                throw new CaptureValidationException($"A tenant can have at most {_options.MaxPoliciesPerTenant} capture policies.");
            var policy = Clone(input);
            policy.TenantId = tenantId;
            policy.PolicyId = string.IsNullOrWhiteSpace(policy.PolicyId)
                ? Guid.NewGuid().ToString("N")
                : ValidateId(policy.PolicyId, "policy id");
            policy.Version = 1;
            policy.CreatedAtUtc = policy.UpdatedAtUtc = DateTimeOffset.UtcNow;
            Validate(policy);
            await using var providerLease = await AcquireMutationLeasesAsync(
                tenantId, [policy.ProviderId], cancellationToken);
            if ((await _store.ListPoliciesAsync(tenantId, cancellationToken)).Count >= _options.MaxPoliciesPerTenant)
                throw new CaptureValidationException($"A tenant can have at most {_options.MaxPoliciesPerTenant} capture policies.");
            if (policy.Enabled)
            {
                var admission = await _capacity.EvaluateAsync(tenantId, policy, cancellationToken);
                if (!admission.Admitted) throw new CaptureCapacityRejectedException(admission);
            }
            var audit = PolicyAudit(tenantId, actor, "capture.policy.create", policy.PolicyId);
            var dispatch = PolicyDispatch(policy, CapturePolicyDispatchKind.Apply);
            if (!await _store.CreatePolicyMutationAsync(policy, audit, dispatch, cancellationToken))
                throw new CaptureVersionConflictException((await _store.GetPolicyAsync(tenantId, policy.PolicyId, cancellationToken))?.Version);
            return policy;
        }
        finally
        {
            _mutationLock.Release();
        }
    }

    public async Task<CapturePolicy> UpdateAsync(
        string tenantId,
        string policyId,
        CapturePolicy input,
        int expectedVersion,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = NormalizeTenant(tenantId);
        policyId = ValidateId(policyId, "policy id");
        if (expectedVersion < 1) throw new CaptureValidationException("An expected policy version is required.");
        await _mutationLock.WaitAsync(cancellationToken);
        try
        {
            var initial = await _store.GetPolicyAsync(tenantId, policyId, cancellationToken)
                           ?? throw new KeyNotFoundException("Capture policy was not found.");
            var policy = Clone(input);
            policy.TenantId = tenantId;
            policy.PolicyId = policyId;
            policy.Version = expectedVersion + 1;
            policy.CreatedAtUtc = initial.CreatedAtUtc;
            policy.UpdatedAtUtc = DateTimeOffset.UtcNow;
            Validate(policy);
            if (!string.Equals(initial.ProviderId, policy.ProviderId, StringComparison.OrdinalIgnoreCase))
                throw new CaptureValidationException(
                    "A capture policy provider cannot be changed in place; delete and recreate the policy.");
            await using var providerLease = await AcquireMutationLeasesAsync(
                tenantId, [initial.ProviderId, policy.ProviderId], cancellationToken);
            var existing = await _store.GetPolicyAsync(tenantId, policyId, cancellationToken)
                           ?? throw new KeyNotFoundException("Capture policy was not found.");
            if (existing.Version != expectedVersion) throw new CaptureVersionConflictException(existing.Version);
            policy.CreatedAtUtc = existing.CreatedAtUtc;
            if (policy.Enabled)
            {
                var admission = await _capacity.EvaluateAsync(tenantId, policy, cancellationToken);
                if (!admission.Admitted) throw new CaptureCapacityRejectedException(admission);
            }
            var audit = PolicyAudit(tenantId, actor, "capture.policy.update", policyId);
            var dispatch = PolicyDispatch(policy, CapturePolicyDispatchKind.Apply);
            if (!await _store.TryUpdatePolicyMutationAsync(
                    policy, expectedVersion, audit, dispatch, cancellationToken))
                throw new CaptureVersionConflictException((await _store.GetPolicyAsync(tenantId, policyId, cancellationToken))?.Version);
            return policy;
        }
        finally
        {
            _mutationLock.Release();
        }
    }

    public async Task<bool> DeleteAsync(
        string tenantId,
        string policyId,
        int expectedVersion,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = NormalizeTenant(tenantId);
        policyId = ValidateId(policyId, "policy id");
        if (expectedVersion < 1) throw new CaptureValidationException("An expected policy version is required.");
        await _mutationLock.WaitAsync(cancellationToken);
        try
        {
            var existing = await _store.GetPolicyAsync(tenantId, policyId, cancellationToken);
            if (existing is null) return false;
            await using var providerLease = await AcquireMutationLeasesAsync(
                tenantId, [existing.ProviderId], cancellationToken);
            existing = await _store.GetPolicyAsync(tenantId, policyId, cancellationToken);
            if (existing is null) return false;
            if (existing.Version != expectedVersion) throw new CaptureVersionConflictException(existing.Version);
            var audit = PolicyAudit(tenantId, actor, "capture.policy.delete", policyId);
            var dispatch = PolicyDispatch(existing, CapturePolicyDispatchKind.Delete);
            if (!await _store.TryDeletePolicyMutationAsync(
                    tenantId, policyId, expectedVersion, audit, dispatch, cancellationToken))
                throw new CaptureVersionConflictException((await _store.GetPolicyAsync(tenantId, policyId, cancellationToken))?.Version);
            return true;
        }
        finally
        {
            _mutationLock.Release();
        }
    }

    private static CaptureAuditEntry PolicyAudit(
        string tenantId,
        CaptureActorContext actor,
        string action,
        string target) =>
        new()
        {
            TenantId = tenantId,
            TimestampUtc = DateTimeOffset.UtcNow,
            Actor = actor.Actor,
            Action = action,
            Target = target,
            Result = "success",
            SourceIp = actor.SourceIp
        };

    private static CapturePolicyDispatch PolicyDispatch(
        CapturePolicy policy,
        CapturePolicyDispatchKind kind)
    {
        var now = DateTimeOffset.UtcNow;
        return new CapturePolicyDispatch
        {
            DispatchId = Guid.NewGuid().ToString("N"),
            TenantId = policy.TenantId,
            ProviderId = policy.ProviderId,
            PolicyId = policy.PolicyId,
            DesiredVersion = policy.Version,
            Kind = kind,
            Policy = kind == CapturePolicyDispatchKind.Apply ? Clone(policy) : null,
            CreatedAtUtc = now,
            AvailableAtUtc = now
        };
    }

    private async Task<IAsyncDisposable> AcquireMutationLeasesAsync(
        string tenantId,
        IEnumerable<string> providerIds,
        CancellationToken cancellationToken)
    {
        var resources = providerIds
            .Select(item => $"provider:{item.ToLowerInvariant()}")
            .Append($"tenant:{tenantId}")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();
        var owner = $"capture-policy:{Environment.ProcessId}:{Guid.NewGuid():N}";
        var acquired = new List<string>();
        var deadline = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(
            _options.ProviderMutationLockWaitSeconds, 1, 60));
        var leaseDuration = TimeSpan.FromSeconds(Math.Clamp(
            _options.ProviderMutationLeaseSeconds, 5, 120));
        try
        {
            foreach (var resource in resources)
            {
                while (true)
                {
                    var now = DateTimeOffset.UtcNow;
                    if (await _store.TryAcquireProviderMutationLeaseAsync(
                            resource,
                            owner,
                            now,
                            deadline.Add(leaseDuration),
                            cancellationToken))
                    {
                        acquired.Add(resource);
                        break;
                    }
                    if (now >= deadline)
                        throw new CaptureValidationException("Capture policy admission is busy; retry the mutation.");
                    await Task.Delay(50, cancellationToken);
                }
            }
            return new MutationLease(_store, owner, acquired);
        }
        catch
        {
            foreach (var resource in acquired)
                await _store.ReleaseProviderMutationLeaseAsync(resource, owner, CancellationToken.None);
            throw;
        }
    }

    private sealed class MutationLease(
        ICaptureControlStore store,
        string owner,
        IReadOnlyList<string> resources) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            foreach (var resource in resources.Reverse())
                await store.ReleaseProviderMutationLeaseAsync(resource, owner, CancellationToken.None);
        }
    }

    private void Validate(CapturePolicy policy)
    {
        policy.PolicyId = ValidateId(policy.PolicyId, "policy id");
        policy.ProviderId = ValidateId(policy.ProviderId, "provider id");
        _ = _providers.GetRequired(policy.ProviderId);
        EnsureProviderAssigned(policy.ProviderId, policy.TenantId);
        policy.Name = Required(policy.Name, "name", 160);
        policy.Description = Optional(policy.Description, 2000);
        if (policy.EstimatedIngressMbps < 0m || policy.EstimatedIngressMbps > 1_000_000m)
            throw new CaptureValidationException("Estimated ingress must be between 0 and 1,000,000 Mbps.");
        if (policy.Enabled && policy.Mode != CaptureMode.MetadataOnly && policy.EstimatedIngressMbps <= 0m)
            throw new CaptureValidationException(
                "An enabled packet-capture policy requires a positive estimated ingress for capacity admission.");
        if (policy.SamplingPercent <= 0m || policy.SamplingPercent > 100m)
            throw new CaptureValidationException("Sampling percent must be greater than 0 and at most 100.");
        if (policy.MaxSessionDurationSeconds is < 1 or > 3600)
            throw new CaptureValidationException("Session duration must be between 1 and 3,600 seconds.");
        if (policy.MaxBytesPerSession is < 65_536 or > 10L * 1024 * 1024 * 1024)
            throw new CaptureValidationException("Per-session bytes must be between 64 KiB and 10 GiB.");
        policy.StorageLifecycle ??= new CaptureStorageLifecycle();
        var maxRetentionDays = Math.Clamp(_options.MaxSessionMetadataRetentionDays, 1, 90);
        if (policy.StorageLifecycle.HotDays is < 1 ||
            policy.StorageLifecycle.ColdDays < 0 ||
            (long)policy.StorageLifecycle.HotDays + policy.StorageLifecycle.ColdDays > maxRetentionDays)
            throw new CaptureValidationException(
                $"Storage lifecycle must keep 1-{maxRetentionDays} total days with at least one hot day.");
        var lifecycleDays = policy.StorageLifecycle.HotDays + policy.StorageLifecycle.ColdDays;
        if (policy.RetentionDays != lifecycleDays)
            throw new CaptureValidationException("RetentionDays must equal StorageLifecycle.HotDays + ColdDays.");
        if (policy.Priority is < 1 or > 1000)
            throw new CaptureValidationException("Priority must be between 1 and 1,000.");

        policy.Scope ??= new CapturePolicyScope();
        policy.Scope.SensorIds = NormalizeIds(policy.Scope.SensorIds, "sensor id", 50);
        policy.Scope.SourceCidrs = NormalizeCidrs(policy.Scope.SourceCidrs, 50);
        policy.Scope.DestinationCidrs = NormalizeCidrs(policy.Scope.DestinationCidrs, 50);
        policy.Scope.ExcludedCidrs = NormalizeCidrs(policy.Scope.ExcludedCidrs, 50);
        policy.Scope.Ports = (policy.Scope.Ports ?? []).Distinct().Order().ToList();
        if (policy.Scope.Ports.Count > 100 || policy.Scope.Ports.Any(port => port is < 1 or > 65535))
            throw new CaptureValidationException("A policy can contain at most 100 valid TCP/UDP ports.");
        policy.Scope.Protocols = (policy.Scope.Protocols ?? [])
            .Select(item => item.Trim().ToLowerInvariant()).Where(item => item.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (policy.Scope.Protocols.Count > 10 || policy.Scope.Protocols.Any(item => !Protocols.Contains(item)))
            throw new CaptureValidationException("A policy contains an unsupported protocol.");
        policy.Scope.BpfFilter = Optional(policy.Scope.BpfFilter, 512);
        if (policy.Scope.BpfFilter is not null && !BpfPattern.IsMatch(policy.Scope.BpfFilter))
            throw new CaptureValidationException("BPF filter contains unsupported characters.");

        policy.Tls ??= new TlsInspectionPolicy();
        policy.Tls.ProviderId = Optional(policy.Tls.ProviderId, 128);
        if (policy.Tls.ProviderId is not null)
        {
            _ = _providers.GetRequired(policy.Tls.ProviderId);
            EnsureProviderAssigned(policy.Tls.ProviderId, policy.TenantId);
        }
        policy.Tls.CertificateProfileId = Optional(policy.Tls.CertificateProfileId, 128);
        policy.Tls.ExcludedCidrs = NormalizeCidrs(policy.Tls.ExcludedCidrs, 100);
        policy.Tls.ExcludedDomains = NormalizeDomains(policy.Tls.ExcludedDomains, 100);
        if (policy.Tls.Mode is TlsInspectionMode.ExternalProxy or TlsInspectionMode.NativeProxy)
        {
            if (!policy.Tls.FailOpen)
                throw new CaptureValidationException("Inline TLS providers must be fail-open.");
            if (string.IsNullOrWhiteSpace(policy.Tls.ProviderId))
                throw new CaptureValidationException("TLS proxy mode requires a configured provider id.");
            if (!string.Equals(policy.Tls.ProviderId, policy.ProviderId, StringComparison.OrdinalIgnoreCase))
                throw new CaptureValidationException(
                    "The TLS inspection provider must own this desired-state policy; create a separate policy for a separate capture provider.");
            if (!policy.Tls.AttemptQuicTcpFallback)
                throw new CaptureValidationException(
                    "Inline TLS policies must request QUIC/HTTP3 fallback to inspectable TCP/TLS.");
        }
        if (policy.Tls.RetainDecryptedArtifactsInProvider)
        {
            if (policy.Tls.Mode is not (TlsInspectionMode.ExternalProxy or TlsInspectionMode.NativeProxy) ||
                string.IsNullOrWhiteSpace(policy.Tls.ProviderId))
                throw new CaptureValidationException("Provider-owned decrypted artifacts require an explicit TLS proxy provider.");
            var tlsProvider = _providers.GetRequired(policy.Tls.ProviderId);
            if (!tlsProvider.Capabilities.Contains("tls-artifact-access") ||
                !tlsProvider.Capabilities.Contains("tls-preview") ||
                !tlsProvider.Capabilities.Contains("retention"))
                throw new CaptureValidationException("TLS provider lacks artifact access, bounded preview, or retention capability.");
        }
    }

    private void EnsureProviderAssigned(string providerId, string tenantId)
    {
        var provider = _options.Providers.FirstOrDefault(item =>
            item.Enabled && string.Equals(item.Id, providerId, StringComparison.OrdinalIgnoreCase));
        if (provider is null || !provider.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase))
            throw new CaptureValidationException(
                $"Provider '{providerId}' is not assigned to tenant '{tenantId}'.");
    }

    private static List<string> NormalizeIds(IEnumerable<string>? values, string field, int max)
    {
        var result = (values ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => ValidateId(item.Trim(), field)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (result.Count > max) throw new CaptureValidationException($"A policy can contain at most {max} {field} values.");
        return result;
    }

    private static List<string> NormalizeCidrs(IEnumerable<string>? values, int max)
    {
        var result = (values ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (result.Count > max) throw new CaptureValidationException($"A policy can contain at most {max} CIDR values.");
        foreach (var cidr in result)
        {
            var parts = cidr.Split('/', 2);
            if (!IPAddress.TryParse(parts[0], out var address)) throw new CaptureValidationException($"Invalid CIDR: {cidr}.");
            var maxPrefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            if (parts.Length == 2 && (!int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > maxPrefix))
                throw new CaptureValidationException($"Invalid CIDR prefix: {cidr}.");
        }
        return result;
    }

    private static List<string> NormalizeDomains(IEnumerable<string>? values, int max)
    {
        var result = (values ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (result.Count > max || result.Any(item => item.Length > 253 || !DomainPattern.IsMatch(item)))
            throw new CaptureValidationException($"A policy can contain at most {max} valid TLS exclusion domains.");
        return result;
    }

    private static string NormalizeTenant(string tenantId) => TopologyService.NormalizeTenantId(tenantId);
    private static string ValidateId(string value, string field)
    {
        value = value?.Trim() ?? "";
        if (!IdPattern.IsMatch(value)) throw new CaptureValidationException($"Invalid {field}.");
        return value;
    }
    private static string Required(string? value, string field, int max)
    {
        var text = value?.Trim();
        if (string.IsNullOrWhiteSpace(text) || text.Length > max)
            throw new CaptureValidationException($"{field} is required and must be at most {max} characters.");
        return text;
    }
    private static string? Optional(string? value, int max)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text)) return null;
        if (text.Length > max) throw new CaptureValidationException($"Text must be at most {max} characters.");
        return text;
    }
    private static CapturePolicy Clone(CapturePolicy value) =>
        JsonSerializer.Deserialize<CapturePolicy>(JsonSerializer.Serialize(value)) ?? new CapturePolicy();
}
