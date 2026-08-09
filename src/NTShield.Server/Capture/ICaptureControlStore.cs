namespace NTShield.Server.Capture;

public readonly record struct CaptureSessionCursor(DateTimeOffset StartedAtUtc, string SessionId);

public interface ICaptureControlStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CapturePolicy>> ListPoliciesAsync(string tenantId, CancellationToken cancellationToken = default);
    Task<CapturePolicy?> GetPolicyAsync(string tenantId, string policyId, CancellationToken cancellationToken = default);
    Task<bool> CreatePolicyMutationAsync(
        CapturePolicy policy,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default);
    Task<bool> TryUpdatePolicyMutationAsync(
        CapturePolicy policy,
        int expectedVersion,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default);
    Task<bool> TryDeletePolicyMutationAsync(
        string tenantId,
        string policyId,
        int expectedVersion,
        CaptureAuditEntry audit,
        CapturePolicyDispatch dispatch,
        CancellationToken cancellationToken = default);
    Task<bool> TryAcquireProviderMutationLeaseAsync(
        string providerId,
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken = default);
    Task ReleaseProviderMutationLeaseAsync(
        string providerId,
        string owner,
        CancellationToken cancellationToken = default);
    Task<CapturePolicyDispatch?> TryClaimNextPolicyDispatchAsync(
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseExpiresAtUtc,
        CancellationToken cancellationToken = default);
    Task<bool> CompletePolicyDispatchAsync(
        string dispatchId,
        string owner,
        CancellationToken cancellationToken = default);
    Task<bool> ReleasePolicyDispatchAsync(
        CapturePolicyDispatch dispatch,
        string owner,
        DateTimeOffset availableAtUtc,
        string errorCode,
        CancellationToken cancellationToken = default);

    Task<bool> UpsertSessionAsync(CaptureSessionMetadata session, CancellationToken cancellationToken = default);
    Task<CaptureSessionMetadata?> GetSessionAsync(string tenantId, string sessionId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CaptureSessionMetadata>> QuerySessionsAsync(
        string tenantId,
        CaptureSessionQuery query,
        CaptureSessionCursor? cursor,
        int take,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CaptureSessionMetadata>> ListExpiredSessionsAsync(int take, CancellationToken cancellationToken = default);
    Task DeleteSessionAsync(string tenantId, string sessionId, CancellationToken cancellationToken = default);

    Task CreateExportJobWithAuditAsync(
        CaptureExportJob job,
        CaptureAuditEntry audit,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CaptureExportJob>> ListExportJobsAsync(string tenantId, int take, CancellationToken cancellationToken = default);
    Task<CaptureExportJob?> GetExportJobAsync(string tenantId, string jobId, CancellationToken cancellationToken = default);
    Task<CaptureExportJob?> TryClaimNextExportJobAsync(
        string owner,
        DateTimeOffset nowUtc,
        DateTimeOffset leaseExpiresAtUtc,
        CancellationToken cancellationToken = default);
    Task<bool> TryUpdateClaimedExportJobAsync(
        CaptureExportJob job,
        string owner,
        CancellationToken cancellationToken = default);

    Task UpsertProviderHealthAsync(CaptureProviderHealth health, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CaptureProviderHealth>> ListProviderHealthAsync(CancellationToken cancellationToken = default);
    Task<string?> GetProviderCursorAsync(string providerId, CancellationToken cancellationToken = default);
    Task SetProviderCursorAsync(string providerId, string? cursor, CancellationToken cancellationToken = default);
    Task CommitProviderSyncPageAsync(
        string providerId,
        string? cursor,
        IReadOnlyList<CaptureProviderQuarantineEntry> quarantined,
        CancellationToken cancellationToken = default);

    Task<VisibilityGap?> GetOpenVisibilityGapAsync(string tenantId, string providerId, string reason, CancellationToken cancellationToken = default);
    Task CreateVisibilityGapAsync(VisibilityGap gap, CancellationToken cancellationToken = default);
    Task CloseVisibilityGapsAsync(
        string tenantId,
        string providerId,
        string reason,
        DateTimeOffset endedAtUtc,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<VisibilityGap>> ListVisibilityGapsAsync(string tenantId, bool openOnly, int take, CancellationToken cancellationToken = default);

    Task AppendAuditAsync(CaptureAuditEntry entry, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CaptureAuditEntry>> ListAuditAsync(string tenantId, int take, CancellationToken cancellationToken = default);
}
