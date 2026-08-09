using System.Text.Json.Serialization;

namespace NTShield.Server.Capture;

[JsonConverter(typeof(JsonStringEnumConverter<CaptureMode>))]
public enum CaptureMode
{
    MetadataOnly,
    SelectivePackets,
    FullPackets
}

[JsonConverter(typeof(JsonStringEnumConverter<TlsInspectionMode>))]
public enum TlsInspectionMode
{
    Disabled,
    MetadataOnly,
    ExternalProxy,
    NativeProxy
}

[JsonConverter(typeof(JsonStringEnumConverter<CaptureJobStatus>))]
public enum CaptureJobStatus
{
    Queued,
    Running,
    Completed,
    Failed,
    Expired
}

[JsonConverter(typeof(JsonStringEnumConverter<CapturePolicyDispatchKind>))]
public enum CapturePolicyDispatchKind
{
    Apply,
    Delete
}

[JsonConverter(typeof(JsonStringEnumConverter<CaptureProviderState>))]
public enum CaptureProviderState
{
    Unknown,
    Healthy,
    Degraded,
    Unavailable
}

[JsonConverter(typeof(JsonStringEnumConverter<CaptureStorageTier>))]
public enum CaptureStorageTier
{
    MetadataOnly,
    Hot,
    Cold,
    Archive
}

[JsonConverter(typeof(JsonStringEnumConverter<CaptureStoragePressureState>))]
public enum CaptureStoragePressureState
{
    Normal,
    Warning,
    Critical
}

public static class CaptureGapReasonCodes
{
    public const string ProviderUnavailable = "provider_unavailable";
    public const string PolicyApplyFailed = "policy_apply_failed";
    public const string PolicyDeleteFailed = "policy_delete_failed";
    public const string StorageCriticalMetadataOnly = "storage_critical_metadata_only";
    public const string TlsQuicBypass = "tls_quic_bypass";
    public const string TlsCertificatePinningBypass = "tls_certificate_pinning_bypass";
    public const string TlsMutualAuthenticationBypass = "tls_mtls_bypass";
    public const string TlsPolicyExclusion = "tls_policy_exclusion";
    public const string TlsInspectionFailed = "tls_inspection_failed";

    public static IReadOnlySet<string> ProviderReported { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        StorageCriticalMetadataOnly,
        TlsQuicBypass,
        TlsCertificatePinningBypass,
        TlsMutualAuthenticationBypass,
        TlsPolicyExclusion,
        TlsInspectionFailed
    };
}

public sealed class CapturePolicy
{
    public string PolicyId { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public bool Enabled { get; set; }
    public string ProviderId { get; set; } = "";
    public CaptureMode Mode { get; set; } = CaptureMode.MetadataOnly;
    public CapturePolicyScope Scope { get; set; } = new();
    public TlsInspectionPolicy Tls { get; set; } = new();
    public decimal EstimatedIngressMbps { get; set; }
    public decimal SamplingPercent { get; set; } = 100m;
    public int MaxSessionDurationSeconds { get; set; } = 300;
    public long MaxBytesPerSession { get; set; } = 100 * 1024 * 1024;
    public int RetentionDays { get; set; } = 90;
    public CaptureStorageLifecycle StorageLifecycle { get; set; } = new();
    public int Priority { get; set; } = 100;
    public int Version { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}

public sealed class CaptureStorageLifecycle
{
    public int HotDays { get; set; } = 7;
    public int ColdDays { get; set; } = 83;

    [JsonIgnore]
    public int ExpireAfterDays => checked(HotDays + ColdDays);
}

public sealed class CapturePolicyScope
{
    public List<string> SensorIds { get; set; } = [];
    public List<string> SourceCidrs { get; set; } = [];
    public List<string> DestinationCidrs { get; set; } = [];
    public List<int> Ports { get; set; } = [];
    public List<string> Protocols { get; set; } = [];
    public List<string> ExcludedCidrs { get; set; } = [];
    public string? BpfFilter { get; set; }
}

public sealed class TlsInspectionPolicy
{
    public TlsInspectionMode Mode { get; set; } = TlsInspectionMode.MetadataOnly;
    public string? ProviderId { get; set; }
    public bool FailOpen { get; set; } = true;
    /// <summary>Requests QUIC/HTTP3 blocking so clients retry over inspectable TCP/TLS.</summary>
    public bool AttemptQuicTcpFallback { get; set; } = true;
    public string? CertificateProfileId { get; set; }
    public List<string> ExcludedDomains { get; set; } = [];
    public List<string> ExcludedCidrs { get; set; } = [];

    /// <summary>Allows an approved provider to retain an encrypted artifact. Central never stores its body.</summary>
    public bool RetainDecryptedArtifactsInProvider { get; set; }
}

public sealed class CapturePolicySimulationRequest
{
    public CapturePolicy Policy { get; set; } = new();
}

public sealed class CaptureAdmissionResult
{
    public bool Admitted { get; set; }
    public string ProviderId { get; set; } = "";
    public decimal ProjectedIngressMbps { get; set; }
    public long ProjectedRetainedBytes { get; set; }
    public long TenantProjectedRetainedBytes { get; set; }
    public long ProviderProjectedRetainedBytes { get; set; }
    public long CapacityBytes { get; set; }
    public long AvailableBytes { get; set; }
    public CaptureProviderState ProviderState { get; set; }
    public bool ProviderHealthStale { get; set; }
    public List<string> Reasons { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

public sealed class CaptureSessionMetadata
{
    public string SessionId { get; set; } = "";
    public string FlowId { get; set; } = "";
    public string? CorrelationId { get; set; }
    public string? CampaignId { get; set; }
    public string? EdgeId { get; set; }
    public string? IncidentId { get; set; }
    public string TenantId { get; set; } = "default";
    public string ProviderId { get; set; } = "";
    public string SensorId { get; set; } = "";
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset? EndedAtUtc { get; set; }
    public string SourceIp { get; set; } = "";
    public int? SourcePort { get; set; }
    public string DestinationIp { get; set; } = "";
    public int? DestinationPort { get; set; }
    public string Protocol { get; set; } = "";
    public string? Application { get; set; }
    public string? SourceHost { get; set; }
    public string? DestinationHost { get; set; }
    public string? SourceAgentId { get; set; }
    public string? DestinationAgentId { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? UserName { get; set; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public bool PayloadAvailable { get; set; }
    public long PayloadBytes { get; set; }
    public string? PayloadSha256 { get; set; }
    public string? EncryptionKeyVersion { get; set; }
    public CaptureStorageTier StorageTier { get; set; } = CaptureStorageTier.MetadataOnly;
    public string? StoragePoolId { get; set; }
    public DateTimeOffset? HotUntilUtc { get; set; }
    public DateTimeOffset? RetainUntilUtc { get; set; }
    public TlsSessionMetadata? Tls { get; set; }
    public List<string> Tags { get; set; } = [];

    // An opaque provider handle is persisted but never serialized to an API or AI DTO.
    [JsonIgnore]
    public string? PayloadReference { get; set; }
}

public sealed class TlsSessionMetadata
{
    public bool IsTls { get; set; }
    public string? Version { get; set; }
    public string? ServerName { get; set; }
    public string? Alpn { get; set; }
    public string? Cipher { get; set; }
    public string? Ja3 { get; set; }
    public string? Ja4 { get; set; }
    public string? CertificateSha256 { get; set; }
    public string? CertificateIssuer { get; set; }
    public string? CertificateSubject { get; set; }
    public DateTimeOffset? CertificateNotAfterUtc { get; set; }
    public string DecryptionState { get; set; } = "not_attempted";
    public bool DecryptedArtifactAvailable { get; set; }
    public string? DecryptedArtifactProviderId { get; set; }
    public string? DecryptedArtifactSha256 { get; set; }
    public string? DecryptedArtifactKeyVersion { get; set; }
    public CaptureStorageTier DecryptedArtifactStorageTier { get; set; } = CaptureStorageTier.MetadataOnly;
    public string? DecryptedArtifactStoragePoolId { get; set; }

    [JsonIgnore]
    public string? DecryptedArtifactReference { get; set; }
}

public sealed class TlsDecodedPreview
{
    public string SessionId { get; set; } = "";
    public string ArtifactSha256 { get; set; } = "";
    public bool Truncated { get; set; } = true;
    public List<TlsDecodedTransactionPreview> Transactions { get; set; } = [];
}

/// <summary>Normalized decoded metadata only. It intentionally has no header values or body field.</summary>
public sealed class TlsDecodedTransactionPreview
{
    public DateTimeOffset TimestampUtc { get; set; }
    public string Protocol { get; set; } = "";
    public string? Method { get; set; }
    public string? Authority { get; set; }
    public string? PathTemplate { get; set; }
    public int? StatusCode { get; set; }
    public string? RequestContentType { get; set; }
    public string? ResponseContentType { get; set; }
    public long RequestBodyBytes { get; set; }
    public long ResponseBodyBytes { get; set; }
    public List<string> RequestHeaderNames { get; set; } = [];
    public List<string> ResponseHeaderNames { get; set; } = [];
}

public sealed class CaptureSessionQuery
{
    public DateTimeOffset? FromUtc { get; set; }
    public DateTimeOffset? ToUtc { get; set; }
    public string? Address { get; set; }
    public int? Port { get; set; }
    public string? Protocol { get; set; }
    public bool? PayloadAvailable { get; set; }
    public string? ProviderId { get; set; }
    public string? CampaignId { get; set; }
    public string? EdgeId { get; set; }
    public string? Cursor { get; set; }
    public int Take { get; set; } = 100;
}

public sealed class CaptureSessionPage
{
    public IReadOnlyList<CaptureSessionMetadata> Items { get; set; } = [];
    public string? NextCursor { get; set; }
}

public sealed class PacketAccessRequest
{
    public string Purpose { get; set; } = "";
    public int? TtlSeconds { get; set; }
}

public sealed class PacketAccessGrant
{
    public string GrantId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public Uri AccessUrl { get; set; } = new("about:blank");
    public DateTimeOffset ExpiresAtUtc { get; set; }
}

public sealed class CaptureExportAccessGrant
{
    public string GrantId { get; set; } = "";
    public string JobId { get; set; } = "";
    public Uri AccessUrl { get; set; } = new("about:blank");
    public DateTimeOffset ExpiresAtUtc { get; set; }
}

public sealed class CreateCaptureExportRequest
{
    public List<string> SessionIds { get; set; } = [];
    public string Format { get; set; } = "pcap";
    public string Purpose { get; set; } = "";
    public int? RetentionHours { get; set; }
}

public sealed class CreateSessionExportRequest
{
    public string Format { get; set; } = "pcap";
    public string Purpose { get; set; } = "";
    public int? RetentionHours { get; set; }
}

public sealed class CaptureExportJob
{
    public string JobId { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public string ProviderId { get; set; } = "";
    public List<string> SessionIds { get; set; } = [];
    public string Format { get; set; } = "pcap";
    public string Purpose { get; set; } = "";
    public CaptureJobStatus Status { get; set; } = CaptureJobStatus.Queued;
    public string RequestedBy { get; set; } = "operator";
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public string? ErrorCode { get; set; }
    public int AttemptCount { get; set; }
    public string? OutputSha256 { get; set; }
    public string? EncryptionKeyVersion { get; set; }
    public CaptureStorageTier StorageTier { get; set; } = CaptureStorageTier.MetadataOnly;
    public string? StoragePoolId { get; set; }

    [JsonIgnore]
    public string? OutputReference { get; set; }

    // Worker coordination is control-plane-only and must not disclose instance identity.
    [JsonIgnore]
    public string? ClaimOwner { get; set; }

    [JsonIgnore]
    public DateTimeOffset? ClaimExpiresAtUtc { get; set; }
}

public sealed class CapturePolicyDispatch
{
    public string DispatchId { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public string ProviderId { get; set; } = "";
    public string PolicyId { get; set; } = "";
    public int DesiredVersion { get; set; }
    public CapturePolicyDispatchKind Kind { get; set; }
    public CapturePolicy? Policy { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset AvailableAtUtc { get; set; }
    public int AttemptCount { get; set; }
    public string? LastErrorCode { get; set; }

    [JsonIgnore]
    public string? ClaimOwner { get; set; }

    [JsonIgnore]
    public DateTimeOffset? ClaimExpiresAtUtc { get; set; }
}

/// <summary>
/// Safe record of a rejected provider item. The raw item and opaque references are never retained.
/// </summary>
public sealed class CaptureProviderQuarantineEntry
{
    public string QuarantineId { get; set; } = "";
    public string ProviderId { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public string? SessionIdHint { get; set; }
    public string ItemSha256 { get; set; } = "";
    public string ReasonCode { get; set; } = "invalid_provider_session";
    public DateTimeOffset ReceivedAtUtc { get; set; }
}

public sealed class CaptureProviderHealth
{
    public string ProviderId { get; set; } = "";
    public string Kind { get; set; } = "";
    public CaptureProviderState State { get; set; } = CaptureProviderState.Unknown;
    public DateTimeOffset CheckedAtUtc { get; set; }
    public long CapacityBytes { get; set; }
    public long UsedBytes { get; set; }
    public long HotCapacityBytes { get; set; }
    public long HotUsedBytes { get; set; }
    public long ColdCapacityBytes { get; set; }
    public long ColdUsedBytes { get; set; }
    public CaptureStoragePressureState StoragePressure { get; set; }
    public bool StorageCriticalMetadataOnly { get; set; }
    public decimal IngestMbps { get; set; }
    public decimal MaxSustainableIngressMbps { get; set; }
    public int QueueDepth { get; set; }
    public string? StatusCode { get; set; }
    public bool FailOpen { get; set; } = true;
    public List<string> Capabilities { get; set; } = [];
    public List<string> ActiveVisibilityGapReasonCodes { get; set; } = [];
}

public sealed class CaptureHealthSummary
{
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public IReadOnlyList<CaptureProviderHealth> Providers { get; set; } = [];
    public int OpenVisibilityGaps { get; set; }
    public bool TrafficFailOpen { get; set; } = true;
}

public sealed class VisibilityGap
{
    public string GapId { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public string ProviderId { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset? EndedAtUtc { get; set; }
    public bool FailOpen { get; set; } = true;
    public string? DetailCode { get; set; }
}

public sealed class CaptureAuditEntry
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public DateTimeOffset TimestampUtc { get; set; }
    public string Actor { get; set; } = "";
    public string Action { get; set; } = "";
    public string? Target { get; set; }
    public string Result { get; set; } = "";
    public string? DetailCode { get; set; }
    public string? Purpose { get; set; }
    public string? SourceIp { get; set; }
}

/// <summary>A bounded evidence reference safe for an AI request. It never contains packet bytes or access URLs.</summary>
public sealed class CaptureAiEvidenceReference
{
    public string SessionId { get; set; } = "";
    public string ProviderId { get; set; } = "";
    public DateTimeOffset StartedAtUtc { get; set; }
    public string Flow { get; set; } = "";
    public string Protocol { get; set; } = "";
    public long ByteCount { get; set; }
    public bool PayloadAvailable { get; set; }
    public string? PayloadSha256 { get; set; }
    public CaptureStorageTier StorageTier { get; set; }
    public string? TlsServerName { get; set; }
    public string? TlsFingerprint { get; set; }
}
