namespace NTShield.Server.Capture;

/// <summary>
/// Data-plane adapter boundary. Implementations operate Arkime/MinIO or an
/// approved TLS proxy; Central never captures packets itself.
/// </summary>
public interface ICaptureProviderAdapter
{
    string ProviderId { get; }
    string Kind { get; }
    bool FailOpen { get; }
    IReadOnlySet<string> Capabilities { get; }

    Task<CaptureProviderHealth> ProbeAsync(CancellationToken cancellationToken);
    Task<CaptureProviderSessionPage> FetchSessionMetadataAsync(
        string? cursor,
        int take,
        CancellationToken cancellationToken);
    Task ApplyPolicyAsync(CapturePolicy policy, CancellationToken cancellationToken);
    Task DeletePolicyAsync(string tenantId, string policyId, CancellationToken cancellationToken);
    Task<ProviderAccessGrant> CreateSessionAccessAsync(
        ProviderSessionAccessRequest request,
        CancellationToken cancellationToken);
    Task<ProviderAccessGrant> CreateTlsArtifactAccessAsync(
        ProviderTlsArtifactAccessRequest request,
        CancellationToken cancellationToken);
    Task<TlsDecodedPreview> GetTlsPreviewAsync(
        ProviderTlsPreviewRequest request,
        CancellationToken cancellationToken);
    Task<ProviderExportResult> StartExportAsync(
        ProviderExportRequest request,
        CancellationToken cancellationToken);
    Task<ProviderAccessGrant> CreateExportAccessAsync(
        ProviderExportAccessRequest request,
        CancellationToken cancellationToken);
    Task RevokeAccessGrantAsync(string grantId, CancellationToken cancellationToken);
    Task DeletePayloadAsync(
        string tenantId,
        string payloadReference,
        CancellationToken cancellationToken);
}

public sealed class CaptureProviderSessionPage
{
    public List<CaptureProviderSession> Items { get; set; } = [];
    public string? NextCursor { get; set; }
}

public sealed class CaptureProviderSession
{
    public string TenantId { get; set; } = "default";
    public string SessionId { get; set; } = "";
    public string FlowId { get; set; } = "";
    public string? CorrelationId { get; set; }
    public string? CampaignId { get; set; }
    public string? EdgeId { get; set; }
    public string? IncidentId { get; set; }
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
    public string? PayloadReference { get; set; }
    public string? TlsArtifactReference { get; set; }
    public TlsSessionMetadata? Tls { get; set; }
    public List<string> Tags { get; set; } = [];
}

public sealed class ProviderSessionAccessRequest
{
    public string TenantId { get; set; } = "default";
    public string SessionId { get; set; } = "";
    public string PayloadReference { get; set; } = "";
    public string Purpose { get; set; } = "";
    public string Actor { get; set; } = "";
    public int TtlSeconds { get; set; }
}

public sealed class ProviderExportRequest
{
    public string TenantId { get; set; } = "default";
    public string JobId { get; set; } = "";
    public List<string> PayloadReferences { get; set; } = [];
    public string Format { get; set; } = "pcap";
    public DateTimeOffset ExpiresAtUtc { get; set; }
}

public sealed class ProviderTlsArtifactAccessRequest
{
    public string TenantId { get; set; } = "default";
    public string SessionId { get; set; } = "";
    public string ArtifactReference { get; set; } = "";
    public string Purpose { get; set; } = "";
    public string Actor { get; set; } = "";
    public int TtlSeconds { get; set; }
}

public sealed class ProviderTlsPreviewRequest
{
    public string TenantId { get; set; } = "default";
    public string SessionId { get; set; } = "";
    public string ArtifactReference { get; set; } = "";
    public string Purpose { get; set; } = "";
    public string Actor { get; set; } = "";
    public int MaxTransactions { get; set; }
}

public sealed class ProviderExportResult
{
    public string OutputReference { get; set; } = "";
    public string? OutputSha256 { get; set; }
    public string? EncryptionKeyVersion { get; set; }
    public CaptureStorageTier StorageTier { get; set; } = CaptureStorageTier.Hot;
    public string? StoragePoolId { get; set; }
}

public sealed class ProviderExportAccessRequest
{
    public string TenantId { get; set; } = "default";
    public string JobId { get; set; } = "";
    public string OutputReference { get; set; } = "";
    public string Purpose { get; set; } = "";
    public string Actor { get; set; } = "";
    public int TtlSeconds { get; set; }
}

public sealed class ProviderAccessGrant
{
    public string GrantId { get; set; } = "";
    public string AccessUrl { get; set; } = "";
    public DateTimeOffset ExpiresAtUtc { get; set; }
}
