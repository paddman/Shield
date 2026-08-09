namespace NTShield.Server.Capture;

public sealed class CaptureControlOptions
{
    public const string SectionName = "CaptureControl";

    public bool Enabled { get; set; }
    public string StoreKind { get; set; } = "sqlite-lab";
    public string DatabasePath { get; set; } =
        @"C:\ProgramData\NTShield\Server\capture-control.db";
    public int MaxPoliciesPerTenant { get; set; } = 100;
    public int MaxSessionsPerQuery { get; set; } = 200;
    public int MaxExportSessions { get; set; } = 100;
    public int MaxAuditEntriesPerQuery { get; set; } = 200;
    public int MaxTlsPreviewTransactions { get; set; } = 20;
    public int DefaultSessionRetentionDays { get; set; } = 90;
    public int MaxSessionMetadataRetentionDays { get; set; } = 90;
    public int AccessGrantTtlSeconds { get; set; } = 300;
    public int MaxAccessGrantTtlSeconds { get; set; } = 900;
    public int ExportRetentionHours { get; set; } = 24;
    public int MaxExportRetentionHours { get; set; } = 168;
    public int HealthProbeIntervalSeconds { get; set; } = 30;
    public int ProviderHealthStaleSeconds { get; set; } = 120;
    public int RetentionSweepIntervalMinutes { get; set; } = 15;
    public int ProviderSyncIntervalSeconds { get; set; } = 15;
    public int PolicyReconcileIntervalSeconds { get; set; } = 15;
    public int ProviderRequestTimeoutSeconds { get; set; } = 15;
    public int ExportClaimLeaseSeconds { get; set; } = 120;
    public int PolicyDispatchLeaseSeconds { get; set; } = 120;
    public int ProviderMutationLeaseSeconds { get; set; } = 120;
    public int ProviderMutationLockWaitSeconds { get; set; } = 15;
    public int MaxProviderResponseBytes { get; set; } = 4 * 1024 * 1024;
    public long DefaultTenantCapacityBytes { get; set; } = 500L * 1024 * 1024 * 1024;
    public decimal CapacityAdmissionPercent { get; set; } = 85m;
    public bool RequireFreshProviderHealthForActivation { get; set; }
    public List<CaptureProviderOptions> Providers { get; set; } = [];
}

public sealed class CaptureProviderOptions
{
    public string Id { get; set; } = "";
    public string Kind { get; set; } = "arkime-minio";
    public bool Enabled { get; set; } = true;
    public string BaseUrl { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string HealthPath { get; set; } = "/v1/health";
    public string SessionsPath { get; set; } = "/v1/sessions";
    public string PolicyPath { get; set; } = "/v1/policies";
    public string AccessPath { get; set; } = "/v1/access-grants";
    public string RevokeAccessPath { get; set; } = "/v1/access-grants/revoke";
    public string TlsPreviewPath { get; set; } = "/v1/tls/previews";
    public string ExportPath { get; set; } = "/v1/exports";
    public string DeletePayloadPath { get; set; } = "/v1/payloads/delete";
    public long CapacityBytes { get; set; }
    public decimal MaxSustainableIngressMbps { get; set; }
    public bool FailOpen { get; set; } = true;
    public List<string> TenantIds { get; set; } = [];
    public List<string> Capabilities { get; set; } =
        ["metadata", "policy", "payload-access", "export", "retention"];
}
