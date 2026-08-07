namespace NTShield.Server.AI;

/// <summary>
/// Server-side bridge settings for the Brain per-asset anomaly baseline.
/// The browser never receives the API key.
/// </summary>
public sealed class AiAnomalyOptions
{
    public const string SectionName = "AIAnomaly";

    public bool Enabled { get; set; }
    public string BaseUrl { get; set; } = string.Empty;
    /// <summary>
    /// Brain tenant mapping. Use "{tenant}" only when Brain is configured
    /// with the same tenant IDs as Central; a fixed value is safer for a
    /// single-tenant Brain deployment.
    /// </summary>
    public string TenantId { get; set; } = "default";
    public string ApiKey { get; set; } = string.Empty;
    public bool SkipTlsVerify { get; set; }
    public int TimeoutSeconds { get; set; } = 5;
    public bool Learn { get; set; } = true;
}
