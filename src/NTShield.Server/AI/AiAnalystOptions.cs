namespace NTShield.Server.AI;

/// <summary>
/// Optional server-side bridge to NT Shield Brain. The browser never receives
/// this API key; Central forwards it only to the configured Brain service.
/// </summary>
public sealed class AiAnalystOptions
{
    public const string SectionName = "AIAnalyst";

    public bool Enabled { get; set; }
    public string BaseUrl { get; set; } = string.Empty;
    /// <summary>Server-side Brain tenant mapping; never trust the browser header for this.</summary>
    public string TenantId { get; set; } = "default";
    public string ApiKey { get; set; } = string.Empty;
    public bool SkipTlsVerify { get; set; }
    public int TimeoutSeconds { get; set; } = 90;
}
