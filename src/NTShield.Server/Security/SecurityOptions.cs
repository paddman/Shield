namespace NTShield.Server.Security;

public sealed class SecurityOptions
{
    public const string SectionName = "Security";
    public const string ApiKeyHeader = "X-NTShield-Api-Key";

    /// <summary>When true, API requires agent or operator keys (except public health).</summary>
    public bool RequireAuth { get; set; }

    /// <summary>Shared secret for first-time agent registration.</summary>
    public string EnrollmentToken { get; set; } = "";

    /// <summary>Dashboard / operator API key (plaintext in config or secrets file).</summary>
    public string OperatorApiKey { get; set; } = "";

    public bool AutoGenerateSecretsOnBoot { get; set; } = true;

    public string SecretsFilePath { get; set; } =
        @"C:\ProgramData\NTShield\Server\secrets.json";

    public bool EnableMtls { get; set; }
    public string? CertificatePath { get; set; }
    public string? CertificatePassword { get; set; }

    /// <summary>
    /// Extra DNS names / IPs for the self-signed HTTPS cert SAN (comma-separated).
    /// Use for public/NAT IP e.g. "203.0.113.10,sentinel.example.com".
    /// </summary>
    public string? CertificateExtraSans { get; set; }

    /// <summary>Alias for a single public host/IP (same as CertificateExtraSans).</summary>
    public string? PublicHost { get; set; }

    /// <summary>When true, delete and recreate central.pfx on next boot.</summary>
    public bool RegenerateCertificate { get; set; }

    public long MaxRequestBodyBytes { get; set; } = 20 * 1024 * 1024;

    /// <summary>When true, reject heartbeats from agents that report unsigned binary.</summary>
    public bool RequireSignedAgent { get; set; }

    /// <summary>Optional allowlist of agent binary SHA-256 (lowercase hex). Empty = any hash ok.</summary>
    public List<string> ApprovedAgentSha256 { get; set; } = [];

    public string? PolicySigningPublicKeyPem { get; set; }
}
