namespace NTShield.Server.Security;

public sealed class SecurityOptions
{
    public const string SectionName = "Security";
    public const string ApiKeyHeader = "X-NTShield-Api-Key";

    /// <summary>
    /// Secure default: every non-public API requires an operator or per-agent key.
    /// Legacy soft mode must be selected explicitly and still never opens operator APIs.
    /// </summary>
    public bool RequireAuth { get; set; } = true;

    /// <summary>
    /// Emergency lab compatibility only. When true with RequireAuth=false, agent
    /// telemetry paths may be anonymous. Operator/read/write APIs remain protected.
    /// </summary>
    public bool AllowLegacyAnonymousAgentIngest { get; set; }

    /// <summary>Shared secret for first-time agent registration.</summary>
    public string EnrollmentToken { get; set; } = "";

    /// <summary>Dashboard / operator API key (plaintext only in protected Central secrets storage).</summary>
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

    /// <summary>Central-only RSA private key used to sign destructive response actions.</summary>
    public string ActionSigningPrivateKeyPem { get; set; } = "";

    /// <summary>RSA public key distributed to agents through versioned policy.</summary>
    public string ActionSigningPublicKeyPem { get; set; } = "";

    public string ActionSigningKeyId { get; set; } = "";

    /// <summary>Default validity window for an approved destructive action.</summary>
    public int ActionLifetimeMinutes { get; set; } = 5;

    /// <summary>Hard upper bound for a client-requested action validity window.</summary>
    public int MaxActionLifetimeMinutes { get; set; } = 15;
}
