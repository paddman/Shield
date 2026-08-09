using NTShield.Shared.Security;

namespace NTShield.Shared.Models;

/// <summary>Central-delivered agent policy (heartbeat pull). Versioned; agents apply when newer.</summary>
public sealed class AgentPolicy
{
    private string? _actionSigningPublicKeyPem;
    private string? _actionSigningKeyId;

    public string PolicyId { get; set; } = "default";
    public int PolicyVersion { get; set; } = 1;

    /// <summary>Ids | Ips</summary>
    public string Mode { get; set; } = "Ids";
    public bool DetectOnly { get; set; } = true;
    public bool AutoRemediate { get; set; }
    public int? HeartbeatSeconds { get; set; }
    public double? CpuAlertPercent { get; set; }
    public double? MemAlertPercent { get; set; }
    public double? DiskAlertPercent { get; set; }
    public bool AllowProcessTerminate { get; set; }
    public bool AllowNetworkIsolation { get; set; } = true;
    public bool AutoBlockSourceIp { get; set; } = true;
    public bool AutoBlockDestinationIp { get; set; } = true;
    public string AutoBlockMinSeverity { get; set; } = "High";
    public List<string>? LogPaths { get; set; }
    public ProtectionPack? ProtectionPack { get; set; }

    /// <summary>Optional RSA signature over policy JSON (base64). Verified when public key configured.</summary>
    public string? Signature { get; set; }

    /// <summary>
    /// Central action-signing public key. Existing policies loaded from storage
    /// inherit the active Central key at serialization time; agents pin it when
    /// applying the newer policy version.
    /// </summary>
    public string? ActionSigningPublicKeyPem
    {
        get => string.IsNullOrWhiteSpace(_actionSigningPublicKeyPem)
            ? ActionApprovalCrypto.TrustedPublicKeyPem
            : _actionSigningPublicKeyPem;
        set => _actionSigningPublicKeyPem = value;
    }

    public string? ActionSigningKeyId
    {
        get => string.IsNullOrWhiteSpace(_actionSigningKeyId)
            ? ActionApprovalCrypto.TrustedKeyId
            : _actionSigningKeyId;
        set => _actionSigningKeyId = value;
    }
}
