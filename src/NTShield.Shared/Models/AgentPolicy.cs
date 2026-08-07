namespace NTShield.Shared.Models;

/// <summary>Central-delivered agent policy (heartbeat pull). Versioned; agents apply when newer.</summary>
public sealed class AgentPolicy
{
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
}
