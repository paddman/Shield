using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

/// <summary>Signed protection content delivered by Central. PayloadJson is the exact signed bytes.</summary>
public sealed class ProtectionPack
{
    public string PackId { get; set; } = "ntshield-default";
    public int Version { get; set; } = 1;
    public string PayloadJson { get; set; } = "{}";
    public string Sha256 { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public DateTimeOffset PublishedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ProtectionPackPayload
{
    public List<ProtectionHashSignature> HashSignatures { get; set; } = [];
    public string YaraRules { get; set; } = string.Empty;
}

public sealed class ProtectionHashSignature
{
    public string Sha256 { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public Severity Severity { get; set; } = Severity.High;
    public string Description { get; set; } = string.Empty;
}

public sealed class ProtectionSignal
{
    public string Source { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public Severity Severity { get; set; } = Severity.Medium;
    public int Score { get; set; }
    public string Evidence { get; set; } = string.Empty;
}

public sealed class FileScanResult
{
    public string ScanId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Path { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Verdict { get; set; } = "clean";
    public Severity Severity { get; set; } = Severity.Low;
    public int Score { get; set; }
    public string DefenderStatus { get; set; } = "not-run";
    public string YaraStatus { get; set; } = "not-run";
    public int RulePackVersion { get; set; }
    public Dictionary<string, double> Features { get; set; } = [];
    public List<ProtectionSignal> Signals { get; set; } = [];
}

public sealed class QuarantineResult
{
    public bool Success { get; set; }
    public string Status { get; set; } = "failed";
    public string QuarantineId { get; set; } = string.Empty;
    public string? VaultPath { get; set; }
    public string? OriginalPath { get; set; }
    public string? Sha256 { get; set; }
    public string? Error { get; set; }
}
