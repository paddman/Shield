using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

public sealed class DetectionAlert
{
    public long Id { get; set; }
    public string AlertId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? DestinationIp { get; set; }
    public string? Username { get; set; }
    public int EventCount { get; set; }
    public int DistinctUserCount { get; set; }
    public int DistinctDestinationCount { get; set; }
    public string EvidenceJson { get; set; } = "[]";
    public int? IncidentScore { get; set; }
    public string? DetectionStage { get; set; }
    public string? FilePath { get; set; }
    public string? FileSha256 { get; set; }
    public string? AssetId { get; set; }
    public Dictionary<string, double> Features { get; set; } = [];
    public bool ObserveBaseline { get; set; }
    public bool Suppressed { get; set; }
    public DateTimeOffset? CooldownUntilUtc { get; set; }
}
