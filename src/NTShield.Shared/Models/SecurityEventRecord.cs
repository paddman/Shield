namespace NTShield.Shared.Models;

public sealed class SecurityEventRecord
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public DateTimeOffset TimestampUtc { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public int EventId { get; set; }
    public string Channel { get; set; } = string.Empty;
    public string? ProviderName { get; set; }
    public string? Username { get; set; }
    public string? Domain { get; set; }
    public string? SourceIp { get; set; }
    public int? SourcePort { get; set; }
    public string? DestinationIp { get; set; }
    public int? DestinationPort { get; set; }
    public int? LogonType { get; set; }
    public string? AuthenticationPackage { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessPath { get; set; }
    public string? LogonProcess { get; set; }
    public string? Status { get; set; }
    public string? SubStatus { get; set; }
    public string? TargetUserName { get; set; }
    public string? TargetDomainName { get; set; }
    public string? WorkstationName { get; set; }
    public string? ServiceName { get; set; }
    public string? TaskName { get; set; }
    public string RawXml { get; set; } = string.Empty;
    public long EventRecordId { get; set; }
    public DateTimeOffset CollectedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
