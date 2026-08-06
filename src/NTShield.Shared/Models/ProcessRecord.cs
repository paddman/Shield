namespace NTShield.Shared.Models;

public sealed class ProcessRecord
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public int? ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string? FullPath { get; set; }
    public string? CommandLine { get; set; }
    public string? User { get; set; }
    public DateTimeOffset? StartTimeUtc { get; set; }
    public string? ExecutableSha256 { get; set; }
    public string? SignerName { get; set; }
    public string? DigitalSignatureStatus { get; set; }
    public string? IntegrityLevel { get; set; }
    public string? ListeningPorts { get; set; }
    public string? OutboundDestinations { get; set; }
    public string? ServiceNames { get; set; }
}
