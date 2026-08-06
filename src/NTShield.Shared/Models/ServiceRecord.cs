namespace NTShield.Shared.Models;

public sealed class ServiceRecord
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? StartAccount { get; set; }
    public string? ImagePath { get; set; }
    public string? State { get; set; }
    public string? StartMode { get; set; }
}
