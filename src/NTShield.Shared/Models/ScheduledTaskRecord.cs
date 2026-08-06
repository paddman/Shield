namespace NTShield.Shared.Models;

public sealed class ScheduledTaskRecord
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public string TaskPath { get; set; } = string.Empty;
    public string TaskName { get; set; } = string.Empty;
    public string? Command { get; set; }
    public string? Arguments { get; set; }
    public string? RunAsAccount { get; set; }
    public string? Triggers { get; set; }
    public bool Enabled { get; set; }
    public string? LastRunResult { get; set; }
    public DateTimeOffset? LastRunTimeUtc { get; set; }
    public string? ChangeType { get; set; }
}
