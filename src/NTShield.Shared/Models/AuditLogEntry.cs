namespace NTShield.Shared.Models;

public sealed class AuditLogEntry
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Actor { get; set; } = "anonymous";
    public string Action { get; set; } = string.Empty;
    public string? Target { get; set; }
    public string Result { get; set; } = "success";
    public string? DetailJson { get; set; }
    public string? SourceIp { get; set; }
}
