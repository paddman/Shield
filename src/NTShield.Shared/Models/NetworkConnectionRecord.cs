using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

public sealed class NetworkConnectionRecord
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public TcpConnectionState? TcpState { get; set; }
    public int ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? ProcessCommandLine { get; set; }
    public string? ProcessOwner { get; set; }
    public int? ParentProcessId { get; set; }
    public string? DigitalSignatureStatus { get; set; }
    public string? SignerName { get; set; }
    public string? ExecutableSha256 { get; set; }
    public string? ServiceNames { get; set; }
    public string? ServiceDisplayNames { get; set; }
    public bool IsNew { get; set; }
    public bool IsClosed { get; set; }
    public string ConnectionKey { get; set; } = string.Empty;
}
