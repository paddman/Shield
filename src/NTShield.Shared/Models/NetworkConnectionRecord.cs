using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

public sealed class NetworkConnectionRecord
{
    /// <summary>Immutable Central tenant provenance stamped during ingest.</summary>
    public string TenantId { get; set; } = "default";
    public long Id { get; set; }
    /// <summary>Time this collector observation was made.</summary>
    public DateTimeOffset TimestampUtc { get; set; }
    /// <summary>First time the current endpoint-local connection lifecycle was observed.</summary>
    public DateTimeOffset? StartedAtUtc { get; set; }
    /// <summary>Collector-observed lifecycle end. Null while the connection remains visible.</summary>
    public DateTimeOffset? EndedAtUtc { get; set; }
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
    /// <summary>
    /// Stable only for one observed open-to-close lifecycle. Unlike ConnectionKey,
    /// a later reconnect receives a new value even if the five-tuple is reused.
    /// </summary>
    public string LifecycleId { get; set; } = string.Empty;
    /// <summary>Stable endpoint/process tuple; TCP state is intentionally excluded.</summary>
    public string ConnectionKey { get; set; } = string.Empty;
}
