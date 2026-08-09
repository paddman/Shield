using System.Text.Json.Serialization;
using NTShield.Shared.Security;

namespace NTShield.Shared.Models;

public sealed class ResponseActionRecord
{
    public long Id { get; set; }
    public string ActionId { get; set; } = Guid.NewGuid().ToString("N");
    public string RequestId { get; set; } = Guid.NewGuid().ToString("N");
    public string Requester { get; set; } = "local";
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ComputerName { get; set; } = string.Empty;
    public string AgentId { get; set; } = string.Empty;
    public string AlertId { get; set; } = string.Empty;
    public string IncidentId { get; set; } = string.Empty;
    public string ActionType { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";
    public string Reason { get; set; } = string.Empty;
    public string? BeforeState { get; set; }
    public string? Result { get; set; }
    public string? RollbackCommand { get; set; }
    public string? Details { get; set; }
    public string? Error { get; set; }
    public string? TargetPath { get; set; }
    public string? QuarantineId { get; set; }
    public bool RequiresApproval { get; set; }
    public bool Approved { get; set; }
    public string? ApprovalId { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAtUtc { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
    public string? ApprovalKeyId { get; set; }
    public string? PayloadSha256 { get; set; }
    public string AuditLog { get; set; } = string.Empty;
}

public sealed class ResponseActionRequest
{
    private bool _approvalRequested;

    public string RequestId { get; set; } = Guid.NewGuid().ToString("N");
    public string Requester { get; set; } = string.Empty;

    /// <summary>Which single agent may execute this action.</summary>
    public string? TargetAgentId { get; set; }

    public string ActionType { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string? TargetIp { get; set; }
    public int? TargetPort { get; set; }

    /// <summary>in | out — firewall direction (default depends on action type).</summary>
    public string? Direction { get; set; }

    /// <summary>tcp | udp | any</summary>
    public string? Protocol { get; set; }

    /// <summary>Optional NTS-* rule name for remove/open/close operations.</summary>
    public string? RuleName { get; set; }

    public int? ProcessId { get; set; }
    public string? ServiceName { get; set; }
    public string? TaskPath { get; set; }
    public string? TaskName { get; set; }
    public string? TargetPath { get; set; }
    public string? FileSha256 { get; set; }
    public string? QuarantineId { get; set; }
    public string? IncidentId { get; set; }
    public string? AlertId { get; set; }

    /// <summary>
    /// Central-side reads perform pure signature validation. Once an agent pins
    /// its AgentId and replay ledger, the first successful read atomically
    /// reserves the nonce; a new request carrying the same nonce is rejected.
    /// Assigning true by itself never creates approval.
    /// </summary>
    public bool Approved
    {
        get => _approvalRequested && ActionApprovalCrypto.ValidateAndReserve(this);
        set => _approvalRequested = value;
    }

    /// <summary>Raw JSON approval intent. Not serialized separately.</summary>
    [JsonIgnore]
    public bool ApprovalRequested => _approvalRequested;

    public string? ApprovalId { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAtUtc { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
    public string? Nonce { get; set; }
    public string? ApprovalKeyId { get; set; }
    public string? PayloadSha256 { get; set; }
    public string? ApprovalSignature { get; set; }

    /// <summary>
    /// Requested action validity window. Central clamps destructive actions to a
    /// short policy maximum before signing.
    /// </summary>
    public int DurationMinutes { get; set; } = 5;
}
