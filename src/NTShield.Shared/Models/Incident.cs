using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

/// <summary>
/// Cross-host correlated incident for analyst display.
/// </summary>
public sealed class Incident
{
    public string IncidentId { get; set; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public Severity Severity { get; set; }

    public string? SourceIp { get; set; }
    public string? SourceHost { get; set; }
    public string? SourceAgentId { get; set; }
    public int? SourcePort { get; set; }

    public string? DestinationIp { get; set; }
    public string? DestinationHost { get; set; }
    public string? DestinationAgentId { get; set; }
    public int? DestinationPort { get; set; }

    public string? ProcessName { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessPath { get; set; }
    public string? ProcessCommandLine { get; set; }
    public string? ExecutableSha256 { get; set; }

    /// <summary>All services sharing the PID (never only "svchost.exe").</summary>
    public List<string> Services { get; set; } = [];
    public string? ServiceAccount { get; set; }

    public string? Username { get; set; }
    public string? Domain { get; set; }
    public string? LogonProcess { get; set; }
    public int? LogonType { get; set; }
    public string? AuthenticationPackage { get; set; }

    public int FailedAttempts { get; set; }
    public int DistinctUsernames { get; set; }
    public bool SuccessfulLoginDetected { get; set; }
    public bool PrivilegedLogon { get; set; }

    public DateTimeOffset? FirstSeen { get; set; }
    public DateTimeOffset? LastSeen { get; set; }

    public string Description { get; set; } = string.Empty;
    public string CorrelationKey { get; set; } = string.Empty;
    public string EvidenceJson { get; set; } = "[]";
    public List<EvidenceEventSummary> EvidenceEvents { get; set; } = [];
    public string Status { get; set; } = "Open";

    // Back-compat aliases used by older correlator fields
    public DateTimeOffset FirstSeenUtc
    {
        get => FirstSeen ?? DateTimeOffset.MinValue;
        set => FirstSeen = value;
    }

    public DateTimeOffset LastSeenUtc
    {
        get => LastSeen ?? DateTimeOffset.MinValue;
        set => LastSeen = value;
    }

    public string? SourceProcessName
    {
        get => ProcessName;
        set => ProcessName = value;
    }

    public string? SourceProcessPath
    {
        get => ProcessPath;
        set => ProcessPath = value;
    }

    public int? SourceProcessId
    {
        get => ProcessId;
        set => ProcessId = value;
    }

    public string? SourceServiceNames
    {
        get => Services.Count == 0 ? null : string.Join(", ", Services);
        set
        {
            Services = string.IsNullOrWhiteSpace(value)
                ? []
                : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        }
    }

    public string? SourceCommandLine
    {
        get => ProcessCommandLine;
        set => ProcessCommandLine = value;
    }

    public int FailedLogonCount
    {
        get => FailedAttempts;
        set => FailedAttempts = value;
    }

    public int SuccessfulLogonCount
    {
        get => SuccessfulLoginDetected ? Math.Max(1, _successCount) : 0;
        set
        {
            _successCount = value;
            SuccessfulLoginDetected = value > 0;
        }
    }

    private int _successCount;

    public string FormatDisplay()
    {
        var services = Services.Count == 0
            ? "  (none)"
            : string.Join(Environment.NewLine, Services.Select(s => $"  - {s}"));

        var evidence = EvidenceEvents.Count == 0
            ? "  (none)"
            : string.Join(Environment.NewLine, EvidenceEvents.Select(e =>
                $"  - [{e.TimestampUtc:O}] EventId={e.EventId} User={e.Username} SourceIp={e.SourceIp} Status={e.Status}"));

        return
            $"""
            Incident: {Title}
            Source: {SourceIp}
            Destination: {DestinationIp ?? DestinationHost}
            Destination port: {DestinationPort}
            Process: {ProcessName}
            PID: {ProcessId}
            Services:
            {services}
            Service account: {ServiceAccount}
            Logon process: {LogonProcess}
            Logon type: {LogonType}
            Failed attempts: {FailedAttempts}
            Distinct usernames: {DistinctUsernames}
            Successful login detected: {SuccessfulLoginDetected.ToString().ToLowerInvariant()}
            First seen: {FirstSeen:O}
            Last seen: {LastSeen:O}
            Evidence events:
            {evidence}
            """;
    }
}

public sealed class EvidenceEventSummary
{
    public int EventId { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string? Username { get; set; }
    public string? SourceIp { get; set; }
    public string? Status { get; set; }
    public long EventRecordId { get; set; }
}
