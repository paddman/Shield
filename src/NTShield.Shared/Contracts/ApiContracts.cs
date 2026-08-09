using NTShield.Shared.Models;

namespace NTShield.Shared.Contracts;

public sealed class AgentRegistrationRequest
{
    public string AgentId { get; set; } = string.Empty;
    /// <summary>Customer workspace assigned during enrollment. Existing agents default to "default".</summary>
    public string? TenantId { get; set; }
    public string ComputerName { get; set; } = string.Empty;
    public string AgentVersion { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string? CertificateThumbprint { get; set; }
    public string? HostIp { get; set; }
    /// <summary>Shared enrollment token from Central secrets (required when RequireAuth or token configured).</summary>
    public string? EnrollmentToken { get; set; }
    /// <summary>When true, issue a new agent API key even if one exists.</summary>
    public bool RotateApiKey { get; set; }
    public string? BinarySha256 { get; set; }
    public bool? IsBinarySigned { get; set; }
    public string Platform { get; set; } = "windows";
}

public sealed class AgentRegistrationResponse
{
    public bool Accepted { get; set; }
    public string? Message { get; set; }
    public DateTimeOffset ServerUtc { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Agent runtime API key — returned once; store as Server:ApiKey.</summary>
    public string? AgentApiKey { get; set; }
    public AgentPolicy? Policy { get; set; }
}

public sealed class AgentHeartbeat
{
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string AgentVersion { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public long LocalQueueDepth { get; set; }
    public long DatabaseSizeBytes { get; set; }
    public string Status { get; set; } = "Healthy";
    public long WorkingSetBytes { get; set; }
    public double? CpuPercentEstimate { get; set; }
    public double ClockSkewSeconds { get; set; }

    /// <summary>Primary host IPv4/IPv6 for inventory (fleet UI).</summary>
    public string? HostIp { get; set; }

    /// <summary>Central URL this agent is configured to use (helps debug wrong-server config).</summary>
    public string? CentralUrl { get; set; }

    /// <summary>windows | linux | unknown</summary>
    public string Platform { get; set; } = "windows";

    /// <summary>Last outbound error (ingest/heartbeat), if any.</summary>
    public string? LastError { get; set; }

    /// <summary>SHA-256 of agent binary (integrity report).</summary>
    public string? BinarySha256 { get; set; }

    /// <summary>Whether the agent binary appears digitally signed.</summary>
    public bool? IsBinarySigned { get; set; }

    /// <summary>Policy version currently applied on the agent.</summary>
    public int? AppliedPolicyVersion { get; set; }

    // Host metrics (Linux full; Windows best-effort)
    public double? MemUsedPercent { get; set; }
    public double? DiskUsedPercent { get; set; }
    public double? NetworkRxBytesPerSec { get; set; }
    public double? NetworkTxBytesPerSec { get; set; }
    public double? DiskReadBytesPerSec { get; set; }
    public double? DiskWriteBytesPerSec { get; set; }
    public double? LoadAverage1 { get; set; }
    public long? HostMemUsedBytes { get; set; }
    public long? HostMemTotalBytes { get; set; }
    /// <summary>One-line metrics summary for Status-like display.</summary>
    public string? MetricsSummary { get; set; }
    public string? ProtectionStatus { get; set; }
    public int? ProtectionRulePackVersion { get; set; }
    public bool? DefenderAvailable { get; set; }
    public bool? YaraAvailable { get; set; }
    public DateTimeOffset? LastProtectionScanUtc { get; set; }
}

/// <summary>Fleet inventory row returned by GET /api/v1/agents</summary>
public sealed class AgentInventoryItem
{
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string? AgentVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? HostIp { get; set; }
    public string? CentralUrl { get; set; }
    public string Platform { get; set; } = "windows";
    public DateTimeOffset LastSeenUtc { get; set; }
    public string? Status { get; set; }
    public long QueueDepth { get; set; }
    public long DatabaseSizeBytes { get; set; }
    public long WorkingSetBytes { get; set; }
    public double? CpuPercent { get; set; }
    public double ClockSkewSeconds { get; set; }
    public string? LastError { get; set; }
    public bool Online { get; set; }
    public int OfflineSeconds { get; set; }
    public string? BinarySha256 { get; set; }
    public bool? IsBinarySigned { get; set; }
    public int? PolicyVersion { get; set; }
    public double? MemUsedPercent { get; set; }
    public double? DiskUsedPercent { get; set; }
    public double? NetworkRxBytesPerSec { get; set; }
    public double? NetworkTxBytesPerSec { get; set; }
    public double? DiskReadBytesPerSec { get; set; }
    public double? DiskWriteBytesPerSec { get; set; }
    public double? LoadAverage1 { get; set; }
    public long? HostMemUsedBytes { get; set; }
    public long? HostMemTotalBytes { get; set; }
    public string? MetricsSummary { get; set; }
    /// <summary>Recent metrics samples (newest first) when requested via detail API.</summary>
    public List<AgentMetricsSample> MetricsHistory { get; set; } = [];
}

/// <summary>One metrics sample stored from agent heartbeat.</summary>
public sealed class AgentMetricsSample
{
    public DateTimeOffset TimestampUtc { get; set; }
    public double? CpuPercent { get; set; }
    public double? MemUsedPercent { get; set; }
    public double? DiskUsedPercent { get; set; }
    public double? NetworkRxBytesPerSec { get; set; }
    public double? NetworkTxBytesPerSec { get; set; }
    public double? DiskReadBytesPerSec { get; set; }
    public double? DiskWriteBytesPerSec { get; set; }
    public double? LoadAverage1 { get; set; }
    public long QueueDepth { get; set; }
    public long WorkingSetBytes { get; set; }
    public string? Status { get; set; }
}

public sealed class HeartbeatResponse
{
    public bool Accepted { get; set; }
    public DateTimeOffset ServerUtc { get; set; } = DateTimeOffset.UtcNow;
    public double ClockSkewSeconds { get; set; }
    public List<ResponseActionRequest> PendingActions { get; set; } = [];
    /// <summary>Present when agent should apply a newer Central policy.</summary>
    public AgentPolicy? Policy { get; set; }
    public string? PolicyMessage { get; set; }
}

public sealed class AgentIngestBatch
{
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string AgentVersion { get; set; } = string.Empty;
    public DateTimeOffset SentAtUtc { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>
    /// Last Central-measured `(agentUtc - serverUtc)` offset. This is distinct
    /// from queue/network delay and may be used to correct event display time.
    /// </summary>
    public double? ClockSkewSeconds { get; set; }
    /// <summary>Central server time at which ClockSkewSeconds was measured.</summary>
    public DateTimeOffset? ClockSkewMeasuredAtUtc { get; set; }
    public string? IdempotencyKey { get; set; }
    public List<SecurityEventRecord> SecurityEvents { get; set; } = [];
    public List<NetworkConnectionRecord> NetworkConnections { get; set; } = [];
    public List<ProcessRecord> Processes { get; set; } = [];
    public List<ServiceRecord> Services { get; set; } = [];
    public List<ScheduledTaskRecord> ScheduledTasks { get; set; } = [];
    public List<DetectionAlert> Alerts { get; set; } = [];
}

public sealed class IngestResponse
{
    public bool Accepted { get; set; }
    public string? Message { get; set; }
    public int ReceivedCount { get; set; }
    public List<string> CreatedIncidentIds { get; set; } = [];
    public bool Duplicate { get; set; }
    public string? AnomalyState { get; set; }
    public double? AnomalyScore { get; set; }
    public double? AnomalyConfidence { get; set; }
    public int? AnomalyBaselineSamples { get; set; }
    public string? AnomalyModel { get; set; }
}

public sealed class EventsBatchRequest
{
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string? IdempotencyKey { get; set; }
    public List<SecurityEventRecord> Events { get; set; } = [];
}

public sealed class ConnectionsBatchRequest
{
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string? IdempotencyKey { get; set; }
    public List<NetworkConnectionRecord> Connections { get; set; } = [];
}
