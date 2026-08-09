using System.Text.Json.Serialization;

namespace NTShield.Shared.Models;

/// <summary>
/// Bounded, database-backed Phase 2 projection of a threat campaign. Unlike the
/// legacy campaign model this type never embeds the complete hop/evidence lists.
/// </summary>
public sealed class ThreatCampaignV2Summary
{
    public string TenantId { get; set; } = "default";
    public string CampaignId { get; set; } = string.Empty;
    public long Revision { get; set; }
    public string Status { get; set; } = "Open";
    public string Severity { get; set; } = "Informational";
    public double? Confidence { get; set; }
    public DateTimeOffset FirstObservedAtUtc { get; set; }
    public DateTimeOffset LastObservedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    [JsonIgnore]
    public DateTimeOffset SnapshotAtUtc { get; set; }
    public long ObservationCount { get; set; }
    public long EpisodeCount { get; set; }
    public long EdgeCount { get; set; }
    public long ContactCount { get; set; }
    public long RecurrenceCount { get; set; }
    public List<string> InvolvedHosts { get; set; } = [];
    public List<string> InvolvedIps { get; set; } = [];
    public long AffectedAssetCount { get; set; }
    public long RelatedIncidentCount { get; set; }
    /// <summary>Bounded samples only; RelatedIncidentCount remains the true total.</summary>
    public List<string> RelatedIncidentIds { get; set; } = [];
    public string? MergedIntoCampaignId { get; set; }
    public DateTimeOffset? TombstonedAtUtc { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
}

public sealed class ThreatCampaignV2Page
{
    public int SchemaVersion { get; set; } = 2;
    public List<ThreatCampaignV2Summary> Items { get; set; } = [];
    public string? NextCursor { get; set; }
    public DateTimeOffset WatermarkUtc { get; set; }
}

/// <summary>
/// Immutable event-time observation used as the source of truth for temporal
/// attack-chain projections. Collected/ingested times remain separate so late
/// data and host clock skew do not silently rewrite observed time.
/// </summary>
public sealed class ThreatObservation
{
    public int SchemaVersion { get; set; } = 2;
    public string TenantId { get; set; } = "default";
    public string CampaignId { get; set; } = string.Empty;
    public string ObservationId { get; set; } = string.Empty;
    public string? EpisodeId { get; set; }
    public string Kind { get; set; } = "event";
    public string Relation { get; set; } = "observed";
    public DateTimeOffset? RawObservedAtUtc { get; set; }
    public DateTimeOffset ObservedAtUtc { get; set; }
    public DateTimeOffset? CollectedAtUtc { get; set; }
    public DateTimeOffset IngestedAtUtc { get; set; }
    public DateTimeOffset? StartedAtUtc { get; set; }
    public DateTimeOffset? EndedAtUtc { get; set; }
    public int OccurrenceCount { get; set; } = 1;

    public string SourceNodeId { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? SourceHost { get; set; }
    public string? SourceAgentId { get; set; }
    public string DestinationNodeId { get; set; } = string.Empty;
    public string? DestinationIp { get; set; }
    public string? DestinationHost { get; set; }
    public string? DestinationAgentId { get; set; }

    public string? Protocol { get; set; }
    public int? LocalPort { get; set; }
    public int? RemotePort { get; set; }
    public string? Username { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ServiceNames { get; set; }
    public string? Technique { get; set; }
    public string? IncidentId { get; set; }
    public string EvidenceType { get; set; } = string.Empty;
    public string EvidenceId { get; set; } = string.Empty;
    public bool Inferred { get; set; }
    public double Confidence { get; set; } = 1;
    public string TimestampQuality { get; set; } = "source_event";
    public double? ClockSkewSeconds { get; set; }

    /// <summary>Deterministic key shared by repeated observations of one logical edge.</summary>
    public string ContactId { get; set; } = string.Empty;
}

/// <summary>
/// Versioned campaign assignment kept separate from the immutable observation.
/// This permits later recomputation, campaign merges and shared evidence without
/// rewriting source telemetry.
/// </summary>
public sealed class ThreatObservationMembership
{
    public string TenantId { get; set; } = "default";
    public string CampaignId { get; set; } = string.Empty;
    public string ObservationId { get; set; } = string.Empty;
    public DateTimeOffset AssignedAtUtc { get; set; }
    public double Confidence { get; set; } = 1;
    public string Provenance { get; set; } = "temporal_correlator_v2";
    public bool Active { get; set; } = true;
}

/// <summary>Durable retry item for the temporal projection worker.</summary>
public sealed class TemporalCorrelationWorkItem
{
    public string WorkId { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
    public string PayloadJson { get; set; } = string.Empty;
    public DateTimeOffset EnqueuedAtUtc { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset? LeaseUntilUtc { get; set; }
    public string? LeaseOwner { get; set; }
    public string? LastError { get; set; }
}

/// <summary>Materialized repeated-contact aggregate; raw observations are retained.</summary>
public sealed class ThreatContactAggregate
{
    public string TenantId { get; set; } = "default";
    public string CampaignId { get; set; } = string.Empty;
    [JsonPropertyName("contactKey")]
    public string ContactId { get; set; } = string.Empty;
    public string SourceNodeId { get; set; } = string.Empty;
    public string DestinationNodeId { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? SourceHost { get; set; }
    public string? SourceAgentId { get; set; }
    public string? DestinationIp { get; set; }
    public string? DestinationHost { get; set; }
    public string? DestinationAgentId { get; set; }
    public string Relation { get; set; } = "observed";
    public string? Technique { get; set; }
    public string? Protocol { get; set; }
    public int? LocalPort { get; set; }
    [JsonPropertyName("destinationPort")]
    public int? RemotePort { get; set; }
    public DateTimeOffset FirstObservedAtUtc { get; set; }
    public DateTimeOffset LastObservedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public long ObservationCount { get; set; }
    public long ObservationRecordCount { get; set; }
    public long RecurrenceCount { get; set; }
    public long AuthenticationFailureCount { get; set; }
    public long AuthenticationSuccessCount { get; set; }
    public long OpenCount { get; set; }
    public long CloseCount { get; set; }
    /// <summary>Subsequent observed network opens after the first lifecycle.</summary>
    public long ReconnectCount => Math.Max(0, OpenCount - 1);
    /// <summary>Exact span between the first and last event-time observation.</summary>
    public double DurationSeconds => Math.Max(0, (LastObservedAtUtc - FirstObservedAtUtc).TotalSeconds);
    public bool Inferred { get; set; }
    public double Confidence { get; set; } = 1;
    public string LastObservationId { get; set; } = string.Empty;
    public double? MedianGapSeconds { get; set; }
    public double? P95GapSeconds { get; set; }
    public double BeaconScore { get; set; }
    /// <summary>Membership provenance for this contact in the requested campaign/window.</summary>
    public string Provenance { get; set; } = "temporal_correlator_v2";
    /// <summary>Describes whether gap/beacon metrics are exact or a bounded projection.</summary>
    public string MetricQuality { get; set; } = "exact_last_64_chronological_gaps";
    public List<string> EvidenceRefs { get; set; } = [];
}

public sealed class ThreatGraphNode
{
    public string NodeId { get; set; } = string.Empty;
    [JsonPropertyName("type")]
    public string Kind { get; set; } = "endpoint";
    public string Label { get; set; } = string.Empty;
    public string? Ip { get; set; }
    public string? Host { get; set; }
    public string? AgentId { get; set; }
    public long ObservationCount { get; set; }
    public DateTimeOffset FirstObservedAtUtc { get; set; }
    public DateTimeOffset LastObservedAtUtc { get; set; }
}

public sealed class ThreatGraphEdge
{
    public string EdgeId { get; set; } = string.Empty;
    [JsonPropertyName("fromNodeId")]
    public string SourceNodeId { get; set; } = string.Empty;
    [JsonPropertyName("toNodeId")]
    public string DestinationNodeId { get; set; } = string.Empty;
    [JsonPropertyName("type")]
    public string Relation { get; set; } = "observed";
    public string? Technique { get; set; }
    public string? Protocol { get; set; }
    public int? Port { get; set; }
    public DateTimeOffset FirstObservedAtUtc { get; set; }
    public DateTimeOffset LastObservedAtUtc { get; set; }
    public long ObservationCount { get; set; }
    public long RecurrenceCount { get; set; }
    /// <summary>Exact span between the first and last observations represented by this edge.</summary>
    public double DurationSeconds { get; set; }
    public double? MedianGapSeconds { get; set; }
    public double? P95GapSeconds { get; set; }
    public double BeaconScore { get; set; }
    public string MetricQuality { get; set; } = "exact_last_64_chronological_gaps";
    public string Provenance { get; set; } = "temporal_correlator_v2";
    public List<string> EvidenceRefs { get; set; } = [];
    /// <summary>Empty unless an explicit causal relation is persisted; temporal order alone is not causality.</summary>
    public List<string> PredecessorEdgeIds { get; set; } = [];
    public bool Inferred { get; set; }
    public double Confidence { get; set; }
}

public sealed class ThreatGraphV2Response
{
    public int SchemaVersion { get; set; } = 2;
    public string CampaignId { get; set; } = string.Empty;
    public long Revision { get; set; }
    public List<ThreatGraphNode> Nodes { get; set; } = [];
    public List<ThreatGraphEdge> Edges { get; set; } = [];
    public long TotalNodes { get; set; }
    public long TotalEdges { get; set; }
    public bool Truncated { get; set; }
}

public sealed class ThreatTimelineBucket
{
    [JsonPropertyName("bucketStartUtc")]
    public DateTimeOffset StartUtc { get; set; }
    [JsonPropertyName("bucketEndUtc")]
    public DateTimeOffset EndUtc { get; set; }
    public long Count { get; set; }
    public Dictionary<string, long> Kinds { get; set; } = [];
}

public sealed class ThreatTimelineV2Response
{
    public List<ThreatObservation> Items { get; set; } = [];
    public List<ThreatTimelineBucket> Buckets { get; set; } = [];
    public string? NextCursor { get; set; }
    public long Total { get; set; }
    public bool Truncated { get; set; }
}

public sealed class ThreatContactsV2Response
{
    public List<ThreatContactAggregate> Items { get; set; } = [];
    public string? NextCursor { get; set; }
    public long Total { get; set; }
}
