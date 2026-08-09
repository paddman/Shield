namespace NTShield.Shared.Models;

public sealed class DashboardSummaryV2
{
    public int SchemaVersion { get; set; } = 2;
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public string Window { get; set; } = "24h";
    public DashboardPostureSummary Posture { get; set; } = new();
    public DashboardCountSummary Counts { get; set; } = new();
    public DashboardTelemetrySummary Telemetry { get; set; } = new();
    public DashboardExecutiveSummary Executive { get; set; } = new();
    public List<DashboardTrendBucket> Trends { get; set; } = [];
    public List<DashboardThreatQueueItem> ThreatQueue { get; set; } = [];
}

/// <summary>
/// Executive measurements remain nullable until Central has the lifecycle
/// timestamps needed to calculate them. Null is preferable to presenting an
/// incident duration or ingest delay as an invented MTTD/MTTR/SLA value.
/// </summary>
public sealed class DashboardExecutiveSummary
{
    public double? CoveragePercent { get; set; }
    public double? MeanTimeToDetectSeconds { get; set; }
    public double? MeanTimeToRespondSeconds { get; set; }
    public int? SlaTracked { get; set; }
    public int? SlaBreached { get; set; }
    public string MeasurementState { get; set; } = "partial";
    public List<string> MeasurementGaps { get; set; } = [];
}

public sealed class DashboardPostureSummary
{
    public string State { get; set; } = "stable";
    public string Reason { get; set; } = "No urgent measured condition";
}

public sealed class DashboardCountSummary
{
    public long IncidentsTotal { get; set; }
    public int OpenIncidents { get; set; }
    public int CriticalOpen { get; set; }
    public int HighOpen { get; set; }
    public int ActiveCampaigns { get; set; }
    public int AffectedAssets { get; set; }
    public int AgentsTotal { get; set; }
    public int AgentsOnline { get; set; }
    public int AgentsOffline { get; set; }
    public int ManagedAssets { get; set; }
    public long ThreatEventsInWindow { get; set; }
}

public sealed class DashboardTelemetrySummary
{
    public DateTimeOffset? LatestEventAtUtc { get; set; }
    public DateTimeOffset? LatestConnectionAtUtc { get; set; }
    public DateTimeOffset? LatestHeartbeatAtUtc { get; set; }
    public long? EventFreshnessSeconds { get; set; }
    public long? ConnectionFreshnessSeconds { get; set; }
    public long? HeartbeatFreshnessSeconds { get; set; }
    /// <summary>
    /// Worst freshness across the required event and connection feeds. Null means
    /// at least one required feed has never been observed; consult VisibilityGaps.
    /// </summary>
    public long? FreshnessSeconds { get; set; }
    public string State { get; set; } = "unknown";
    public List<string> VisibilityGaps { get; set; } = [];
}

public sealed class DashboardTrendBucket
{
    public DateTimeOffset BucketStartUtc { get; set; }
    public int Incidents { get; set; }
    public int Campaigns { get; set; }
}

public sealed class DashboardThreatQueueItem
{
    public string Kind { get; set; } = "incident";
    public string Id { get; set; } = string.Empty;
    public string? CampaignId { get; set; }
    public string? IncidentId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Severity { get; set; } = "Informational";
    public double? Confidence { get; set; }
    public long RecurrenceCount { get; set; }
    public DateTimeOffset FirstObservedAtUtc { get; set; }
    public DateTimeOffset LastObservedAtUtc { get; set; }
    public int AffectedAssetCount { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string Status { get; set; } = "Open";
}
