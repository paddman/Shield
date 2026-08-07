using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

/// <summary>Customer workspace managed by NT Shield Central.</summary>
public sealed class CustomerTenant
{
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = "Default customer";
    public string? LegalName { get; set; }
    public string? ContactName { get; set; }
    public string? ContactEmail { get; set; }
    public string Plan { get; set; } = "standard";
    public string Status { get; set; } = "active";
    public string? Notes { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class TenantAgentAssignment
{
    public string TenantId { get; set; } = "default";
    public string AgentId { get; set; } = string.Empty;
    public DateTimeOffset AssignedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class CreateSecurityReportRequest
{
    public string? Title { get; set; }
    public DateTimeOffset? PeriodStartUtc { get; set; }
    public DateTimeOffset? PeriodEndUtc { get; set; }
}

public sealed class SecurityReportRecord
{
    public string ReportId { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = "default";
    public string CustomerName { get; set; } = string.Empty;
    public string Title { get; set; } = "Security operations report";
    public DateTimeOffset PeriodStartUtc { get; set; }
    public DateTimeOffset PeriodEndUtc { get; set; }
    public DateTimeOffset GeneratedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public SecurityReportMetrics Metrics { get; set; } = new();
    public Dictionary<string, int> SeverityCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<SecurityReportCountItem> TopSourceIps { get; set; } = [];
    public List<SecurityReportCountItem> TopEventIds { get; set; } = [];
    public List<SecurityReportIncident> PriorityIncidents { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public string CoverageNote { get; set; } = string.Empty;
}

public sealed class SecurityReportMetrics
{
    public int Agents { get; set; }
    public int OnlineAgents { get; set; }
    public int Assets { get; set; }
    public int ThreatEvents { get; set; }
    public int Incidents { get; set; }
    public int OpenIncidents { get; set; }
    public int ThreatCampaigns { get; set; }
    public int DefenseScore { get; set; }
}

/// <summary>Exact tenant totals used by report summaries; detail rows may still be sampled.</summary>
public sealed class TenantReportAggregate
{
    public int ThreatEvents { get; set; }
    public int Incidents { get; set; }
    public int OpenIncidents { get; set; }
    public int CriticalIncidents { get; set; }
    public int HighIncidents { get; set; }
    public int MediumIncidents { get; set; }
    public int LowIncidents { get; set; }
}

public sealed class SecurityReportCountItem
{
    public string Value { get; set; } = string.Empty;
    public int Count { get; set; }
}

public sealed class SecurityReportIncident
{
    public string IncidentId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? DestinationIp { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
}
