using NTShield.Shared.Enums;

namespace NTShield.Shared.Models;

/// <summary>
/// Multi-host attack path (lateral movement chain).
/// Tracks threat progression: Host A → Host B → Host C with process/service attribution.
/// Detection / investigation only — never used to attack.
/// </summary>
public sealed class ThreatCampaign
{
    public string CampaignId { get; set; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public string Status { get; set; } = "Open";
    public List<string> ThreatCategories { get; set; } = [];
    public List<string> InvolvedHosts { get; set; } = [];
    public List<string> InvolvedIps { get; set; } = [];
    public List<string> InvolvedUsernames { get; set; } = [];
    public List<ThreatHop> Hops { get; set; } = [];
    public List<string> RelatedIncidentIds { get; set; } = [];
    public string Summary { get; set; } = string.Empty;

    public string FormatDisplay()
    {
        var hops = Hops.Count == 0
            ? "  (none)"
            : string.Join(Environment.NewLine, Hops.Select((h, i) =>
                $"  {i + 1}. {h.FromHost ?? h.FromIp} --[{h.Technique}/{h.Port}]--> {h.ToHost ?? h.ToIp}" +
                (h.ProcessId is null ? "" : $"  PID={h.ProcessId} {h.ProcessName} svc={h.ServiceNames}")));

        return
            $"""
            Threat Campaign: {Title}
            Campaign ID: {CampaignId}
            Severity: {Severity}
            Categories: {string.Join(", ", ThreatCategories)}
            First seen: {FirstSeenUtc:O}
            Last seen: {LastSeenUtc:O}
            Hosts: {string.Join(" → ", InvolvedHosts.DefaultIfEmpty("(unknown)"))}
            IPs: {string.Join(", ", InvolvedIps)}
            Users: {string.Join(", ", InvolvedUsernames)}
            Related incidents: {string.Join(", ", RelatedIncidentIds)}
            Lateral path (hops):
            {hops}
            Summary: {Summary}
            """;
    }
}

public sealed class ThreatHop
{
    public DateTimeOffset TimestampUtc { get; set; }
    public string? FromIp { get; set; }
    public string? FromHost { get; set; }
    public string? FromAgentId { get; set; }
    public string? ToIp { get; set; }
    public string? ToHost { get; set; }
    public string? ToAgentId { get; set; }
    public int? Port { get; set; }
    public string Technique { get; set; } = string.Empty;
    public string? Username { get; set; }
    public int? LogonType { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? ServiceNames { get; set; }
    public string? IncidentId { get; set; }
    public string Evidence { get; set; } = string.Empty;
}

/// <summary>Catalog entry describing a detectable threat class.</summary>
public sealed class ThreatCatalogEntry
{
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string MitreTactic { get; set; } = string.Empty;
    public string MitreTechnique { get; set; } = string.Empty;
    public string DetectionRuleId { get; set; } = string.Empty;
    public string CrossHostTracking { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
}
