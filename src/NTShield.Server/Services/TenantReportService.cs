using System.Net;
using System.Text;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class TenantReportService
{
    private const int ReportRowLimit = 10_000;
    private readonly ICentralStore _store;
    private readonly LateralMovementTracker _tracker;

    public TenantReportService(ICentralStore store, LateralMovementTracker tracker)
    {
        _store = store;
        _tracker = tracker;
    }

    public Task<IReadOnlyList<SecurityReportRecord>> ListAsync(string tenantId, int take) =>
        _store.ListReportsAsync(TopologyService.NormalizeTenantId(tenantId), Math.Clamp(take, 1, 100));

    public Task<SecurityReportRecord?> GetAsync(string tenantId, string reportId) =>
        _store.GetReportAsync(TopologyService.NormalizeTenantId(tenantId), reportId);

    public async Task<SecurityReportRecord> GenerateAsync(string tenantId, CreateSecurityReportRequest request)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var tenant = await _store.GetTenantAsync(tenantId)
            ?? throw new TopologyValidationException("Customer tenant does not exist.");
        var now = DateTimeOffset.UtcNow;
        var start = request.PeriodStartUtc ?? new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var end = request.PeriodEndUtc ?? now;
        start = start.ToUniversalTime();
        end = end.ToUniversalTime();
        if (start >= end) throw new TopologyValidationException("Report start must be before report end.");
        if (end - start > TimeSpan.FromDays(366))
            throw new TopologyValidationException("A report period cannot exceed 366 days.");

        var eventsTask = _store.ListSecurityEventsAsync(ReportRowLimit, tenantId, start, end);
        var incidentsTask = _store.ListIncidentsAsync(ReportRowLimit, tenantId, start, end);
        var aggregateTask = _store.GetReportAggregateAsync(tenantId, start, end);
        var agentsTask = _store.ListAgentsAsync(tenantId);
        var assetsTask = _store.ListAssetsAsync(tenantId);
        await Task.WhenAll(eventsTask, incidentsTask, aggregateTask, agentsTask, assetsTask);

        var events = await eventsTask;
        var incidents = await incidentsTask;
        var aggregate = await aggregateTask;
        var agents = await agentsTask;
        var assets = await assetsTask;
        var agentIds = agents.OfType<AgentInventoryItem>()
            .Select(item => item.AgentId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var incidentIds = incidents.Select(item => item.IncidentId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var campaigns = _tracker.ListCampaigns(500)
            .Where(campaign => campaign.LastSeenUtc >= start && campaign.LastSeenUtc <= end)
            .Where(campaign =>
                campaign.RelatedIncidentIds.Any(incidentIds.Contains) ||
                campaign.Hops.Any(hop =>
                    (!string.IsNullOrWhiteSpace(hop.FromAgentId) && agentIds.Contains(hop.FromAgentId)) ||
                    (!string.IsNullOrWhiteSpace(hop.ToAgentId) && agentIds.Contains(hop.ToAgentId))))
            .ToList();

        var critical = aggregate.CriticalIncidents;
        var high = aggregate.HighIncidents;
        var medium = aggregate.MediumIncidents;
        var low = aggregate.LowIncidents;
        var onlineAgents = agents.OfType<AgentInventoryItem>().Count(item => item.Online);
        var offlineAgents = Math.Max(0, agents.Count - onlineAgents);
        var score = Math.Clamp(100 - critical * 8 - high * 3 - medium - offlineAgents * 2, 0, 100);

        var report = new SecurityReportRecord
        {
            ReportId = Guid.NewGuid().ToString("N"),
            TenantId = tenantId,
            CustomerName = tenant.Name,
            Title = string.IsNullOrWhiteSpace(request.Title)
                ? $"{tenant.Name} Security Report"
                : request.Title.Trim()[..Math.Min(request.Title.Trim().Length, 200)],
            PeriodStartUtc = start,
            PeriodEndUtc = end,
            GeneratedAtUtc = now,
            Metrics = new SecurityReportMetrics
            {
                Agents = agents.Count,
                OnlineAgents = onlineAgents,
                Assets = assets.Count,
                ThreatEvents = aggregate.ThreatEvents,
                Incidents = aggregate.Incidents,
                OpenIncidents = aggregate.OpenIncidents,
                ThreatCampaigns = campaigns.Count,
                DefenseScore = score
            },
            SeverityCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["critical"] = critical,
                ["high"] = high,
                ["medium"] = medium,
                ["low"] = low
            },
            TopSourceIps = events
                .Where(item => !string.IsNullOrWhiteSpace(item.SourceIp))
                .GroupBy(item => item.SourceIp!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(group => new SecurityReportCountItem { Value = group.Key, Count = group.Count() })
                .ToList(),
            TopEventIds = events
                .GroupBy(item => item.EventId)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Key)
                .Take(10)
                .Select(group => new SecurityReportCountItem { Value = group.Key.ToString(), Count = group.Count() })
                .ToList(),
            PriorityIncidents = incidents
                .OrderByDescending(item => item.Severity)
                .ThenByDescending(item => item.LastSeenUtc)
                .Take(12)
                .Select(item => new SecurityReportIncident
                {
                    IncidentId = item.IncidentId,
                    Title = item.Title,
                    Severity = item.Severity,
                    Status = item.Status,
                    SourceIp = item.SourceIp,
                    DestinationIp = item.DestinationIp,
                    LastSeenUtc = item.LastSeenUtc
                })
                .ToList(),
            CoverageNote = events.Count == ReportRowLimit || incidents.Count == ReportRowLimit
                ? $"Summary totals cover all tenant records. Detail rankings use the latest {ReportRowLimit:N0} rows per dataset."
                : "Report covers all tenant records found in the selected UTC period."
        };
        report.Recommendations = BuildRecommendations(report);
        await _store.UpsertReportAsync(report);
        return report;
    }

    public static string RenderHtml(SecurityReportRecord report)
    {
        static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
        var incidentRows = string.Join("", report.PriorityIncidents.Select(item =>
            $"<tr><td>{E(item.Severity.ToString())}</td><td>{E(item.Title)}</td><td>{E(item.SourceIp)}</td><td>{E(item.DestinationIp)}</td><td>{E(item.Status)}</td><td>{item.LastSeenUtc:yyyy-MM-dd HH:mm} UTC</td></tr>"));
        var recommendations = string.Join("", report.Recommendations.Select(item => $"<li>{E(item)}</li>"));
        var sources = string.Join("", report.TopSourceIps.Select(item => $"<li><code>{E(item.Value)}</code><b>{item.Count:N0}</b></li>"));
        const string style = """
            <style>body{font:14px/1.55 Arial,sans-serif;color:#252c38;margin:38px}header{border-bottom:3px solid #efb900;padding-bottom:16px}h1{margin:0}small{color:#687386}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:22px 0}.metrics div{border:1px solid #d9dee6;border-radius:10px;padding:12px}.metrics b{display:block;font-size:24px;color:#b67e00}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #e2e6ec;text-align:left}ul.counts{padding:0;list-style:none}ul.counts li{display:flex;justify-content:space-between;padding:5px 0}footer{margin-top:28px;color:#687386}@media print{body{margin:18mm}button{display:none}}</style>
            """;
        return $"""
            <!doctype html><html lang="th"><head><meta charset="utf-8"><title>{E(report.Title)}</title>
            {style}</head>
            <body><header><small>NT SHIELD • TENANT SECURITY REPORT</small><h1>{E(report.Title)}</h1><p>{E(report.CustomerName)} · {report.PeriodStartUtc:yyyy-MM-dd} – {report.PeriodEndUtc:yyyy-MM-dd} UTC</p><button onclick="window.print()">Print / Save PDF</button></header>
            <section class="metrics"><div><small>Threat events</small><b>{report.Metrics.ThreatEvents:N0}</b></div><div><small>Incidents</small><b>{report.Metrics.Incidents:N0}</b></div><div><small>Threat campaigns</small><b>{report.Metrics.ThreatCampaigns:N0}</b></div><div><small>Defense score</small><b>{report.Metrics.DefenseScore}%</b></div><div><small>Agents online</small><b>{report.Metrics.OnlineAgents}/{report.Metrics.Agents}</b></div><div><small>Assets</small><b>{report.Metrics.Assets:N0}</b></div><div><small>Critical</small><b>{report.SeverityCounts.GetValueOrDefault("critical"):N0}</b></div><div><small>High</small><b>{report.SeverityCounts.GetValueOrDefault("high"):N0}</b></div></section>
            <h2>Priority incidents</h2><table><thead><tr><th>Severity</th><th>Incident</th><th>Source</th><th>Destination</th><th>Status</th><th>Last seen</th></tr></thead><tbody>{incidentRows}</tbody></table>
            <h2>Top source IPs</h2><ul class="counts">{sources}</ul><h2>Recommendations</h2><ol>{recommendations}</ol>
            <footer>Generated {report.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC · Report {E(report.ReportId)}<br>{E(report.CoverageNote)}</footer></body></html>
            """;
    }

    public static string RenderCsv(SecurityReportRecord report)
    {
        static string Csv(string? value) => $"\"{(value ?? string.Empty).Replace("\"", "\"\"")}\"";
        var lines = new List<string>
        {
            "section,key,value",
            $"summary,customer,{Csv(report.CustomerName)}",
            $"summary,period_start,{Csv(report.PeriodStartUtc.ToString("O"))}",
            $"summary,period_end,{Csv(report.PeriodEndUtc.ToString("O"))}",
            $"metric,threat_events,{report.Metrics.ThreatEvents}",
            $"metric,incidents,{report.Metrics.Incidents}",
            $"metric,threat_campaigns,{report.Metrics.ThreatCampaigns}",
            $"metric,defense_score,{report.Metrics.DefenseScore}",
            "",
            "incident_id,severity,title,source_ip,destination_ip,status,last_seen_utc"
        };
        lines.AddRange(report.PriorityIncidents.Select(item => string.Join(',',
            Csv(item.IncidentId), Csv(item.Severity.ToString()), Csv(item.Title), Csv(item.SourceIp),
            Csv(item.DestinationIp), Csv(item.Status), Csv(item.LastSeenUtc.ToString("O")))));
        return string.Join("\r\n", lines);
    }

    private static bool IsClosed(string? status) =>
        string.Equals(status, "closed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "resolved", StringComparison.OrdinalIgnoreCase);

    private static List<string> BuildRecommendations(SecurityReportRecord report)
    {
        var result = new List<string>();
        if (report.SeverityCounts.GetValueOrDefault("critical") > 0)
            result.Add("Review every critical incident and preserve the referenced evidence before response actions.");
        if (report.Metrics.OpenIncidents > 0)
            result.Add($"Triage {report.Metrics.OpenIncidents:N0} open incidents by severity, recency and affected asset criticality.");
        if (report.Metrics.OnlineAgents < report.Metrics.Agents)
            result.Add("Restore offline agents to close telemetry coverage gaps for this customer.");
        if (report.Metrics.Assets == 0)
            result.Add("Build the customer asset inventory and topology so detections can be mapped to business impact.");
        if (result.Count == 0)
            result.Add("Continue monitoring and review this report with the customer during the next service checkpoint.");
        return result;
    }
}
