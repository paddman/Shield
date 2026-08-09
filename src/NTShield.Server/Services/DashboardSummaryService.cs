using System.Collections.Concurrent;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class DashboardSummaryService
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(10);
    private sealed record CacheEntry(DateTimeOffset CreatedAtUtc, DashboardSummaryV2 Value);

    private readonly ICentralStore _store;
    private readonly LateralMovementTracker _tracker;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _refreshGates = new(StringComparer.OrdinalIgnoreCase);

    public DashboardSummaryService(ICentralStore store, LateralMovementTracker tracker)
    {
        _store = store;
        _tracker = tracker;
    }

    public async Task<DashboardSummaryV2> GetAsync(
        string tenantId,
        string requestedWindow,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var (windowName, windowDuration) = ParseWindow(requestedWindow);
        var cacheKey = $"{tenantId}|{windowName}";
        var now = DateTimeOffset.UtcNow;
        if (_cache.TryGetValue(cacheKey, out var cached) && now - cached.CreatedAtUtc < CacheLifetime)
            return cached.Value;

        // A slow tenant must not head-of-line block every other dashboard. Only
        // coalesce refreshes for the same tenant/window cache key.
        var refreshGate = _refreshGates.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1));
        await refreshGate.WaitAsync(cancellationToken);
        try
        {
            now = DateTimeOffset.UtcNow;
            if (_cache.TryGetValue(cacheKey, out cached) && now - cached.CreatedAtUtc < CacheLifetime)
                return cached.Value;
            var summary = await BuildAsync(tenantId, windowName, windowDuration, now, cancellationToken);
            _cache[cacheKey] = new CacheEntry(now, summary);
            return summary;
        }
        finally
        {
            refreshGate.Release();
        }
    }

    public void Invalidate(string tenantId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        foreach (var key in _cache.Keys.Where(key => key.StartsWith($"{tenantId}|", StringComparison.OrdinalIgnoreCase)))
            _cache.TryRemove(key, out _);
    }

    private async Task<DashboardSummaryV2> BuildAsync(
        string tenantId,
        string windowName,
        TimeSpan windowDuration,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var from = now - windowDuration;
        var overviewTask = _store.GetDashboardOverviewAggregateAsync(
            tenantId, from, now, cancellationToken);
        // These legacy store methods do not yet accept a CancellationToken. WaitAsync
        // keeps an abandoned HTTP request from waiting on them while their bounded
        // reads finish in the background.
        var agentsTask = _store.ListAgentsAsync(tenantId).WaitAsync(cancellationToken);
        var assetsTask = _store.ListAssetsAsync(tenantId).WaitAsync(cancellationToken);
        var recentIncidentsTask = _store.ListIncidentsAsync(100, tenantId, now.AddDays(-30), now)
            .WaitAsync(cancellationToken);
        var activeCampaignCountTask = _store.CountActiveThreatCampaignsAsync(
            tenantId, from, now, cancellationToken);
        var v2CampaignsTask = _store.ListThreatCampaignV2SummariesAsync(
            tenantId,
            now,
            fromObservedAtUtc: from,
            toObservedAtUtc: now,
            status: null,
            severity: null,
            afterLastObservedAtUtc: null,
            afterCampaignId: null,
            take: 100,
            cancellationToken: cancellationToken);

        var trendTasks = Enumerable.Range(0, 7).Select(index =>
        {
            var bucketStart = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero).AddDays(index - 6);
            var bucketEndExclusive = bucketStart.AddDays(1);
            // The store count contract uses an inclusive upper bound. Subtract one
            // tick for complete days so a midnight incident is not counted twice,
            // and cap today's bucket at now so clock-skewed future rows stay out.
            var bucketEndInclusive = bucketEndExclusive <= now
                ? bucketEndExclusive.AddTicks(-1)
                : now;
            return GetTrendBucketAsync(tenantId, bucketStart, bucketEndInclusive, cancellationToken);
        }).ToArray();

        var trendsTask = Task.WhenAll(trendTasks);
        await Task.WhenAll(
            overviewTask,
            agentsTask,
            assetsTask,
            recentIncidentsTask,
            activeCampaignCountTask,
            v2CampaignsTask,
            trendsTask);
        var trends = trendsTask.Result;

        var agents = agentsTask.Result.OfType<AgentInventoryItem>().ToList();
        var incidents = recentIncidentsTask.Result;
        var v2Campaigns = v2CampaignsTask.Result
            .Where(campaign => !IsClosed(campaign.Status))
            .ToList();
        var legacyCampaigns = _tracker.ListCampaigns(100, tenantId)
            .Where(campaign => !IsClosed(campaign.Status))
            .ToList();
        var activeCampaigns = activeCampaignCountTask.Result > 0
            ? (int)Math.Min(int.MaxValue, activeCampaignCountTask.Result)
            : legacyCampaigns.Count;

        var relatedIncidentIds = legacyCampaigns
            .SelectMany(campaign => campaign.RelatedIncidentIds)
            .Concat(v2Campaigns.SelectMany(campaign => campaign.RelatedIncidentIds))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var queue = BuildThreatQueue(v2Campaigns, legacyCampaigns, incidents, relatedIncidentIds);
        var all = overviewTask.Result;
        var latestEvent = all.LatestEventAtUtc;
        var latestConnection = all.LatestConnectionAtUtc;
        var latestHeartbeat = agents.Count == 0 ? null : agents.Max(agent => (DateTimeOffset?)agent.LastSeenUtc);
        var eventFreshness = AgeSeconds(now, latestEvent);
        var connectionFreshness = AgeSeconds(now, latestConnection);
        var heartbeatFreshness = AgeSeconds(now, latestHeartbeat);
        var requiredFreshness = eventFreshness.HasValue && connectionFreshness.HasValue
            ? Math.Max(eventFreshness.Value, connectionFreshness.Value)
            : (long?)null;
        var visibilityGaps = BuildVisibilityGaps(
            eventFreshness, connectionFreshness, heartbeatFreshness, agents.Count);
        var telemetryState = requiredFreshness switch
        {
            <= 120 => "live",
            <= 300 => "degraded",
            > 300 => "stale",
            _ => "unknown"
        };
        var criticalOpen = all.CriticalOpenIncidents;
        var highOpen = all.HighOpenIncidents;

        return new DashboardSummaryV2
        {
            GeneratedAtUtc = now,
            Window = windowName,
            Posture = BuildPosture(
                criticalOpen, highOpen, agents.Count(agent => !agent.Online), telemetryState, visibilityGaps),
            Counts = new DashboardCountSummary
            {
                IncidentsTotal = all.Incidents,
                OpenIncidents = all.OpenIncidents,
                CriticalOpen = criticalOpen,
                HighOpen = highOpen,
                ActiveCampaigns = activeCampaigns,
                AffectedAssets = all.AffectedAssets,
                AgentsTotal = agents.Count,
                AgentsOnline = agents.Count(agent => agent.Online),
                AgentsOffline = agents.Count(agent => !agent.Online),
                ManagedAssets = assetsTask.Result.Count,
                ThreatEventsInWindow = all.ThreatEvents
            },
            Telemetry = new DashboardTelemetrySummary
            {
                LatestEventAtUtc = latestEvent,
                LatestConnectionAtUtc = latestConnection,
                LatestHeartbeatAtUtc = latestHeartbeat,
                EventFreshnessSeconds = eventFreshness,
                ConnectionFreshnessSeconds = connectionFreshness,
                HeartbeatFreshnessSeconds = heartbeatFreshness,
                FreshnessSeconds = requiredFreshness,
                State = telemetryState,
                VisibilityGaps = visibilityGaps
            },
            Executive = new DashboardExecutiveSummary
            {
                CoveragePercent = agents.Count == 0
                    ? null
                    : Math.Round(agents.Count(agent => agent.Online) * 100d / agents.Count, 2),
                // Incident lifecycle currently preserves event first/last time,
                // but not detected/acknowledged/resolved/SLA instants. Keep these
                // unknown until that evidence exists instead of fabricating KPIs.
                MeanTimeToDetectSeconds = null,
                MeanTimeToRespondSeconds = null,
                SlaTracked = null,
                SlaBreached = null,
                MeasurementState = "partial",
                MeasurementGaps =
                [
                    "incident_detected_at_utc_missing",
                    "incident_acknowledged_at_utc_missing",
                    "incident_resolved_at_utc_missing",
                    "incident_sla_due_at_utc_missing"
                ]
            },
            Trends = trends.ToList(),
            ThreatQueue = queue
        };
    }

    private async Task<DashboardTrendBucket> GetTrendBucketAsync(
        string tenantId,
        DateTimeOffset start,
        DateTimeOffset end,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Trend only needs incident volume. Reusing the report aggregate here
        // also scanned security events, network freshness and affected assets
        // four times per bucket (28 unrelated queries for a seven-day chart).
        var incidentTask = _store.CountIncidentsAsync(tenantId, start, end)
            .WaitAsync(cancellationToken);
        var campaignTask = _store.CountActiveThreatCampaignsAsync(tenantId, start, end, cancellationToken);
        await Task.WhenAll(incidentTask, campaignTask);
        return new DashboardTrendBucket
        {
            BucketStartUtc = start,
            Incidents = (int)Math.Min(int.MaxValue, incidentTask.Result),
            Campaigns = (int)Math.Min(int.MaxValue, campaignTask.Result)
        };
    }

    private static List<DashboardThreatQueueItem> BuildThreatQueue(
        IReadOnlyList<ThreatCampaignV2Summary> v2Campaigns,
        IReadOnlyList<ThreatCampaign> legacyCampaigns,
        IReadOnlyList<Incident> incidents,
        IReadOnlySet<string> relatedIncidentIds)
    {
        var items = new List<DashboardThreatQueueItem>();
        if (v2Campaigns.Count > 0)
        {
            items.AddRange(v2Campaigns.Select(campaign => new DashboardThreatQueueItem
            {
                Kind = "campaign",
                Id = campaign.CampaignId,
                CampaignId = campaign.CampaignId,
                Title = string.IsNullOrWhiteSpace(campaign.Title) ? "Correlated threat campaign" : campaign.Title,
                Severity = campaign.Severity,
                Confidence = campaign.Confidence,
                RecurrenceCount = campaign.RecurrenceCount,
                FirstObservedAtUtc = campaign.FirstObservedAtUtc,
                LastObservedAtUtc = campaign.LastObservedAtUtc,
                AffectedAssetCount = campaign.InvolvedHosts.Concat(campaign.InvolvedIps)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                Reason = campaign.RecurrenceCount > 1
                    ? $"Repeated contact observed {campaign.RecurrenceCount} times"
                    : $"Correlated from {campaign.ObservationCount} observations",
                Status = campaign.Status
            }));
        }
        else
        {
            items.AddRange(legacyCampaigns.Select(campaign => new DashboardThreatQueueItem
            {
                Kind = "campaign",
                Id = campaign.CampaignId,
                CampaignId = campaign.CampaignId,
                IncidentId = campaign.RelatedIncidentIds.FirstOrDefault(),
                Title = string.IsNullOrWhiteSpace(campaign.Summary) ? "Correlated threat campaign" : campaign.Summary,
                Severity = campaign.Severity.ToString(),
                Confidence = null,
                RecurrenceCount = Math.Max(1, campaign.Hops.Count),
                FirstObservedAtUtc = campaign.FirstSeenUtc,
                LastObservedAtUtc = campaign.LastSeenUtc,
                AffectedAssetCount = campaign.InvolvedHosts.Concat(campaign.InvolvedIps)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                Reason = $"{campaign.Hops.Count} correlated observations",
                Status = campaign.Status
            }));
        }

        items.AddRange(incidents
            .Where(incident => !IsClosed(incident.Status) && !relatedIncidentIds.Contains(incident.IncidentId))
            .Select(incident => new DashboardThreatQueueItem
            {
                Kind = "incident",
                Id = incident.IncidentId,
                IncidentId = incident.IncidentId,
                Title = incident.Title,
                Severity = incident.Severity.ToString(),
                Confidence = incident.IncidentScore.HasValue ? Math.Clamp(incident.IncidentScore.Value / 100d, 0, 1) : null,
                RecurrenceCount = Math.Max(1, incident.FailedAttempts),
                FirstObservedAtUtc = SafeIncidentTime(incident.FirstSeen, incident.LastSeen),
                LastObservedAtUtc = SafeIncidentTime(incident.LastSeen, incident.FirstSeen),
                AffectedAssetCount = new[] { incident.SourceHost, incident.DestinationHost, incident.SourceIp, incident.DestinationIp }
                    .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                Reason = incident.FailedAttempts > 1
                    ? $"{incident.FailedAttempts} repeated attempts"
                    : "Open incident awaiting triage",
                Status = incident.Status
            }));

        return items
            .OrderByDescending(item => SeverityRank(item.Severity))
            .ThenByDescending(item => item.RecurrenceCount)
            .ThenByDescending(item => item.LastObservedAtUtc)
            .Take(20)
            .ToList();
    }

    private static DashboardPostureSummary BuildPosture(
        int criticalOpen,
        int highOpen,
        int offlineAgents,
        string telemetryState,
        IReadOnlyCollection<string> visibilityGaps)
    {
        if (criticalOpen > 0)
            return new DashboardPostureSummary { State = "critical", Reason = $"{criticalOpen} critical threat(s) require attention" };
        if (highOpen > 0)
            return new DashboardPostureSummary { State = "elevated", Reason = $"{highOpen} high-severity threat(s) remain open" };
        if (offlineAgents > 0)
            return new DashboardPostureSummary { State = "elevated", Reason = $"{offlineAgents} managed agent(s) are offline" };
        if (!string.Equals(telemetryState, "live", StringComparison.Ordinal))
            return new DashboardPostureSummary
            {
                State = "elevated",
                Reason = visibilityGaps.Count > 0
                    ? $"Security visibility gap: {string.Join(", ", visibilityGaps)}"
                    : "Security telemetry is degraded or unavailable"
            };
        return new DashboardPostureSummary { State = "stable", Reason = "No urgent measured condition" };
    }

    private static long? AgeSeconds(DateTimeOffset now, DateTimeOffset? timestamp) =>
        timestamp.HasValue ? Math.Max(0, (long)(now - timestamp.Value).TotalSeconds) : null;

    private static List<string> BuildVisibilityGaps(
        long? eventFreshness,
        long? connectionFreshness,
        long? heartbeatFreshness,
        int agentCount)
    {
        var gaps = new List<string>();
        AddGap(gaps, "security_events", eventFreshness);
        AddGap(gaps, "network_connections", connectionFreshness);
        if (agentCount > 0) AddGap(gaps, "agent_heartbeats", heartbeatFreshness);
        return gaps;
    }

    private static void AddGap(List<string> gaps, string feed, long? freshness)
    {
        if (!freshness.HasValue) gaps.Add($"{feed}_missing");
        else if (freshness.Value > 300) gaps.Add($"{feed}_stale");
    }

    private static (string Name, TimeSpan Duration) ParseWindow(string requested) =>
        requested.Trim().ToLowerInvariant() switch
        {
            "7d" => ("7d", TimeSpan.FromDays(7)),
            "30d" => ("30d", TimeSpan.FromDays(30)),
            _ => ("24h", TimeSpan.FromHours(24))
        };

    private static bool IsClosed(string? status) =>
        string.Equals(status, "closed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "resolved", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "merged", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "tombstoned", StringComparison.OrdinalIgnoreCase);

    private static int SeverityRank(string? severity) => severity?.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private static DateTimeOffset SafeIncidentTime(DateTimeOffset? preferred, DateTimeOffset? fallback)
    {
        var value = preferred ?? fallback ?? DateTimeOffset.UtcNow;
        return value == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : value;
    }
}
