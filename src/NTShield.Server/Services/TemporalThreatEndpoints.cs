using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public static class TemporalThreatEndpoints
{
    private const int DefaultPageSize = 100;
    private const int MaxPageSize = 500;
    private static readonly JsonSerializerOptions CursorJson = new(JsonSerializerDefaults.Web);

    public static WebApplication MapTemporalThreatEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/v2/threats");

        group.MapGet("/stream", async (
            HttpContext http,
            TemporalThreatRevisionNotifier notifier) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            TemporalThreatRevisionNotifier.Subscription subscription;
            try
            {
                subscription = notifier.Subscribe(tenantId);
            }
            catch (InvalidOperationException)
            {
                http.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                await http.Response.WriteAsJsonAsync(new { error = "temporal_stream_capacity" }, http.RequestAborted);
                return;
            }

            using (subscription)
            {
                http.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
                http.Response.StatusCode = StatusCodes.Status200OK;
                http.Response.ContentType = "text/event-stream";
                http.Response.Headers.CacheControl = "no-cache, no-store";
                http.Response.Headers.Append("X-Accel-Buffering", "no");
                await http.Response.WriteAsync("retry: 15000\n\n", http.RequestAborted);
                await http.Response.Body.FlushAsync(http.RequestAborted);

                var waitToRead = subscription.Reader.WaitToReadAsync(http.RequestAborted).AsTask();
                while (!http.RequestAborted.IsCancellationRequested)
                {
                    var completed = await Task.WhenAny(waitToRead, Task.Delay(TimeSpan.FromSeconds(15), http.RequestAborted));
                    if (completed == waitToRead)
                    {
                        if (!await waitToRead) break;
                        while (subscription.Reader.TryRead(out var notification))
                        {
                            var payload = JsonSerializer.Serialize(notification, CursorJson);
                            await http.Response.WriteAsync(
                                $"id: {notification.Revision}\nevent: threat-revision\ndata: {payload}\n\n",
                                http.RequestAborted);
                        }
                        waitToRead = subscription.Reader.WaitToReadAsync(http.RequestAborted).AsTask();
                    }
                    else
                    {
                        await http.Response.WriteAsync(": keepalive\n\n", http.RequestAborted);
                    }
                    await http.Response.Body.FlushAsync(http.RequestAborted);
                }
            }
        }).WithName("StreamTemporalThreatRevisions");

        group.MapGet("", async (
            HttpContext http,
            ICentralStore store,
            IDataProtectionProvider dataProtection,
            string? cursor = null,
            [FromQuery(Name = "from")] DateTimeOffset? fromUtc = null,
            [FromQuery(Name = "to")] DateTimeOffset? toUtc = null,
            string? status = null,
            string? severity = null,
            int limit = DefaultPageSize) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var cursorProtector = dataProtection.CreateProtector("NTShield.TemporalThreatCursor.v2");
            if (!TryReadCursor(cursor, "campaign", tenantId, null, cursorProtector, out var position))
                return Results.BadRequest(new { error = "invalid_cursor" });
            if (fromUtc > toUtc) return Results.BadRequest(new { error = "invalid_time_range" });
            if (position is not null && !CursorFiltersMatch(position, fromUtc, toUtc, status, severity, null))
                return Results.BadRequest(new { error = "cursor_filter_mismatch" });

            var watermark = position?.WatermarkUtc ?? DateTimeOffset.UtcNow;
            var effectiveFrom = position?.FromUtc ?? fromUtc;
            var effectiveTo = position?.ToUtc ?? toUtc;
            var effectiveStatus = position?.Status ?? NormalizeFilter(status);
            var effectiveSeverity = position?.Severity ?? NormalizeFilter(severity);
            var pageSize = Math.Clamp(limit, 1, MaxPageSize);
            var rows = (await store.ListThreatCampaignV2SummariesAsync(
                tenantId,
                watermark,
                effectiveFrom,
                effectiveTo,
                effectiveStatus,
                effectiveSeverity,
                position?.PositionUtc,
                position?.Id,
                pageSize + 1,
                http.RequestAborted)).ToList();
            var hasMore = rows.Count > pageSize;
            if (hasMore) rows.RemoveAt(rows.Count - 1);
            // The list endpoint is a queue summary, not a detail transport.
            // Preserve exact totals while bounding samples so 100 campaigns
            // remain safely within the compressed response budget.
            foreach (var row in rows) BoundCampaignListItem(row);
            var nextCursor = hasMore && rows.Count > 0
                ? WriteCursor(new TemporalCursor
                {
                    Kind = "campaign",
                    TenantId = tenantId,
                    WatermarkUtc = watermark,
                    PositionUtc = rows[^1].SnapshotAtUtc,
                    Id = rows[^1].CampaignId,
                    FromUtc = effectiveFrom,
                    ToUtc = effectiveTo,
                    Status = effectiveStatus,
                    Severity = effectiveSeverity
                }, cursorProtector)
                : null;
            return Results.Ok(new ThreatCampaignV2Page
            {
                Items = rows,
                NextCursor = nextCursor,
                WatermarkUtc = watermark
            });
        }).WithName("ListTemporalThreatCampaigns");

        group.MapGet("/{campaignId}", async (
            string campaignId,
            HttpContext http,
            ICentralStore store) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var summary = await store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, http.RequestAborted);
            return summary is null ? Results.NotFound() : Results.Ok(summary);
        }).WithName("GetTemporalThreatCampaign");

        group.MapGet("/{campaignId}/graph", async (
            string campaignId,
            HttpContext http,
            ICentralStore store,
            [FromQuery(Name = "from")] DateTimeOffset? fromUtc = null,
            [FromQuery(Name = "to")] DateTimeOffset? toUtc = null,
            int limit = 200) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var summary = await store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, http.RequestAborted);
            if (summary is null) return Results.NotFound();
            if (fromUtc > toUtc) return Results.BadRequest(new { error = "invalid_time_range" });

            var pageSize = Math.Clamp(limit, 1, MaxPageSize);
            var watermark = DateTimeOffset.UtcNow;
            var contacts = (await store.ListThreatContactsAsync(
                tenantId, campaignId, watermark, fromUtc, toUtc,
                null, null, pageSize + 1, http.RequestAborted)).ToList();
            var truncated = contacts.Count > pageSize;
            if (truncated) contacts.RemoveAt(contacts.Count - 1);
            var totalEdges = await store.CountThreatContactsAsync(
                tenantId, campaignId, watermark, fromUtc, toUtc, http.RequestAborted);
            var response = BuildGraph(summary, contacts, totalEdges, truncated);
            return Results.Ok(response);
        }).WithName("GetTemporalThreatGraph");

        group.MapGet("/{campaignId}/timeline", async (
            string campaignId,
            HttpContext http,
            ICentralStore store,
            IDataProtectionProvider dataProtection,
            string? cursor = null,
            [FromQuery(Name = "from")] DateTimeOffset? fromUtc = null,
            [FromQuery(Name = "to")] DateTimeOffset? toUtc = null,
            string resolution = "raw",
            int limit = DefaultPageSize) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var cursorProtector = dataProtection.CreateProtector("NTShield.TemporalThreatCursor.v2");
            if (!TryReadCursor(cursor, "timeline", tenantId, campaignId, cursorProtector, out var position))
                return Results.BadRequest(new { error = "invalid_cursor" });
            var normalizedResolution = NormalizeResolution(resolution);
            if (normalizedResolution is null)
                return Results.BadRequest(new { error = "invalid_resolution", allowed = new[] { "raw", "1m", "5m", "1h" } });
            if (position is not null && !CursorFiltersMatch(position, fromUtc, toUtc, null, null, normalizedResolution))
                return Results.BadRequest(new { error = "cursor_filter_mismatch" });

            var summary = await store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, http.RequestAborted);
            if (summary is null) return Results.NotFound();
            if (position is not null && position.Revision != summary.Revision)
                return Results.Conflict(new { error = "cursor_revision_stale", currentRevision = summary.Revision });
            var watermark = position?.WatermarkUtc ?? DateTimeOffset.UtcNow;
            var effectiveFrom = position?.FromUtc ?? fromUtc;
            var effectiveTo = position?.ToUtc ?? toUtc;
            var effectiveResolution = position?.Resolution ?? normalizedResolution;
            if (effectiveFrom > effectiveTo)
                return Results.BadRequest(new { error = "invalid_time_range" });

            var pageSize = Math.Clamp(limit, 1, MaxPageSize);
            var total = effectiveResolution == "raw"
                ? await store.CountThreatObservationDetailsAsync(
                    tenantId, campaignId, watermark, effectiveFrom, effectiveTo, http.RequestAborted)
                : await store.CountThreatObservationsAsync(
                    tenantId, campaignId, watermark, effectiveFrom, effectiveTo, http.RequestAborted);
            if (effectiveResolution != "raw")
            {
                var resolutionSeconds = ResolutionSeconds(effectiveResolution);
                var buckets = (await store.ListThreatTimelineBucketsAsync(
                    tenantId, campaignId, watermark, effectiveFrom, effectiveTo,
                    resolutionSeconds, position?.PositionUtc, pageSize + 1, http.RequestAborted)).ToList();
                var hasMoreBuckets = buckets.Count > pageSize;
                if (hasMoreBuckets) buckets.RemoveAt(buckets.Count - 1);
                var bucketCursor = hasMoreBuckets && buckets.Count > 0
                    ? WriteCursor(new TemporalCursor
                    {
                        Kind = "timeline",
                        TenantId = tenantId,
                        ResourceId = campaignId,
                        Revision = summary.Revision,
                        WatermarkUtc = watermark,
                        PositionUtc = buckets[^1].StartUtc,
                        Id = buckets[^1].StartUtc.ToUnixTimeSeconds().ToString(),
                        FromUtc = effectiveFrom,
                        ToUtc = effectiveTo,
                        Resolution = effectiveResolution
                    }, cursorProtector)
                    : null;
                return Results.Ok(new ThreatTimelineV2Response
                {
                    Items = [],
                    Buckets = buckets,
                    NextCursor = bucketCursor,
                    Total = total,
                    Truncated = hasMoreBuckets
                });
            }

            var rows = (await store.ListThreatObservationsAsync(
                tenantId,
                campaignId,
                watermark,
                effectiveFrom,
                effectiveTo,
                position?.PositionUtc,
                position?.Id,
                pageSize + 1,
                http.RequestAborted)).ToList();
            var hasMore = rows.Count > pageSize;
            if (hasMore) rows.RemoveAt(rows.Count - 1);
            var nextCursor = hasMore && rows.Count > 0
                ? WriteCursor(new TemporalCursor
                {
                    Kind = "timeline",
                    TenantId = tenantId,
                    ResourceId = campaignId,
                    Revision = summary.Revision,
                    WatermarkUtc = watermark,
                    PositionUtc = rows[^1].ObservedAtUtc,
                    Id = rows[^1].ObservationId,
                    FromUtc = effectiveFrom,
                    ToUtc = effectiveTo,
                    Resolution = "raw"
                }, cursorProtector)
                : null;
            return Results.Ok(new ThreatTimelineV2Response
            {
                Items = rows,
                Buckets = [],
                NextCursor = nextCursor,
                Total = total,
                Truncated = hasMore
            });
        }).WithName("GetTemporalThreatTimeline");

        group.MapGet("/{campaignId}/contacts", async (
            string campaignId,
            HttpContext http,
            ICentralStore store,
            IDataProtectionProvider dataProtection,
            string? cursor = null,
            [FromQuery(Name = "from")] DateTimeOffset? fromUtc = null,
            [FromQuery(Name = "to")] DateTimeOffset? toUtc = null,
            int limit = DefaultPageSize) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var cursorProtector = dataProtection.CreateProtector("NTShield.TemporalThreatCursor.v2");
            if (!TryReadCursor(cursor, "contact", tenantId, campaignId, cursorProtector, out var position))
                return Results.BadRequest(new { error = "invalid_cursor" });
            if (fromUtc > toUtc) return Results.BadRequest(new { error = "invalid_time_range" });
            if (position is not null && !CursorFiltersMatch(position, fromUtc, toUtc, null, null, null))
                return Results.BadRequest(new { error = "cursor_filter_mismatch" });
            var summary = await store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, http.RequestAborted);
            if (summary is null) return Results.NotFound();
            if (position is not null && position.Revision != summary.Revision)
                return Results.Conflict(new { error = "cursor_revision_stale", currentRevision = summary.Revision });

            var watermark = position?.WatermarkUtc ?? DateTimeOffset.UtcNow;
            var effectiveFrom = position?.FromUtc ?? fromUtc;
            var effectiveTo = position?.ToUtc ?? toUtc;
            var pageSize = Math.Clamp(limit, 1, MaxPageSize);
            var rows = (await store.ListThreatContactsAsync(
                tenantId,
                campaignId,
                watermark,
                effectiveFrom,
                effectiveTo,
                position?.PositionUtc,
                position?.Id,
                pageSize + 1,
                http.RequestAborted)).ToList();
            var hasMore = rows.Count > pageSize;
            if (hasMore) rows.RemoveAt(rows.Count - 1);
            var total = await store.CountThreatContactsAsync(
                tenantId, campaignId, watermark, effectiveFrom, effectiveTo, http.RequestAborted);
            var nextCursor = hasMore && rows.Count > 0
                ? WriteCursor(new TemporalCursor
                {
                    Kind = "contact",
                    TenantId = tenantId,
                    ResourceId = campaignId,
                    Revision = summary.Revision,
                    WatermarkUtc = watermark,
                    PositionUtc = rows[^1].LastObservedAtUtc,
                    Id = rows[^1].ContactId,
                    FromUtc = effectiveFrom,
                    ToUtc = effectiveTo
                }, cursorProtector)
                : null;
            return Results.Ok(new ThreatContactsV2Response
            {
                Items = rows,
                NextCursor = nextCursor,
                Total = total
            });
        }).WithName("GetTemporalThreatContacts");

        return app;
    }

    private static void BoundCampaignListItem(ThreatCampaignV2Summary summary)
    {
        summary.Title = BoundText(summary.Title, 160);
        summary.Summary = BoundText(summary.Summary, 240);
        summary.InvolvedHosts = BoundSamples(summary.InvolvedHosts, 2, 96);
        summary.InvolvedIps = BoundSamples(summary.InvolvedIps, 2, 64);
        summary.RelatedIncidentIds = BoundSamples(summary.RelatedIncidentIds, 2, 96);
    }

    private static List<string> BoundSamples(IEnumerable<string>? values, int take, int maxLength) =>
        (values ?? [])
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(take)
        .Select(value => BoundText(value, maxLength))
        .ToList();

    private static string BoundText(string? value, int maxLength)
    {
        value = value?.Trim() ?? string.Empty;
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private static ThreatGraphV2Response BuildGraph(
        ThreatCampaignV2Summary summary,
        IReadOnlyCollection<ThreatContactAggregate> contacts,
        long totalEdges,
        bool truncated)
    {
        var nodes = new Dictionary<string, ThreatGraphNode>(StringComparer.OrdinalIgnoreCase);
        var edges = new List<ThreatGraphEdge>(contacts.Count);
        foreach (var contact in contacts)
        {
            AddNode(nodes, contact.SourceNodeId, contact.SourceIp, contact.SourceHost,
                contact.SourceAgentId, contact.ObservationCount, contact.FirstObservedAtUtc, contact.LastObservedAtUtc);
            AddNode(nodes, contact.DestinationNodeId, contact.DestinationIp, contact.DestinationHost,
                contact.DestinationAgentId, contact.ObservationCount, contact.FirstObservedAtUtc, contact.LastObservedAtUtc);
            edges.Add(new ThreatGraphEdge
            {
                EdgeId = contact.ContactId,
                SourceNodeId = contact.SourceNodeId,
                DestinationNodeId = contact.DestinationNodeId,
                Relation = contact.Relation,
                Technique = contact.Technique,
                Protocol = contact.Protocol,
                Port = contact.RemotePort,
                FirstObservedAtUtc = contact.FirstObservedAtUtc,
                LastObservedAtUtc = contact.LastObservedAtUtc,
                ObservationCount = contact.ObservationCount,
                RecurrenceCount = contact.RecurrenceCount,
                DurationSeconds = Math.Round(Math.Max(
                    0, (contact.LastObservedAtUtc - contact.FirstObservedAtUtc).TotalSeconds), 3),
                MedianGapSeconds = contact.MedianGapSeconds,
                P95GapSeconds = contact.P95GapSeconds,
                BeaconScore = contact.BeaconScore,
                MetricQuality = contact.MetricQuality,
                Provenance = contact.Provenance,
                EvidenceRefs = contact.EvidenceRefs.Take(32).ToList(),
                PredecessorEdgeIds = [],
                Inferred = contact.Inferred,
                Confidence = contact.Confidence
            });
        }

        return new ThreatGraphV2Response
        {
            CampaignId = summary.CampaignId,
            Revision = summary.Revision,
            Nodes = nodes.Values.OrderBy(item => item.NodeId, StringComparer.Ordinal).ToList(),
            Edges = edges,
            TotalNodes = nodes.Count,
            TotalEdges = totalEdges,
            Truncated = truncated || totalEdges > edges.Count
        };
    }

    private static void AddNode(
        IDictionary<string, ThreatGraphNode> nodes,
        string nodeId,
        string? ip,
        string? host,
        string? agentId,
        long count,
        DateTimeOffset first,
        DateTimeOffset last)
    {
        if (nodes.TryGetValue(nodeId, out var existing))
        {
            existing.ObservationCount += count;
            if (first < existing.FirstObservedAtUtc) existing.FirstObservedAtUtc = first;
            if (last > existing.LastObservedAtUtc) existing.LastObservedAtUtc = last;
            return;
        }

        nodes[nodeId] = new ThreatGraphNode
        {
            NodeId = nodeId,
            Kind = !string.IsNullOrWhiteSpace(agentId) ? "agent" :
                !string.IsNullOrWhiteSpace(host) ? "host" :
                !string.IsNullOrWhiteSpace(ip) ? "ip" : "endpoint",
            Label = host ?? ip ?? agentId ?? nodeId,
            Ip = ip,
            Host = host,
            AgentId = agentId,
            ObservationCount = count,
            FirstObservedAtUtc = first,
            LastObservedAtUtc = last
        };
    }

    private static List<ThreatTimelineBucket> BuildBuckets(
        IReadOnlyCollection<ThreatObservation> observations,
        DateTimeOffset? fromUtc,
        DateTimeOffset? toUtc)
    {
        if (observations.Count == 0) return [];
        var first = fromUtc ?? observations.Min(item => item.ObservedAtUtc);
        var last = toUtc ?? observations.Max(item => item.ObservedAtUtc);
        var range = last - first;
        var seconds = range <= TimeSpan.FromHours(2) ? 60L :
            range <= TimeSpan.FromHours(12) ? 300L :
            range <= TimeSpan.FromDays(7) ? 3_600L : 86_400L;
        return observations
            .GroupBy(item => FloorTime(item.ObservedAtUtc, seconds))
            .OrderBy(group => group.Key)
            .Select(group => new ThreatTimelineBucket
            {
                StartUtc = group.Key,
                EndUtc = group.Key.AddSeconds(seconds),
                Count = group.Sum(item => (long)Math.Max(1, item.OccurrenceCount)),
                Kinds = group.GroupBy(item => item.Kind, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(
                        kind => kind.Key,
                        kind => kind.Sum(item => (long)Math.Max(1, item.OccurrenceCount)),
                        StringComparer.OrdinalIgnoreCase)
            }).ToList();
    }

    private static DateTimeOffset FloorTime(DateTimeOffset value, long bucketSeconds)
    {
        var utc = value.ToUniversalTime();
        var seconds = utc.ToUnixTimeSeconds();
        return DateTimeOffset.FromUnixTimeSeconds(seconds - seconds % bucketSeconds);
    }

    private static bool CursorFiltersMatch(
        TemporalCursor cursor,
        DateTimeOffset? fromUtc,
        DateTimeOffset? toUtc,
        string? status,
        string? severity,
        string? resolution) =>
        (!fromUtc.HasValue || cursor.FromUtc == fromUtc.Value.ToUniversalTime()) &&
        (!toUtc.HasValue || cursor.ToUtc == toUtc.Value.ToUniversalTime()) &&
        (string.IsNullOrWhiteSpace(status) || string.Equals(cursor.Status, NormalizeFilter(status), StringComparison.Ordinal)) &&
        (string.IsNullOrWhiteSpace(severity) || string.Equals(cursor.Severity, NormalizeFilter(severity), StringComparison.Ordinal)) &&
        (string.IsNullOrWhiteSpace(resolution) || string.Equals(cursor.Resolution, resolution, StringComparison.Ordinal));

    private static string NormalizeFilter(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();

    private static string? NormalizeResolution(string? value) =>
        NormalizeFilter(value) switch
        {
            "" or "raw" => "raw",
            "1m" => "1m",
            "5m" => "5m",
            "1h" => "1h",
            _ => null
        };

    private static int ResolutionSeconds(string resolution) => resolution switch
    {
        "1m" => 60,
        "5m" => 300,
        "1h" => 3_600,
        _ => throw new ArgumentOutOfRangeException(nameof(resolution))
    };

    private static bool TryReadCursor(
        string? encoded,
        string kind,
        string tenantId,
        string? resourceId,
        IDataProtector protector,
        out TemporalCursor? cursor)
    {
        cursor = null;
        if (string.IsNullOrWhiteSpace(encoded)) return true;
        if (encoded.Length > 2_048) return false;
        try
        {
            cursor = JsonSerializer.Deserialize<TemporalCursor>(protector.Unprotect(encoded), CursorJson);
            return cursor is not null &&
                   string.Equals(cursor.Kind, kind, StringComparison.Ordinal) &&
                   string.Equals(cursor.TenantId, tenantId, StringComparison.OrdinalIgnoreCase) &&
                   (resourceId is null || string.Equals(cursor.ResourceId, resourceId, StringComparison.Ordinal)) &&
                   cursor.WatermarkUtc != default && cursor.PositionUtc != default &&
                   !string.IsNullOrWhiteSpace(cursor.Id);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException)
        {
            cursor = null;
            return false;
        }
    }

    private static string WriteCursor(TemporalCursor cursor, IDataProtector protector) =>
        protector.Protect(JsonSerializer.Serialize(cursor, CursorJson));

    private sealed class TemporalCursor
    {
        public string Kind { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string? ResourceId { get; set; }
        public long Revision { get; set; }
        public DateTimeOffset WatermarkUtc { get; set; }
        public DateTimeOffset PositionUtc { get; set; }
        public string Id { get; set; } = string.Empty;
        public DateTimeOffset? FromUtc { get; set; }
        public DateTimeOffset? ToUtc { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Resolution { get; set; } = string.Empty;
    }
}
