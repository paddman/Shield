using System.Security.Cryptography;
using System.Text;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Correlation;

/// <summary>
/// Phase 2 event-time projection. It preserves immutable repeated observations and
/// lets the store atomically materialize contact/campaign aggregates. The legacy
/// tracker remains the campaign detector during the compatibility phase.
/// </summary>
public sealed class TemporalAttackChainService
{
    private const int MaxObservationsPerIngest = 5_000;
    private readonly ICentralStore _store;
    private readonly ILogger<TemporalAttackChainService> _logger;
    private readonly TemporalThreatRevisionNotifier? _notifier;

    public TemporalAttackChainService(
        ICentralStore store,
        ILogger<TemporalAttackChainService> logger,
        TemporalThreatRevisionNotifier? notifier = null)
    {
        _store = store;
        _logger = logger;
        _notifier = notifier;
    }

    public async Task<int> RecordAsync(
        AgentIngestBatch batch,
        IReadOnlyCollection<Incident> incidents,
        IReadOnlyCollection<ThreatCampaign> campaigns,
        string tenantId,
        CancellationToken cancellationToken)
    {
        tenantId = NormalizeTenant(tenantId);
        var now = DateTimeOffset.UtcNow;
        var clockCorrection = ResolveClockCorrection(
            batch.ClockSkewSeconds, batch.ClockSkewMeasuredAtUtc, now);

        // Preserve every usable network contact before campaign assignment. This
        // append-only staging set lets a later correlator discover recurrence/beacon
        // behavior even when the current legacy detector has no incident yet.
        var unassignedCampaign = new ThreatCampaign { CampaignId = string.Empty };
        var candidates = batch.NetworkConnections
            .Where(item => !string.IsNullOrWhiteSpace(item.RemoteAddress))
            .Take(MaxObservationsPerIngest)
            .Select(item => FromNetworkConnection(
                tenantId, unassignedCampaign, item, null, now))
            .Concat(batch.SecurityEvents.Take(MaxObservationsPerIngest)
                .Select(item => FromSecurityEvent(tenantId, unassignedCampaign, item, null, now)))
            .Concat(batch.Alerts.Where(item => !item.Suppressed).Take(MaxObservationsPerIngest)
                .Select(item => FromAlert(tenantId, unassignedCampaign, item, null, now)))
            .Select(item => ApplyClockCorrection(item, clockCorrection))
            .Where(IsUsable)
            .GroupBy(item => item.ObservationId, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .Take(MaxObservationsPerIngest)
            .ToList();
        var staged = 0;
        foreach (var chunk in candidates.Chunk(16))
        {
            var results = await Task.WhenAll(chunk.Select(item =>
                _store.TryAppendThreatCandidateObservationAsync(item, cancellationToken)));
            staged += results.Count(value => value);
        }
        var promoted = await CorrelateCandidatesAsync(
            tenantId, candidates, now, cancellationToken);

        if (incidents.Count == 0 || campaigns.Count == 0) return staged + promoted;

        var incidentIds = incidents.Select(item => item.IncidentId)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var relevantCampaigns = campaigns
            .Where(item => string.Equals(NormalizeTenant(item.TenantId), tenantId, StringComparison.Ordinal))
            .Where(item => item.RelatedIncidentIds.Any(incidentIds.Contains))
            .GroupBy(item => item.CampaignId, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(item => item.LastSeenUtc).First())
            .Take(100)
            .ToList();
        if (relevantCampaigns.Count == 0) return staged + promoted;

        var campaignByIncident = new Dictionary<string, ThreatCampaign>(StringComparer.OrdinalIgnoreCase);
        foreach (var campaign in relevantCampaigns)
        foreach (var incidentId in campaign.RelatedIncidentIds.Where(incidentIds.Contains))
            campaignByIncident[incidentId] = campaign;

        var contexts = relevantCampaigns.Select(CampaignContext.Create).ToList();
        var observations = new List<ThreatObservation>();
        var representedIncidents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var securityEvent in batch.SecurityEvents)
        {
            var incident = FindIncident(securityEvent, incidents);
            var campaign = incident is not null && campaignByIncident.TryGetValue(incident.IncidentId, out var direct)
                ? direct
                : FindCampaign(contexts, securityEvent.SourceIp, securityEvent.DestinationIp,
                    null, securityEvent.ComputerName, securityEvent.AgentId, securityEvent.TimestampUtc);
            if (campaign is null) continue;
            if (incident is not null) representedIncidents.Add(incident.IncidentId);
            observations.Add(FromSecurityEvent(tenantId, campaign, securityEvent, incident, now));
        }

        foreach (var alert in batch.Alerts.Where(item => !item.Suppressed))
        {
            var incident = incidents.FirstOrDefault(item =>
                item.IncidentId.EndsWith(alert.AlertId, StringComparison.OrdinalIgnoreCase));
            var campaign = incident is not null && campaignByIncident.TryGetValue(incident.IncidentId, out var direct)
                ? direct
                : FindCampaign(contexts, alert.SourceIp, alert.DestinationIp, null,
                    alert.ComputerName, alert.AgentId, alert.TimestampUtc);
            if (campaign is null) continue;
            if (incident is not null) representedIncidents.Add(incident.IncidentId);
            observations.Add(FromAlert(tenantId, campaign, alert, incident, now));
        }

        foreach (var connection in batch.NetworkConnections)
        {
            if (string.IsNullOrWhiteSpace(connection.RemoteAddress)) continue;
            var campaign = FindCampaign(contexts, connection.LocalAddress, connection.RemoteAddress,
                connection.ComputerName, null, connection.AgentId, connection.TimestampUtc);
            if (campaign is null) continue;
            var incident = FindNearestIncident(connection, incidents, campaign);
            observations.Add(FromNetworkConnection(tenantId, campaign, connection, incident, now));
        }

        foreach (var incident in incidents.Where(item => !representedIncidents.Contains(item.IncidentId)))
        {
            if (!campaignByIncident.TryGetValue(incident.IncidentId, out var campaign)) continue;
            observations.Add(FromIncident(tenantId, campaign, incident, now));
        }

        observations = observations
            .Select(item => ApplyClockCorrection(item, clockCorrection))
            .Where(IsUsable)
            .GroupBy(item => item.ObservationId, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.ObservedAtUtc)
            .Take(MaxObservationsPerIngest)
            .ToList();
        if (observations.Count == 0) return staged + promoted;

        var usedCampaignIds = observations.Select(item => item.CampaignId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var campaign in relevantCampaigns.Where(item => usedCampaignIds.Contains(item.CampaignId)))
            await _store.UpsertThreatCampaignV2SummaryAsync(ProjectSummary(campaign, tenantId, now), cancellationToken);

        var inserted = 0;
        foreach (var chunk in observations.Chunk(16))
        {
            var results = await Task.WhenAll(chunk.Select(item =>
                AppendOrAssignAsync(item, "legacy_campaign_match", cancellationToken)));
            inserted += results.Count(value => value);
        }

        if (inserted > 0)
        {
            if (_notifier is not null)
            {
                foreach (var campaignId in usedCampaignIds)
                {
                    var summary = await _store.GetThreatCampaignV2SummaryAsync(
                        tenantId, campaignId, cancellationToken);
                    if (summary is not null)
                    {
                        _notifier.Publish(tenantId, new TemporalThreatRevisionNotification(
                            campaignId, summary.Revision, summary.UpdatedAtUtc));
                    }
                }
            }
            _logger.LogInformation(
                "Temporal threat projection appended {Inserted}/{Candidates} observations tenant={Tenant} campaigns={Campaigns}",
                inserted, observations.Count, tenantId, usedCampaignIds.Count);
        }
        return inserted + staged + promoted;
    }

    public Task EnsureSummaryAsync(
        ThreatCampaign campaign,
        string tenantId,
        CancellationToken cancellationToken = default) =>
        _store.UpsertThreatCampaignV2SummaryAsync(
            ProjectSummary(campaign, NormalizeTenant(tenantId), DateTimeOffset.UtcNow),
            cancellationToken);

    private async Task<int> CorrelateCandidatesAsync(
        string tenantId,
        IReadOnlyCollection<ThreatObservation> seeds,
        DateTimeOffset ingestedAtUtc,
        CancellationToken cancellationToken)
    {
        if (seeds.Count == 0) return 0;
        var promoted = 0;
        var handledCampaigns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var seed in seeds
                     .GroupBy(CandidateContextKey, StringComparer.Ordinal)
                     .Select(group => group.First())
                     .Take(500))
        {
            // A recurrence candidate is only meaningful when both sides of the
            // contact have a stable identity. Security events with no source
            // IP/host/agent are common local audit noise; grouping those rows
            // would turn an unknown endpoint into an active threat. Keep the
            // raw observation staged for audit/rebuild, but do not promote it.
            if (!HasStableEndpointContext(seed))
            {
                await DowngradeUncorroboratedRecurrenceAsync(
                    tenantId, seed, ingestedAtUtc, cancellationToken);
                continue;
            }

            var recent = await _store.ListThreatCandidateContextObservationsAsync(
                tenantId, seed.SourceNodeId, seed.DestinationNodeId,
                ingestedAtUtc.AddDays(-7), ingestedAtUtc.AddMinutes(5), 500, cancellationToken);
            var candidates = recent
                .Where(item => SharedEvidenceDimensions(seed, item) >= 2)
                .GroupBy(item => item.ObservationId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderBy(item => item.ObservedAtUtc)
                .ToList();
            var categories = CandidateEvidenceCategories(candidates);
            var rawConfidence = Math.Min(.95, .55 + Math.Min(candidates.Count, 5) * .05 +
                Math.Max(0, categories.Count - 1) * .10);
            var confirmed = candidates.Count >= 3 && categories.Count >= 2 && rawConfidence >= .80;
            // The wire contract reserves >=.80 for corroborated campaigns. A
            // periodic-only candidate may be highly repeatable, but remains
            // inferred until an independent evidence category arrives.
            var confidence = confirmed ? rawConfidence : Math.Min(.79, rawConfidence);
            var candidateOnly = candidates.Count >= 5;
            if (!confirmed && !candidateOnly) continue;

            var campaignId = "recurrence-" + StableId(
                $"{tenantId}|{CandidateContextKey(seed)}", 32);
            if (!handledCampaigns.Add(campaignId)) continue;
            var existing = await _store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, cancellationToken);
            var refreshInferredCandidate = existing is not null && !confirmed &&
                string.Equals(existing.Status, "Candidate", StringComparison.OrdinalIgnoreCase) &&
                (existing.Confidence ?? 0) > .79;
            if (existing is null || (confirmed &&
                string.Equals(existing.Status, "Candidate", StringComparison.OrdinalIgnoreCase)) ||
                refreshInferredCandidate)
            {
                var first = candidates[0];
                var last = candidates[^1];
                var hosts = candidates.SelectMany(item => new[] { item.SourceHost, item.DestinationHost })
                    .Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList();
                var ips = candidates.SelectMany(item => new[] { item.SourceIp, item.DestinationIp })
                    .Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToList();
                await _store.UpsertThreatCampaignV2SummaryAsync(new ThreatCampaignV2Summary
                {
                    TenantId = tenantId,
                    CampaignId = campaignId,
                    Revision = 1,
                    Status = confirmed ? "Open" : "Candidate",
                    Severity = confirmed ? "Medium" : "Informational",
                    Confidence = confidence,
                    FirstObservedAtUtc = first.ObservedAtUtc,
                    LastObservedAtUtc = last.ObservedAtUtc,
                    UpdatedAtUtc = ingestedAtUtc,
                    InvolvedHosts = hosts,
                    InvolvedIps = ips,
                    AffectedAssetCount = candidates
                        .SelectMany(item => new[] { item.SourceNodeId, item.DestinationNodeId })
                        .Distinct(StringComparer.OrdinalIgnoreCase).LongCount(),
                    Title = confirmed ? "Corroborated repeated contact" : "Repeated contact candidate",
                    Summary = confirmed
                        ? $"Repeated contact observed {candidates.Count} times with {categories.Count} corroborating evidence categories."
                        : $"Repeated contact observed {candidates.Count} times; retained as inferred candidate pending corroboration."
                }, cancellationToken);
            }

            foreach (var candidate in candidates)
            {
                candidate.CampaignId = campaignId;
                candidate.Inferred = !confirmed;
                if (await AppendOrAssignAsync(
                        candidate,
                        confirmed ? "candidate_corroboration_promoted" : "candidate_recurrence_inferred",
                        cancellationToken))
                    promoted++;
            }

            if (_notifier is not null)
            {
                var summary = await _store.GetThreatCampaignV2SummaryAsync(
                    tenantId, campaignId, cancellationToken);
                if (summary is not null)
                    _notifier.Publish(tenantId, new TemporalThreatRevisionNotification(
                        campaignId, summary.Revision, summary.UpdatedAtUtc));
            }
        }
        return promoted;
    }

    private async Task<bool> AppendOrAssignAsync(
        ThreatObservation observation,
        string provenance,
        CancellationToken cancellationToken)
    {
        if (await _store.TryAppendThreatObservationAsync(observation, cancellationToken)) return true;
        await _store.UpsertThreatObservationMembershipAsync(new ThreatObservationMembership
        {
            TenantId = observation.TenantId,
            CampaignId = observation.CampaignId,
            ObservationId = observation.ObservationId,
            AssignedAtUtc = observation.IngestedAtUtc,
            Confidence = observation.Confidence,
            Provenance = provenance,
            Active = true
        }, cancellationToken);
        return false;
    }

    public async Task<int> BackfillLegacyCampaignAsync(
        ThreatCampaign campaign,
        CancellationToken cancellationToken = default)
    {
        var tenantId = NormalizeTenant(campaign.TenantId);
        var existing = await _store.GetThreatCampaignV2SummaryAsync(
            tenantId, campaign.CampaignId, cancellationToken);
        if (existing is null)
            await _store.UpsertThreatCampaignV2SummaryAsync(
                ProjectSummary(campaign, tenantId, DateTimeOffset.UtcNow), cancellationToken);
        var inserted = 0;
        foreach (var indexed in campaign.Hops.Take(500).Select((hop, index) => (hop, index)))
        {
            var hop = indexed.hop;
            var observed = ValidDate(hop.TimestampUtc, campaign.LastSeenUtc, campaign.FirstSeenUtc, DateTimeOffset.UtcNow);
            var evidenceId = $"legacy:{campaign.CampaignId}:{indexed.index}:{StableId(hop.Evidence ?? string.Empty, 16)}";
            var observation = new ThreatObservation
            {
                TenantId = tenantId,
                CampaignId = campaign.CampaignId,
                Kind = "legacy_hop",
                Relation = "lateral_movement",
                RawObservedAtUtc = observed,
                ObservedAtUtc = observed,
                IngestedAtUtc = DateTimeOffset.UtcNow,
                OccurrenceCount = 1,
                SourceNodeId = NodeId(hop.FromAgentId, hop.FromHost, CleanEndpoint(hop.FromIp),
                    $"legacy-source:{campaign.CampaignId}:{indexed.index}"),
                SourceIp = CleanEndpoint(hop.FromIp),
                SourceHost = hop.FromHost,
                SourceAgentId = hop.FromAgentId,
                DestinationNodeId = NodeId(hop.ToAgentId, hop.ToHost, CleanEndpoint(hop.ToIp),
                    $"legacy-destination:{campaign.CampaignId}:{indexed.index}"),
                DestinationIp = CleanEndpoint(hop.ToIp),
                DestinationHost = hop.ToHost,
                DestinationAgentId = hop.ToAgentId,
                RemotePort = hop.Port,
                Username = hop.Username,
                ProcessId = hop.ProcessId,
                ProcessName = hop.ProcessName,
                ServiceNames = hop.ServiceNames,
                Technique = Bound(hop.Technique, 128),
                IncidentId = hop.IncidentId,
                EvidenceType = "legacy_campaign_hop",
                EvidenceId = evidenceId,
                Confidence = .5,
                TimestampQuality = "legacy_collapsed"
            };
            CompleteKeys(observation, evidenceId);
            if (await AppendOrAssignAsync(
                    observation, "legacy_campaign_backfill", cancellationToken)) inserted++;
        }
        return inserted;
    }

    private static ThreatCampaignV2Summary ProjectSummary(
        ThreatCampaign campaign,
        string tenantId,
        DateTimeOffset updatedAtUtc)
    {
        var first = ValidDate(campaign.FirstSeenUtc, campaign.LastSeenUtc, updatedAtUtc);
        var last = ValidDate(campaign.LastSeenUtc, first, updatedAtUtc);
        var hosts = campaign.InvolvedHosts.Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList();
        var ips = campaign.InvolvedIps.Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToList();
        var assetCount = campaign.InvolvedHosts.Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase).LongCount();
        if (assetCount == 0)
            assetCount = campaign.InvolvedIps.Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase).LongCount();

        return new ThreatCampaignV2Summary
        {
            TenantId = tenantId,
            CampaignId = campaign.CampaignId,
            Revision = 1,
            Status = Bound(campaign.Status, 32),
            Severity = campaign.Severity.ToString(),
            Confidence = campaign.MlConfidence,
            FirstObservedAtUtc = first,
            LastObservedAtUtc = last,
            UpdatedAtUtc = updatedAtUtc,
            AffectedAssetCount = assetCount,
            RelatedIncidentCount = campaign.RelatedIncidentIds.LongCount(),
            RelatedIncidentIds = campaign.RelatedIncidentIds
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase).Take(50).ToList(),
            InvolvedHosts = hosts,
            InvolvedIps = ips,
            Title = Bound(campaign.Title, 300),
            Summary = Bound(campaign.Summary, 2_000)
        };
    }

    private static ThreatObservation FromSecurityEvent(
        string tenantId,
        ThreatCampaign campaign,
        SecurityEventRecord item,
        Incident? incident,
        DateTimeOffset ingestedAtUtc)
    {
        var sourceIp = CleanEndpoint(item.SourceIp) ?? incident?.SourceIp;
        var destinationIp = CleanEndpoint(item.DestinationIp) ?? incident?.DestinationIp;
        var sourceNode = NodeId(incident?.SourceAgentId, incident?.SourceHost, sourceIp,
            $"source:{campaign.CampaignId}");
        var destinationNode = NodeId(item.AgentId, item.ComputerName, destinationIp,
            $"destination:{campaign.CampaignId}");
        var kind = item.EventId switch
        {
            4625 => "authentication_failure",
            4624 => "authentication_success",
            4648 => "explicit_credentials",
            4672 => "privileged_logon",
            _ => "security_event"
        };
        var evidenceId = item.EventRecordId > 0
            ? $"windows:{item.AgentId}:{item.Channel}:{item.EventRecordId}"
            : $"windows:{item.AgentId}:{item.Channel}:{item.EventId}:{item.TimestampUtc.UtcTicks}";
        var observation = new ThreatObservation
        {
            TenantId = tenantId,
            CampaignId = campaign.CampaignId,
            EpisodeId = incident?.IncidentId,
            Kind = kind,
            Relation = "authentication",
            ObservedAtUtc = ValidDate(item.TimestampUtc, ingestedAtUtc),
            CollectedAtUtc = ValidNullableDate(item.CollectedAtUtc),
            IngestedAtUtc = ingestedAtUtc,
            OccurrenceCount = 1,
            SourceNodeId = sourceNode,
            SourceIp = sourceIp,
            SourceHost = incident?.SourceHost,
            SourceAgentId = incident?.SourceAgentId,
            DestinationNodeId = destinationNode,
            DestinationIp = destinationIp,
            DestinationHost = item.ComputerName,
            DestinationAgentId = item.AgentId,
            Protocol = "authentication",
            LocalPort = item.SourcePort,
            RemotePort = item.DestinationPort ?? incident?.DestinationPort,
            Username = item.Username,
            ProcessId = item.ProcessId ?? incident?.ProcessId,
            ProcessName = incident?.ProcessName,
            ServiceNames = incident?.SourceServiceNames,
            Technique = Technique(incident),
            IncidentId = incident?.IncidentId,
            EvidenceType = "windows_event",
            EvidenceId = Bound(evidenceId, 300),
            Confidence = 1,
            TimestampQuality = "source_event"
        };
        CompleteKeys(observation, $"security|{evidenceId}");
        return observation;
    }

    private static ThreatObservation FromAlert(
        string tenantId,
        ThreatCampaign campaign,
        DetectionAlert item,
        Incident? incident,
        DateTimeOffset ingestedAtUtc)
    {
        var sourceIp = CleanEndpoint(item.SourceIp) ?? incident?.SourceIp;
        var destinationIp = CleanEndpoint(item.DestinationIp) ?? incident?.DestinationIp;
        var sourceNode = NodeId(incident?.SourceAgentId, incident?.SourceHost, sourceIp,
            $"alert-source:{campaign.CampaignId}");
        var destinationHost = string.IsNullOrWhiteSpace(item.ComputerName) ? incident?.DestinationHost : item.ComputerName;
        var destinationAgent = string.IsNullOrWhiteSpace(item.AgentId) ? incident?.DestinationAgentId : item.AgentId;
        var destinationNode = NodeId(destinationAgent, destinationHost, destinationIp,
            $"alert-destination:{campaign.CampaignId}");
        var evidenceId = $"alert:{item.AlertId}";
        var observation = new ThreatObservation
        {
            TenantId = tenantId,
            CampaignId = campaign.CampaignId,
            EpisodeId = incident?.IncidentId,
            Kind = "detection_alert",
            Relation = "detection",
            ObservedAtUtc = ValidDate(item.TimestampUtc, ingestedAtUtc),
            CollectedAtUtc = null,
            IngestedAtUtc = ingestedAtUtc,
            OccurrenceCount = Math.Max(1, item.EventCount),
            SourceNodeId = sourceNode,
            SourceIp = sourceIp,
            SourceHost = incident?.SourceHost,
            SourceAgentId = incident?.SourceAgentId,
            DestinationNodeId = destinationNode,
            DestinationIp = destinationIp,
            DestinationHost = destinationHost,
            DestinationAgentId = destinationAgent,
            RemotePort = incident?.DestinationPort,
            Username = item.Username,
            ProcessId = incident?.ProcessId,
            ProcessName = incident?.ProcessName,
            ServiceNames = incident?.SourceServiceNames,
            Technique = Technique(incident, item.RuleId),
            IncidentId = incident?.IncidentId,
            EvidenceType = "detection_alert",
            EvidenceId = Bound(evidenceId, 300),
            Confidence = .95,
            TimestampQuality = "detector_event"
        };
        CompleteKeys(observation, evidenceId);
        return observation;
    }

    private static ThreatObservation FromNetworkConnection(
        string tenantId,
        ThreatCampaign campaign,
        NetworkConnectionRecord item,
        Incident? incident,
        DateTimeOffset ingestedAtUtc)
    {
        var sourceIp = CleanEndpoint(item.LocalAddress);
        var destinationIp = CleanEndpoint(item.RemoteAddress);
        var sourceNode = NodeId(item.AgentId, item.ComputerName, sourceIp,
            $"network-source:{campaign.CampaignId}");
        var destinationNode = NodeId(incident?.DestinationAgentId, incident?.DestinationHost, destinationIp,
            $"network-destination:{campaign.CampaignId}");
        var phase = item.IsClosed ? "network_close" : item.IsNew ? "network_open" : "network_observation";
        var stableConnection = !string.IsNullOrWhiteSpace(item.LifecycleId)
            ? $"lifecycle:{item.LifecycleId}"
            : !string.IsNullOrWhiteSpace(item.ConnectionKey)
                ? $"tuple:{item.ConnectionKey}"
                : $"tuple:{item.Protocol}|{item.LocalAddress}|{item.LocalPort}|{item.RemoteAddress}|{item.RemotePort}|{item.ProcessId}";
        var evidenceId = $"connection:{item.AgentId}:{StableId(stableConnection, 24)}:{phase}:{item.TimestampUtc.UtcTicks}";
        var observation = new ThreatObservation
        {
            TenantId = tenantId,
            CampaignId = campaign.CampaignId,
            EpisodeId = incident?.IncidentId,
            Kind = phase,
            Relation = "network",
            ObservedAtUtc = ValidDate(item.TimestampUtc, ingestedAtUtc),
            IngestedAtUtc = ingestedAtUtc,
            StartedAtUtc = ValidNullableDate(item.StartedAtUtc),
            EndedAtUtc = ValidNullableDate(item.EndedAtUtc),
            OccurrenceCount = 1,
            SourceNodeId = sourceNode,
            SourceIp = sourceIp,
            SourceHost = item.ComputerName,
            SourceAgentId = item.AgentId,
            DestinationNodeId = destinationNode,
            DestinationIp = destinationIp,
            DestinationHost = incident?.DestinationHost,
            DestinationAgentId = incident?.DestinationAgentId,
            Protocol = item.Protocol,
            LocalPort = item.LocalPort,
            RemotePort = item.RemotePort,
            Username = item.ProcessOwner,
            ProcessId = item.ProcessId > 0 ? item.ProcessId : null,
            ProcessName = item.ProcessName,
            ServiceNames = item.ServiceNames,
            Technique = Technique(incident, "network_contact"),
            IncidentId = incident?.IncidentId,
            EvidenceType = "network_connection",
            EvidenceId = Bound(evidenceId, 300),
            Confidence = 1,
            TimestampQuality = "collector_observation"
        };
        CompleteKeys(observation, evidenceId);
        return observation;
    }

    private static ThreatObservation FromIncident(
        string tenantId,
        ThreatCampaign campaign,
        Incident item,
        DateTimeOffset ingestedAtUtc)
    {
        var observed = ValidDate(item.LastSeen ?? item.FirstSeen ?? default, ingestedAtUtc);
        var sourceIp = CleanEndpoint(item.SourceIp);
        var destinationIp = CleanEndpoint(item.DestinationIp);
        var sourceNode = NodeId(item.SourceAgentId, item.SourceHost, sourceIp,
            $"incident-source:{campaign.CampaignId}");
        var destinationNode = NodeId(item.DestinationAgentId, item.DestinationHost, destinationIp,
            $"incident-destination:{campaign.CampaignId}");
        var evidenceId = $"incident:{item.IncidentId}:{observed.UtcTicks}";
        var observation = new ThreatObservation
        {
            TenantId = tenantId,
            CampaignId = campaign.CampaignId,
            EpisodeId = item.IncidentId,
            Kind = "correlated_incident",
            Relation = "correlated",
            ObservedAtUtc = observed,
            StartedAtUtc = ValidNullableDate(item.FirstSeen),
            EndedAtUtc = ValidNullableDate(item.LastSeen),
            IngestedAtUtc = ingestedAtUtc,
            OccurrenceCount = Math.Max(1, item.FailedAttempts + item.SuccessfulLogonCount),
            SourceNodeId = sourceNode,
            SourceIp = sourceIp,
            SourceHost = item.SourceHost,
            SourceAgentId = item.SourceAgentId,
            DestinationNodeId = destinationNode,
            DestinationIp = destinationIp,
            DestinationHost = item.DestinationHost,
            DestinationAgentId = item.DestinationAgentId,
            LocalPort = item.SourcePort,
            RemotePort = item.DestinationPort,
            Username = item.Username,
            ProcessId = item.ProcessId,
            ProcessName = item.ProcessName,
            ServiceNames = item.SourceServiceNames,
            Technique = Technique(item),
            IncidentId = item.IncidentId,
            EvidenceType = "correlated_incident",
            EvidenceId = Bound(evidenceId, 300),
            Confidence = .75,
            TimestampQuality = "incident_window_end"
        };
        CompleteKeys(observation, evidenceId);
        return observation;
    }

    private static void CompleteKeys(ThreatObservation observation, string identityMaterial)
    {
        observation.ContactId = "contact-" + StableId(
            $"{observation.TenantId}|{observation.SourceNodeId}|{observation.DestinationNodeId}|" +
            $"{observation.Relation}|{observation.Protocol}|{observation.RemotePort}|{observation.Technique}", 32);
        // Episodes are inactivity sessions, not fixed wall-clock buckets. The durable
        // store assigns them transactionally after seeing adjacent observations.
        observation.EpisodeId = null;
        observation.ObservationId = "observation-" + StableId(
            $"{observation.TenantId}|{identityMaterial}", 32);
    }

    private static Incident? FindIncident(
        SecurityEventRecord item,
        IReadOnlyCollection<Incident> incidents)
    {
        var byEvidence = incidents.FirstOrDefault(incident => incident.EvidenceEvents.Any(evidence =>
            evidence.EventRecordId > 0 && evidence.EventRecordId == item.EventRecordId &&
            (string.IsNullOrWhiteSpace(evidence.SourceIp) || EndpointEquals(evidence.SourceIp, item.SourceIp))));
        if (byEvidence is not null) return byEvidence;

        return incidents
            .Where(incident => EndpointEquals(incident.SourceIp, item.SourceIp))
            .Where(incident => string.IsNullOrWhiteSpace(incident.DestinationHost) ||
                               string.Equals(incident.DestinationHost, item.ComputerName, StringComparison.OrdinalIgnoreCase))
            .Where(incident => Within(item.TimestampUtc, incident.FirstSeen, incident.LastSeen, TimeSpan.FromMinutes(5)))
            .OrderBy(incident => Distance(item.TimestampUtc, incident.LastSeen ?? incident.FirstSeen))
            .FirstOrDefault();
    }

    private static Incident? FindNearestIncident(
        NetworkConnectionRecord item,
        IReadOnlyCollection<Incident> incidents,
        ThreatCampaign campaign) =>
        incidents
            .Where(incident => campaign.RelatedIncidentIds.Contains(incident.IncidentId, StringComparer.OrdinalIgnoreCase))
            .Where(incident => EndpointEquals(incident.SourceIp, item.LocalAddress) ||
                               EndpointEquals(incident.DestinationIp, item.RemoteAddress) ||
                               string.Equals(incident.SourceAgentId, item.AgentId, StringComparison.OrdinalIgnoreCase))
            .Where(incident => Within(item.TimestampUtc, incident.FirstSeen, incident.LastSeen, TimeSpan.FromMinutes(10)))
            .OrderBy(incident => Distance(item.TimestampUtc, incident.LastSeen ?? incident.FirstSeen))
            .FirstOrDefault();

    private static ThreatCampaign? FindCampaign(
        IReadOnlyCollection<CampaignContext> contexts,
        string? sourceIp,
        string? destinationIp,
        string? sourceHost,
        string? destinationHost,
        string? agentId,
        DateTimeOffset observedAtUtc)
    {
        return contexts
            .Select(context => new
            {
                context.Campaign,
                Score = context.Score(sourceIp, destinationIp, sourceHost, destinationHost, agentId),
                Dimensions = context.EvidenceDimensions(sourceIp, destinationIp, sourceHost, destinationHost, agentId),
                Distance = Distance(observedAtUtc, context.Campaign.LastSeenUtc)
            })
            // A shared NAT/proxy IP is never sufficient. Require two independent
            // endpoint/host/agent dimensions unless an incident relation selected
            // the campaign directly before this fallback matcher.
            .Where(item => item.Dimensions >= 2)
            .Where(item => Within(observedAtUtc, item.Campaign.FirstSeenUtc, item.Campaign.LastSeenUtc,
                TimeSpan.FromMinutes(60)))
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Distance)
            .Select(item => item.Campaign)
            .FirstOrDefault();
    }

    private static int SharedEvidenceDimensions(ThreatObservation left, ThreatObservation right)
    {
        var leftIdentities = CandidateEndpointIdentities(left);
        return CandidateEndpointIdentities(right).Count(leftIdentities.Contains);
    }

    private static string CandidateContextKey(ThreatObservation item) =>
        string.Compare(item.SourceNodeId, item.DestinationNodeId, StringComparison.Ordinal) <= 0
            ? $"{item.SourceNodeId}|{item.DestinationNodeId}"
            : $"{item.DestinationNodeId}|{item.SourceNodeId}";

    private async Task DowngradeUncorroboratedRecurrenceAsync(
        string tenantId,
        ThreatObservation seed,
        DateTimeOffset updatedAtUtc,
        CancellationToken cancellationToken)
    {
        var campaignId = "recurrence-" + StableId(
            $"{tenantId}|{CandidateContextKey(seed)}", 32);
        var existing = await _store.GetThreatCampaignV2SummaryAsync(
            tenantId, campaignId, cancellationToken);
        if (existing is null || existing.RelatedIncidentCount > 0 ||
            (!string.Equals(existing.Status, "Open", StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(existing.Status, "Investigating", StringComparison.OrdinalIgnoreCase)))
            return;

        existing.Status = "Candidate";
        existing.Severity = "Informational";
        existing.Confidence = Math.Min(existing.Confidence ?? .5, .79);
        existing.Title = "Repeated contact candidate";
        existing.Summary = "Repeated telemetry lacks a stable source or destination identity; retained as an inferred candidate and excluded from active threats until corroborated.";
        existing.UpdatedAtUtc = updatedAtUtc;
        await _store.UpsertThreatCampaignV2SummaryAsync(existing, cancellationToken);
    }

    private static bool HasStableEndpointContext(ThreatObservation item)
    {
        if (!HasStableNode(item.SourceNodeId) || !HasStableNode(item.DestinationNodeId))
            return false;

        // A node id alone is not evidence: require at least one concrete
        // identity on each side so a generated fallback id cannot become the
        // key for a recurrence campaign.
        return HasConcreteIdentity(item.SourceIp, item.SourceHost, item.SourceAgentId) &&
               HasConcreteIdentity(item.DestinationIp, item.DestinationHost, item.DestinationAgentId);

        static bool HasStableNode(string? nodeId) =>
            !string.IsNullOrWhiteSpace(nodeId) &&
            !nodeId.StartsWith("unknown-", StringComparison.OrdinalIgnoreCase);

        static bool HasConcreteIdentity(params string?[] values) =>
            values.Any(value => !string.IsNullOrWhiteSpace(value));
    }

    private static HashSet<string> CandidateEndpointIdentities(ThreatObservation item)
    {
        var values = new[]
        {
            Prefix("node", item.SourceNodeId), Prefix("node", item.DestinationNodeId),
            Prefix("ip", item.SourceIp), Prefix("ip", item.DestinationIp),
            Prefix("host", item.SourceHost), Prefix("host", item.DestinationHost),
            Prefix("agent", item.SourceAgentId), Prefix("agent", item.DestinationAgentId)
        };
        return values.Where(value => value is not null).Select(value => value!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        static string? Prefix(string kind, string? value) => string.IsNullOrWhiteSpace(value)
            ? null
            : $"{kind}:{value.Trim()}";
    }

    private static HashSet<string> CandidateEvidenceCategories(
        IReadOnlyCollection<ThreatObservation> candidates)
    {
        var categories = candidates.Select(item => item.EvidenceType.ToLowerInvariant() switch
            {
                "network_connection" => "network",
                "detection_alert" => "detection",
                "security_event" => "security_event",
                var value when value.Contains("incident", StringComparison.Ordinal) => "incident",
                _ => "other"
            })
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Process/user context from a non-network source is corroboration. Routine
        // socket process metadata alone must not turn periodic traffic malicious.
        if (candidates.Any(item => !string.Equals(item.EvidenceType, "network_connection", StringComparison.OrdinalIgnoreCase) &&
                                   (item.ProcessId.HasValue || !string.IsNullOrWhiteSpace(item.ProcessName))))
            categories.Add("process_context");
        if (candidates.Any(item => !string.Equals(item.EvidenceType, "network_connection", StringComparison.OrdinalIgnoreCase) &&
                                   !string.IsNullOrWhiteSpace(item.Username)))
            categories.Add("identity_context");
        return categories;
    }

    private static string NodeId(string? agentId, string? host, string? ip, string fallback)
    {
        var (kind, value) = !string.IsNullOrWhiteSpace(agentId)
            ? ("agent", agentId)
            : !string.IsNullOrWhiteSpace(host)
                ? ("host", host)
                : !string.IsNullOrWhiteSpace(ip)
                    ? ("ip", ip)
                    : ("unknown", fallback);
        return $"{kind}-{StableId(value!.Trim().ToLowerInvariant(), 24)}";
    }

    private static string Technique(Incident? incident, string? fallback = null)
    {
        var rule = incident?.RuleId;
        if (string.IsNullOrWhiteSpace(rule)) rule = fallback;
        return string.IsNullOrWhiteSpace(rule)
            ? "observed_activity"
            : rule.Trim().ToLowerInvariant().Replace(' ', '_');
    }

    private static string StableId(string material, int length)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash).ToLowerInvariant()[..Math.Clamp(length, 8, 64)];
    }

    private static bool IsUsable(ThreatObservation item) =>
        !string.IsNullOrWhiteSpace(item.ObservationId) &&
        !string.IsNullOrWhiteSpace(item.ContactId) &&
        !string.IsNullOrWhiteSpace(item.SourceNodeId) &&
        !string.IsNullOrWhiteSpace(item.DestinationNodeId);

    private static ClockCorrection ResolveClockCorrection(
        double? measuredSkewSeconds,
        DateTimeOffset? measuredAtUtc,
        DateTimeOffset ingestedAtUtc)
    {
        if (!measuredSkewSeconds.HasValue || !measuredAtUtc.HasValue)
            return new ClockCorrection(null, "clock_skew_missing");
        if (!double.IsFinite(measuredSkewSeconds.Value) || Math.Abs(measuredSkewSeconds.Value) > 86_400)
            return new ClockCorrection(null, "clock_skew_invalid");
        var age = ingestedAtUtc.ToUniversalTime() - measuredAtUtc.Value.ToUniversalTime();
        if (age < TimeSpan.FromMinutes(-5) || age > TimeSpan.FromHours(24))
            return new ClockCorrection(null, "clock_skew_stale");
        return new ClockCorrection(measuredSkewSeconds.Value, "clock_corrected");
    }

    private static ThreatObservation ApplyClockCorrection(
        ThreatObservation observation,
        ClockCorrection correction)
    {
        var raw = observation.ObservedAtUtc.ToUniversalTime();
        observation.RawObservedAtUtc = raw;
        observation.ClockSkewSeconds = correction.OffsetSeconds.HasValue
            ? Math.Round(correction.OffsetSeconds.Value, 3)
            : null;
        var offset = correction.OffsetSeconds ?? 0;
        observation.ObservedAtUtc = raw.AddSeconds(-offset);
        if (observation.StartedAtUtc.HasValue && correction.OffsetSeconds.HasValue)
            observation.StartedAtUtc = observation.StartedAtUtc.Value.ToUniversalTime().AddSeconds(-offset);
        if (observation.EndedAtUtc.HasValue && correction.OffsetSeconds.HasValue)
            observation.EndedAtUtc = observation.EndedAtUtc.Value.ToUniversalTime().AddSeconds(-offset);
        observation.TimestampQuality = Bound(
            observation.TimestampQuality + "_" + correction.Quality, 64);
        return observation;
    }

    private readonly record struct ClockCorrection(double? OffsetSeconds, string Quality);

    private static string NormalizeTenant(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? "default" : tenantId.Trim().ToLowerInvariant();

    private static string Bound(string? value, int maxLength)
    {
        var clean = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    private static DateTimeOffset ValidDate(DateTimeOffset value, params DateTimeOffset[] fallbacks)
    {
        if (value != default && value != DateTimeOffset.MinValue) return value.ToUniversalTime();
        return fallbacks.FirstOrDefault(item => item != default && item != DateTimeOffset.MinValue).ToUniversalTime();
    }

    private static DateTimeOffset? ValidNullableDate(DateTimeOffset? value) =>
        value.HasValue && value.Value != default && value.Value != DateTimeOffset.MinValue
            ? value.Value.ToUniversalTime()
            : null;

    private static bool EndpointEquals(string? left, string? right) =>
        !string.IsNullOrWhiteSpace(left) && !string.IsNullOrWhiteSpace(right) &&
        string.Equals(CleanEndpoint(left), CleanEndpoint(right), StringComparison.OrdinalIgnoreCase);

    private static string? CleanEndpoint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "-" or "::" or "0.0.0.0") return null;
        return value.Trim();
    }

    private static bool Within(
        DateTimeOffset value,
        DateTimeOffset? first,
        DateTimeOffset? last,
        TimeSpan tolerance)
    {
        var normalized = ValidDate(value, DateTimeOffset.UtcNow);
        var start = ValidDate(first ?? default, last ?? default, normalized);
        var end = ValidDate(last ?? default, start);
        return normalized >= start - tolerance && normalized <= end + tolerance;
    }

    private static TimeSpan Distance(DateTimeOffset value, DateTimeOffset? other) =>
        other.HasValue ? (value - other.Value).Duration() : TimeSpan.MaxValue;

    private sealed class CampaignContext
    {
        public required ThreatCampaign Campaign { get; init; }
        public required HashSet<string> Ips { get; init; }
        public required HashSet<string> Hosts { get; init; }
        public required HashSet<string> AgentIds { get; init; }

        public static CampaignContext Create(ThreatCampaign campaign) => new()
        {
            Campaign = campaign,
            Ips = campaign.InvolvedIps.Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase),
            Hosts = campaign.InvolvedHosts.Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase),
            AgentIds = campaign.Hops.SelectMany(hop => new[] { hop.FromAgentId, hop.ToAgentId })
                .Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
        };

        public int Score(
            string? sourceIp,
            string? destinationIp,
            string? sourceHost,
            string? destinationHost,
            string? agentId)
        {
            var score = 0;
            if (!string.IsNullOrWhiteSpace(sourceIp) && Ips.Contains(sourceIp)) score += 4;
            if (!string.IsNullOrWhiteSpace(destinationIp) && Ips.Contains(destinationIp)) score += 4;
            if (!string.IsNullOrWhiteSpace(sourceHost) && Hosts.Contains(sourceHost)) score += 3;
            if (!string.IsNullOrWhiteSpace(destinationHost) && Hosts.Contains(destinationHost)) score += 3;
            if (!string.IsNullOrWhiteSpace(agentId) && AgentIds.Contains(agentId)) score += 2;
            return score;
        }

        public int EvidenceDimensions(
            string? sourceIp,
            string? destinationIp,
            string? sourceHost,
            string? destinationHost,
            string? agentId)
        {
            var dimensions = 0;
            if (!string.IsNullOrWhiteSpace(sourceIp) && Ips.Contains(sourceIp)) dimensions++;
            if (!string.IsNullOrWhiteSpace(destinationIp) && Ips.Contains(destinationIp) &&
                !string.Equals(sourceIp, destinationIp, StringComparison.OrdinalIgnoreCase)) dimensions++;
            if ((!string.IsNullOrWhiteSpace(sourceHost) && Hosts.Contains(sourceHost)) ||
                (!string.IsNullOrWhiteSpace(destinationHost) && Hosts.Contains(destinationHost))) dimensions++;
            if (!string.IsNullOrWhiteSpace(agentId) && AgentIds.Contains(agentId)) dimensions++;
            return dimensions;
        }
    }
}
