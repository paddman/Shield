using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NTShield.Server.Data;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Correlation;

/// <summary>
/// Tracks threat progression across hosts (A → B → C).
/// Investigation aid only — does not initiate connections or attacks.
/// </summary>
public sealed class LateralMovementTracker
{
    private const int MaxMlHistoryPerCampaign = 48;
    private const int MaxSummaryHops = 8;
    private readonly CorrelationOptions _options;
    private readonly ILogger<LateralMovementTracker> _logger;
    private readonly ICentralStore _store;
    private readonly ConcurrentDictionary<string, ThreatCampaign> _campaigns = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, List<string>> _ipToCampaigns = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private int _loaded;

    public LateralMovementTracker(
        IOptions<CorrelationOptions> options,
        ILogger<LateralMovementTracker> logger,
        ICentralStore store)
    {
        _options = options.Value;
        _logger = logger;
        _store = store;
    }

    public async Task LoadAsync()
    {
        if (Interlocked.Exchange(ref _loaded, 1) == 1) return;
        try
        {
            var rows = await _store.ListCampaignJsonAsync(200);
            foreach (var (_, json) in rows)
            {
                var c = JsonSerializer.Deserialize<ThreatCampaign>(json, JsonOptions);
                if (c is null || string.IsNullOrWhiteSpace(c.CampaignId)) continue;
                _campaigns[c.CampaignId] = c;
                foreach (var ip in c.InvolvedIps)
                    IndexIp(ip, c.CampaignId);
            }

            // Campaign persistence was added after incidents. Rebuild the in-memory
            // view once when an older database has incidents but no campaign rows.
            // This keeps the Threat Campaigns page useful after upgrading without
            // waiting for a new alert to arrive.
            if (_campaigns.IsEmpty)
            {
                var incidents = await _store.ListIncidentsAsync(500);
                foreach (var incident in incidents)
                {
                    var campaign = MergeIncident(incident);
                    if (campaign is not null)
                    {
                        Persist(campaign);
                    }
                }

                LinkPivotChains();
                _logger.LogInformation("Rebuilt {Count} threat campaigns from persisted incidents", _campaigns.Count);
            }

            _logger.LogInformation("Loaded {Count} threat campaigns from durable store", _campaigns.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not load durable threat campaigns");
        }
    }

    public IReadOnlyList<ThreatCampaign> IngestIncidents(IEnumerable<Incident> incidents)
    {
        _ = LoadAsync(); // fire-and-forget ensure load
        var updated = new List<ThreatCampaign>();
        foreach (var incident in incidents)
        {
            var campaign = MergeIncident(incident);
            if (campaign is not null)
            {
                updated.Add(campaign);
                Persist(campaign);
            }
        }

        // Second pass: link hop chains when a destination later becomes a source
        LinkPivotChains();
        return updated
            .GroupBy(c => c.CampaignId)
            .Select(g => g.Last())
            .OrderByDescending(c => c.LastSeenUtc)
            .ToList();
    }

    private void Persist(ThreatCampaign campaign)
    {
        try
        {
            var json = JsonSerializer.Serialize(campaign, JsonOptions);
            _ = _store.UpsertCampaignJsonAsync(campaign.CampaignId, json);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to persist campaign {Id}", campaign.CampaignId);
        }
    }

    public IReadOnlyList<ThreatCampaign> ListCampaigns(int take = 100) =>
        _campaigns.Values
            .OrderByDescending(c => c.LastSeenUtc)
            .Take(Math.Clamp(take, 1, 500))
            .ToList();

    public ThreatCampaign? GetCampaign(string id) =>
        _campaigns.TryGetValue(id, out var c) ? c : null;

    /// <summary>
    /// Find campaigns that touch a given IP or host (track threat onto other machines).
    /// </summary>
    public IReadOnlyList<ThreatCampaign> FindByHostOrIp(string hostOrIp)
    {
        if (string.IsNullOrWhiteSpace(hostOrIp))
        {
            return [];
        }

        return _campaigns.Values
            .Where(c =>
                c.InvolvedIps.Any(ip => string.Equals(ip, hostOrIp, StringComparison.OrdinalIgnoreCase)) ||
                c.InvolvedHosts.Any(h => string.Equals(h, hostOrIp, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(c => c.LastSeenUtc)
            .ToList();
    }

    public IReadOnlyList<ThreatCatalogEntry> GetThreatCatalog() => ThreatCatalog.All;

    /// <summary>
    /// Attach the latest anomaly observation to campaigns touching an agent.
    /// This enriches durable campaign JSON only; it never triggers a response.
    /// </summary>
    public int ApplyAnomaly(
        string agentId,
        double score,
        double confidence,
        int baselineSamples,
        string model,
        DateTimeOffset observedAtUtc,
        IEnumerable<string>? signals = null)
    {
        if (string.IsNullOrWhiteSpace(agentId)) return 0;

        var cleanSignals = (signals ?? [])
            .Where(signal => !string.IsNullOrWhiteSpace(signal))
            .Select(signal => signal.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToList();
        var updated = 0;
        lock (_sync)
        {
            foreach (var campaign in _campaigns.Values.Where(c => c.Hops.Any(h =>
                         string.Equals(h.FromAgentId, agentId, StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(h.ToAgentId, agentId, StringComparison.OrdinalIgnoreCase))))
            {
                campaign.MlScore = Math.Clamp(score, 0, 1);
                campaign.MlConfidence = Math.Clamp(confidence, 0, 1);
                campaign.MlBaselineSamples = Math.Max(0, baselineSamples);
                campaign.MlModel = string.IsNullOrWhiteSpace(model) ? null : model.Trim();
                campaign.MlObservedAtUtc = observedAtUtc;
                campaign.MlSignals = cleanSignals;
                campaign.MlHistory ??= [];
                var observation = new ThreatMlObservation
                {
                    ObservedAtUtc = observedAtUtc,
                    Score = campaign.MlScore.Value,
                    Confidence = campaign.MlConfidence.Value,
                    BaselineSamples = campaign.MlBaselineSamples.Value,
                    Model = campaign.MlModel ?? string.Empty,
                    Signals = [.. cleanSignals]
                };
                var existing = campaign.MlHistory.FindIndex(item => item.ObservedAtUtc == observedAtUtc);
                if (existing >= 0)
                    campaign.MlHistory[existing] = observation;
                else
                    campaign.MlHistory.Add(observation);

                campaign.MlHistory = campaign.MlHistory
                    .OrderBy(item => item.ObservedAtUtc)
                    .TakeLast(MaxMlHistoryPerCampaign)
                    .ToList();
                Persist(campaign);
                updated++;
            }
        }

        if (updated > 0)
        {
            _logger.LogInformation(
                "ML anomaly attached to {Campaigns} campaign(s) agent={AgentId} score={Score} baseline={Baseline}",
                updated, agentId, score, baselineSamples);
        }

        return updated;
    }

    private ThreatCampaign? MergeIncident(Incident incident)
    {
        var fromIp = incident.SourceIp;
        var toIp = incident.DestinationIp ?? incident.DestinationHost;
        if (string.IsNullOrWhiteSpace(fromIp) && string.IsNullOrWhiteSpace(toIp))
        {
            return null;
        }

        var hop = new ThreatHop
        {
            TimestampUtc = incident.LastSeen ?? incident.FirstSeen ?? DateTimeOffset.UtcNow,
            FromIp = fromIp,
            FromHost = incident.SourceHost,
            FromAgentId = incident.SourceAgentId,
            ToIp = toIp,
            ToHost = incident.DestinationHost,
            ToAgentId = incident.DestinationAgentId,
            Port = incident.DestinationPort,
            Technique = MapTechnique(incident),
            Username = incident.Username,
            LogonType = incident.LogonType,
            ProcessId = incident.ProcessId,
            ProcessName = incident.ProcessName,
            ProcessPath = incident.ProcessPath,
            ServiceNames = incident.SourceServiceNames,
            IncidentId = incident.IncidentId,
            Evidence = $"{incident.RuleId}; failed={incident.FailedAttempts}; success={incident.SuccessfulLoginDetected}"
        };

        // Prefer existing campaign sharing source or destination IP within time window
        ThreatCampaign? campaign = null;
        lock (_sync)
        {
            campaign = FindRelatedCampaign(fromIp, toIp, hop.TimestampUtc);
            if (campaign is null)
            {
                campaign = new ThreatCampaign
                {
                    CampaignId = ShortId($"{fromIp}|{toIp}|{incident.RuleId}|{hop.TimestampUtc:yyyyMMddHH}"),
                    Title = BuildTitle(incident),
                    Severity = incident.Severity,
                    FirstSeenUtc = incident.FirstSeen ?? hop.TimestampUtc,
                    LastSeenUtc = hop.TimestampUtc,
                    Status = "Open"
                };
                _campaigns[campaign.CampaignId] = campaign;
            }

            campaign.LastSeenUtc = Max(campaign.LastSeenUtc, hop.TimestampUtc);
            campaign.FirstSeenUtc = Min(campaign.FirstSeenUtc, incident.FirstSeen ?? hop.TimestampUtc);
            if (incident.Severity > campaign.Severity)
            {
                campaign.Severity = incident.Severity;
            }

            AddUnique(campaign.RelatedIncidentIds, incident.IncidentId);
            AddUnique(campaign.InvolvedIps, fromIp);
            AddUnique(campaign.InvolvedIps, toIp);
            AddUnique(campaign.InvolvedHosts, incident.SourceHost);
            AddUnique(campaign.InvolvedHosts, incident.DestinationHost);
            AddUnique(campaign.InvolvedUsernames, incident.Username);
            AddUnique(campaign.ThreatCategories, MapCategory(incident));

            if (!campaign.Hops.Any(h =>
                    h.IncidentId == hop.IncidentId ||
                    (h.FromIp == hop.FromIp && h.ToIp == hop.ToIp && h.Technique == hop.Technique &&
                     Math.Abs((h.TimestampUtc - hop.TimestampUtc).TotalSeconds) < 30)))
            {
                campaign.Hops.Add(hop);
                campaign.Hops = campaign.Hops.OrderBy(h => h.TimestampUtc).ToList();
            }

            campaign.Title = campaign.Hops.Count > 1
                ? $"Lateral movement chain ({campaign.Hops.Count} hops)"
                : BuildTitle(incident);
            campaign.Summary = BuildSummary(campaign);

            IndexIp(fromIp, campaign.CampaignId);
            IndexIp(toIp, campaign.CampaignId);
        }

        _logger.LogWarning(
            "Threat path updated campaign={CampaignId} severity={Severity} hops={Hops} hosts={Hosts} ips={Ips} summary={Summary}",
            campaign.CampaignId,
            campaign.Severity,
            campaign.Hops.Count,
            campaign.InvolvedHosts.Count,
            campaign.InvolvedIps.Count,
            campaign.Summary);
        return campaign;
    }

    private void LinkPivotChains()
    {
        lock (_sync)
        {
            // If campaign1 ends at IP X and campaign2 starts at X within tolerance, merge into campaign1
            var list = _campaigns.Values.OrderBy(c => c.FirstSeenUtc).ToList();
            var tolerance = TimeSpan.FromMinutes(Math.Max(5, _options.TimestampToleranceSeconds / 60.0 * 5));

            for (var i = 0; i < list.Count; i++)
            {
                for (var j = i + 1; j < list.Count; j++)
                {
                    var a = list[i];
                    var b = list[j];
                    if (a.CampaignId == b.CampaignId)
                    {
                        continue;
                    }

                    var aEnds = a.Hops.Select(h => h.ToIp).Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    var bStarts = b.Hops.Select(h => h.FromIp).Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if (!aEnds.Overlaps(bStarts))
                    {
                        continue;
                    }

                    if (b.FirstSeenUtc < a.FirstSeenUtc - tolerance || b.FirstSeenUtc > a.LastSeenUtc + tolerance)
                    {
                        continue;
                    }

                    // Merge b into a
                    foreach (var hop in b.Hops)
                    {
                        if (a.Hops.All(h => h.IncidentId != hop.IncidentId))
                        {
                            a.Hops.Add(hop);
                        }
                    }

                    a.Hops = a.Hops.OrderBy(h => h.TimestampUtc).ToList();
                    a.LastSeenUtc = Max(a.LastSeenUtc, b.LastSeenUtc);
                    a.Severity = a.Severity >= b.Severity ? a.Severity : b.Severity;
                    foreach (var x in b.RelatedIncidentIds) AddUnique(a.RelatedIncidentIds, x);
                    foreach (var x in b.InvolvedIps) AddUnique(a.InvolvedIps, x);
                    foreach (var x in b.InvolvedHosts) AddUnique(a.InvolvedHosts, x);
                    foreach (var x in b.InvolvedUsernames) AddUnique(a.InvolvedUsernames, x);
                    foreach (var x in b.ThreatCategories) AddUnique(a.ThreatCategories, x);
                    a.Title = $"Lateral movement chain ({a.Hops.Count} hops)";
                    a.Summary = BuildSummary(a);
                    _campaigns.TryRemove(b.CampaignId, out _);
                    list[j] = a;
                    _logger.LogWarning("Merged pivot campaigns into {Id} hops={Hops}", a.CampaignId, a.Hops.Count);
                }
            }
        }
    }

    private ThreatCampaign? FindRelatedCampaign(string? fromIp, string? toIp, DateTimeOffset ts)
    {
        var window = TimeSpan.FromMinutes(60);
        foreach (var c in _campaigns.Values)
        {
            if (ts < c.FirstSeenUtc - window || ts > c.LastSeenUtc + window)
            {
                continue;
            }

            if ((!string.IsNullOrWhiteSpace(fromIp) && c.InvolvedIps.Contains(fromIp, StringComparer.OrdinalIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(toIp) && c.InvolvedIps.Contains(toIp, StringComparer.OrdinalIgnoreCase)))
            {
                return c;
            }
        }

        return null;
    }

    private void IndexIp(string? ip, string campaignId)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        _ipToCampaigns.AddOrUpdate(ip,
            _ => [campaignId],
            (_, list) =>
            {
                if (!list.Contains(campaignId, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(campaignId);
                }

                return list;
            });
    }

    private static string MapTechnique(Incident i) =>
        i.RuleId switch
        {
            "INTERNAL_PASSWORD_SPRAY" or "DISTRIBUTED_PASSWORD_SPRAY" or "SPRAY_THEN_SUCCESS" => "password_spray",
            "BRUTE_FORCE_SINGLE_ACCOUNT" => "brute_force",
            "MULTIPLE_INTERNAL_TARGETS" or "LATERAL_AUTH_PORT_SCAN" => "lateral_scan",
            "EXPLICIT_CREDENTIALS_LATERAL" => "explicit_credentials",
            "NETWORK_LOGON_BURST" => "network_logon",
            "RDP_LOGON_BURST" => "rdp",
            "PRIVILEGED_LOGON_AFTER_FAILURES" => "privilege_escalation",
            "NEW_SERVICE_INSTALLED" => "persistence_service",
            "SCHEDULED_TASK_CREATED" => "persistence_task",
            _ => string.IsNullOrEmpty(i.RuleId) ? "auth_activity" : i.RuleId.ToLowerInvariant()
        };

    private static string MapCategory(Incident i) =>
        i.RuleId switch
        {
            "INTERNAL_PASSWORD_SPRAY" or "DISTRIBUTED_PASSWORD_SPRAY" or "BRUTE_FORCE_SINGLE_ACCOUNT"
                or "SPRAY_THEN_SUCCESS" or "SUSPICIOUS_ACCOUNT_NAMES" => "credential_access",
            "MULTIPLE_INTERNAL_TARGETS" or "LATERAL_AUTH_PORT_SCAN" or "EXPLICIT_CREDENTIALS_LATERAL"
                or "NETWORK_LOGON_BURST" or "RDP_LOGON_BURST" => "lateral_movement",
            "NEW_SERVICE_INSTALLED" or "SCHEDULED_TASK_CREATED" or "ACCOUNT_CREATED" => "persistence",
            "PRIVILEGED_LOGON_AFTER_FAILURES" or "PRIVILEGED_GROUP_CHANGE" => "privilege_escalation",
            _ => "other"
        };

    private static string BuildTitle(Incident i) =>
        string.IsNullOrWhiteSpace(i.Title) ? $"Threat {i.RuleId}" : i.Title;

    private static string BuildSummary(ThreatCampaign c)
    {
        if (c.Hops.Count == 0)
        {
            return "No hops recorded.";
        }

        var ordered = c.Hops.OrderBy(h => h.TimestampUtc).ToList();
        var representative = ordered.Count <= MaxSummaryHops
            ? ordered
            : ordered.Take(MaxSummaryHops / 2)
                .Concat(ordered.TakeLast(MaxSummaryHops / 2))
                .ToList();
        var path = string.Join(" → ", representative.Select(h =>
            $"{BoundSummaryValue(h.FromIp)}»{BoundSummaryValue(h.ToIp)}"));
        var omitted = ordered.Count - representative.Count;
        var coverage = omitted > 0
            ? $"Showing {representative.Count} of {ordered.Count} hops ({omitted} omitted)"
            : $"Showing all {ordered.Count} hops";
        var categories = string.Join(", ", c.ThreatCategories
            .Take(8)
            .Select(category => BoundSummaryValue(category, 40)));
        if (c.ThreatCategories.Count > 8)
        {
            categories += $", +{c.ThreatCategories.Count - 8} more";
        }

        return $"Tracked {ordered.Count} hop(s) across {c.InvolvedIps.Count} IP(s). {coverage}: {path}. Categories: {categories}.";
    }

    private static string BoundSummaryValue(string? value, int maxLength = 64)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? "?"
            : value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength] + "…";
    }

    private static string ShortId(string material)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash).ToLowerInvariant()[..20];
    }

    private static void AddUnique(List<string> list, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            list.Add(value);
        }
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;
    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;
}

public static class ThreatCatalog
{
    public static IReadOnlyList<ThreatCatalogEntry> All { get; } =
    [
        new() { Category = "credential_access", Name = "Internal Password Spray", MitreTactic = "Credential Access", MitreTechnique = "T1110.003", DetectionRuleId = "INTERNAL_PASSWORD_SPRAY", CrossHostTracking = "Source IP process/service on origin host + 4625 on targets" },
        new() { Category = "credential_access", Name = "Distributed Password Spray", MitreTactic = "Credential Access", MitreTechnique = "T1110.003", DetectionRuleId = "DISTRIBUTED_PASSWORD_SPRAY", CrossHostTracking = "Many sources → one destination" },
        new() { Category = "credential_access", Name = "Brute Force", MitreTactic = "Credential Access", MitreTechnique = "T1110.001", DetectionRuleId = "BRUTE_FORCE_SINGLE_ACCOUNT", CrossHostTracking = "Source→dest attribution" },
        new() { Category = "credential_access", Name = "Spray Then Success", MitreTactic = "Credential Access", MitreTechnique = "T1110.003", DetectionRuleId = "SPRAY_THEN_SUCCESS", CrossHostTracking = "Failure+success chain; hop recorded for lateral follow" },
        new() { Category = "lateral_movement", Name = "Multi-target Auth Ports", MitreTactic = "Lateral Movement / Discovery", MitreTechnique = "T1021 / T1046", DetectionRuleId = "MULTIPLE_INTERNAL_TARGETS", CrossHostTracking = "Fan-out from one host to many" },
        new() { Category = "lateral_movement", Name = "Auth Port Fan-out Scan", MitreTactic = "Discovery", MitreTechnique = "T1046", DetectionRuleId = "LATERAL_AUTH_PORT_SCAN", CrossHostTracking = "Prep hop before lateral auth" },
        new() { Category = "lateral_movement", Name = "Explicit Credentials", MitreTactic = "Lateral Movement", MitreTechnique = "T1021", DetectionRuleId = "EXPLICIT_CREDENTIALS_LATERAL", CrossHostTracking = "4648 on host; correlate outbound" },
        new() { Category = "lateral_movement", Name = "Network Logon Burst", MitreTactic = "Lateral Movement", MitreTechnique = "T1021.002", DetectionRuleId = "NETWORK_LOGON_BURST", CrossHostTracking = "Type 3 success from remote" },
        new() { Category = "lateral_movement", Name = "RDP Logon Burst", MitreTactic = "Lateral Movement", MitreTechnique = "T1021.001", DetectionRuleId = "RDP_LOGON_BURST", CrossHostTracking = "Type 10/7 RDP path" },
        new() { Category = "privilege_escalation", Name = "Privileged Logon After Failures", MitreTactic = "Privilege Escalation", MitreTechnique = "T1078", DetectionRuleId = "PRIVILEGED_LOGON_AFTER_FAILURES", CrossHostTracking = "4624+4672 after spray" },
        new() { Category = "privilege_escalation", Name = "Privileged Group Change", MitreTactic = "Persistence / Privilege Escalation", MitreTechnique = "T1098", DetectionRuleId = "PRIVILEGED_GROUP_CHANGE", CrossHostTracking = "Local host; link if after lateral success" },
        new() { Category = "persistence", Name = "New Service", MitreTactic = "Persistence", MitreTechnique = "T1543.003", DetectionRuleId = "NEW_SERVICE_INSTALLED", CrossHostTracking = "Persistence after pivot" },
        new() { Category = "persistence", Name = "Scheduled Task", MitreTactic = "Persistence / Execution", MitreTechnique = "T1053.005", DetectionRuleId = "SCHEDULED_TASK_CREATED", CrossHostTracking = "Persistence after pivot" },
        new() { Category = "persistence", Name = "Account Created", MitreTactic = "Persistence", MitreTechnique = "T1136.001", DetectionRuleId = "ACCOUNT_CREATED", CrossHostTracking = "Local account after compromise" },
        new() { Category = "credential_access", Name = "Suspicious Account Names", MitreTactic = "Credential Access", MitreTechnique = "T1110", DetectionRuleId = "SUSPICIOUS_ACCOUNT_NAMES", CrossHostTracking = "Volume-gated only" }
    ];
}
