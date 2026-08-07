using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Correlation;

/// <summary>
/// Correlates destination auth events with source host outbound process/service context.
/// Produces analyst-facing incidents with process/service attribution.
/// </summary>
public sealed class CrossHostCorrelator
{
    private readonly ICentralStore _store;
    private readonly CorrelationOptions _options;
    private readonly ILogger<CrossHostCorrelator> _logger;

    public CrossHostCorrelator(
        ICentralStore store,
        IOptions<CorrelationOptions> options,
        ILogger<CrossHostCorrelator> logger)
    {
        _store = store;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<IReadOnlyList<Incident>> CorrelateAsync(AgentIngestBatch batch, CancellationToken cancellationToken)
    {
        var incidents = new List<Incident>();
        incidents.AddRange(BuildAlertIncidents(batch));
        var authEvents = batch.SecurityEvents
            .Where(e => e.EventId is 4624 or 4625 or 4672)
            .Where(e => !string.IsNullOrWhiteSpace(e.SourceIp))
            .ToList();

        // Also build local-only spray incidents from this batch (destination agent view).
        incidents.AddRange(BuildLocalSprayIncidents(batch));

        if (authEvents.Count == 0)
        {
            return incidents;
        }

        var tolerance = TimeSpan.FromSeconds(Math.Max(30, _options.TimestampToleranceSeconds));

        foreach (var group in authEvents.GroupBy(e => $"{e.SourceIp}|{e.ComputerName}"))
        {
            var list = group.OrderBy(e => e.TimestampUtc).ToList();
            var sample = list[0];
            var sourceIp = sample.SourceIp!;
            var from = list.Min(e => e.TimestampUtc) - tolerance;
            var to = list.Max(e => e.TimestampUtc) + tolerance;

            IReadOnlyList<NetworkConnectionRecord> outbound;
            try
            {
                var destinationIp = GuessLocalIp(batch) ?? sample.DestinationIp ?? string.Empty;
                outbound = string.IsNullOrWhiteSpace(destinationIp)
                    ? Array.Empty<NetworkConnectionRecord>()
                    : await _store.FindOutboundAsync(destinationIp, sample.DestinationPort, from, to);

                if (!string.IsNullOrWhiteSpace(sourceIp) && outbound.Count > 0)
                {
                    var filtered = outbound
                        .Where(o => string.Equals(o.LocalAddress, sourceIp, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (filtered.Count > 0)
                    {
                        outbound = filtered;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Correlation outbound lookup failed");
                outbound = Array.Empty<NetworkConnectionRecord>();
            }

            var batchOutbound = batch.NetworkConnections
                .Where(n => n.IsNew)
                .Where(n => string.Equals(n.LocalAddress, sourceIp, StringComparison.OrdinalIgnoreCase)
                            || string.Equals(n.RemoteAddress, GuessLocalIp(batch), StringComparison.OrdinalIgnoreCase))
                .ToList();

            var best = outbound.Concat(batchOutbound)
                .OrderByDescending(o => o.TimestampUtc)
                .FirstOrDefault();

            var failed = list.Count(e => e.EventId == 4625);
            var success = list.Count(e => e.EventId == 4624);
            var privileged = list.Any(e => e.EventId == 4672);
            var distinctUsers = list
                .Select(e => e.Username)
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            if (failed < 5 && best is null)
            {
                continue;
            }

            var severity = privileged || (failed >= 20 && success > 0)
                ? Severity.Critical
                : failed >= 20
                    ? Severity.High
                    : Severity.Medium;

            var title = success > 0
                ? "Password Spray Then Success"
                : distinctUsers >= 5
                    ? "Internal Password Spray"
                    : "Cross-host Authentication Activity";

            var keyMaterial = $"{sourceIp}|{sample.ComputerName}|{best?.ProcessId}|{failed}";
            var correlationKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyMaterial))).ToLowerInvariant()[..24];

            var services = SplitServices(best?.ServiceNames);
            var incident = new Incident
            {
                IncidentId = correlationKey,
                Title = title,
                RuleId = success > 0 ? "SPRAY_THEN_SUCCESS" : "INTERNAL_PASSWORD_SPRAY",
                Severity = severity,
                CorrelationKey = correlationKey,
                SourceIp = sourceIp,
                SourceHost = best?.ComputerName,
                SourceAgentId = best?.AgentId,
                SourcePort = best?.LocalPort ?? sample.SourcePort,
                DestinationIp = GuessLocalIp(batch) ?? sample.DestinationIp,
                DestinationHost = sample.ComputerName,
                DestinationAgentId = sample.AgentId,
                DestinationPort = sample.DestinationPort ?? best?.RemotePort,
                ProcessName = best?.ProcessName,
                ProcessId = best?.ProcessId is > 0 ? best.ProcessId : null,
                ProcessPath = best?.ProcessPath,
                ProcessCommandLine = best?.ProcessCommandLine,
                ExecutableSha256 = best?.ExecutableSha256,
                Services = services,
                ServiceAccount = null,
                Username = sample.Username,
                Domain = sample.Domain,
                LogonProcess = sample.LogonProcess,
                LogonType = sample.LogonType,
                AuthenticationPackage = sample.AuthenticationPackage,
                FailedAttempts = failed,
                DistinctUsernames = distinctUsers,
                SuccessfulLoginDetected = success > 0,
                SuccessfulLogonCount = success,
                PrivilegedLogon = privileged,
                FirstSeen = list.Min(e => e.TimestampUtc),
                LastSeen = list.Max(e => e.TimestampUtc),
                Description = $"{title}: {sourceIp} -> {sample.ComputerName}",
                EvidenceEvents = list.Take(50).Select(e => new EvidenceEventSummary
                {
                    EventId = e.EventId,
                    TimestampUtc = e.TimestampUtc,
                    Username = e.Username,
                    SourceIp = e.SourceIp,
                    Status = e.Status,
                    EventRecordId = e.EventRecordId
                }).ToList(),
                EvidenceJson = JsonSerializer.Serialize(new
                {
                    auth = list.Take(30),
                    source = best
                }),
                Status = "Open"
            };

            // Prefer destination port from outbound remote port when auth lacks it
            if (incident.DestinationPort is null or 0 && best is not null)
            {
                incident.DestinationPort = best.RemotePort;
            }

            incidents.Add(incident);
        }

        return Dedup(incidents);
    }

    private static IEnumerable<Incident> BuildAlertIncidents(AgentIngestBatch batch)
    {
        foreach (var alert in batch.Alerts)
        {
            var id = "alert-" + alert.AlertId;
            yield return new Incident
            {
                IncidentId = id,
                Title = alert.Title,
                RuleId = alert.RuleId,
                Severity = alert.Severity,
                SourceHost = alert.ComputerName,
                SourceAgentId = alert.AgentId,
                ProcessPath = alert.FilePath,
                ExecutableSha256 = alert.FileSha256,
                FirstSeen = alert.TimestampUtc,
                LastSeen = alert.TimestampUtc,
                Description = alert.Description,
                IncidentScore = alert.IncidentScore,
                DetectionStage = alert.DetectionStage,
                Features = new Dictionary<string, double>(alert.Features),
                AssetId = alert.AssetId ?? alert.ComputerName,
                ObserveBaseline = alert.ObserveBaseline,
                EvidenceJson = alert.EvidenceJson,
                CorrelationKey = id,
                Status = "Open",
                Context = new Dictionary<string, object?>
                {
                    ["filePath"] = alert.FilePath,
                    ["fileSha256"] = alert.FileSha256,
                    ["detectionStage"] = alert.DetectionStage,
                    ["incidentScore"] = alert.IncidentScore
                }
            };
        }
    }

    private static List<Incident> BuildLocalSprayIncidents(AgentIngestBatch batch)
    {
        var fails = batch.SecurityEvents.Where(e => e.EventId == 4625).ToList();
        if (fails.Count < 20)
        {
            return [];
        }

        var bySource = fails.GroupBy(e => e.SourceIp ?? "-");
        var list = new List<Incident>();
        foreach (var g in bySource)
        {
            var events = g.ToList();
            var users = events.Select(e => e.Username).Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (events.Count < 20 || users.Count < 5)
            {
                continue;
            }

            var sample = events[0];
            var outbound = batch.NetworkConnections
                .Where(n => string.Equals(n.LocalAddress, g.Key, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(n.RemoteAddress, GuessLocalIp(batch), StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(n => n.TimestampUtc)
                .FirstOrDefault();

            // Also accept source-side connection reports in same multi-agent batch simulation
            outbound ??= batch.NetworkConnections
                .Where(n => n.IsNew && n.ProcessId > 0)
                .OrderByDescending(n => n.TimestampUtc)
                .FirstOrDefault();

            var success = batch.SecurityEvents.Any(e =>
                e.EventId == 4624 &&
                string.Equals(e.SourceIp, g.Key, StringComparison.OrdinalIgnoreCase));

            var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"local|{g.Key}|{sample.ComputerName}|{events.Count}"))).ToLowerInvariant()[..24];

            list.Add(new Incident
            {
                IncidentId = id,
                Title = "Internal Password Spray",
                RuleId = "INTERNAL_PASSWORD_SPRAY",
                Severity = Severity.High,
                SourceIp = g.Key,
                DestinationIp = GuessLocalIp(batch) ?? sample.DestinationIp ?? sample.ComputerName,
                DestinationHost = sample.ComputerName,
                DestinationAgentId = sample.AgentId,
                DestinationPort = outbound?.RemotePort ?? sample.DestinationPort ?? 0,
                ProcessName = outbound?.ProcessName,
                ProcessId = outbound?.ProcessId is > 0 ? outbound.ProcessId : null,
                ProcessPath = outbound?.ProcessPath,
                Services = SplitServices(outbound?.ServiceNames),
                ServiceAccount = "LocalSystem",
                LogonProcess = sample.LogonProcess ?? events.Select(e => e.LogonProcess).FirstOrDefault(x => !string.IsNullOrEmpty(x)),
                LogonType = sample.LogonType ?? events.Select(e => e.LogonType).FirstOrDefault(x => x.HasValue),
                FailedAttempts = events.Count,
                DistinctUsernames = users.Count,
                SuccessfulLoginDetected = success,
                FirstSeen = events.Min(e => e.TimestampUtc),
                LastSeen = events.Max(e => e.TimestampUtc),
                EvidenceEvents = events.Take(50).Select(e => new EvidenceEventSummary
                {
                    EventId = e.EventId,
                    TimestampUtc = e.TimestampUtc,
                    Username = e.Username,
                    SourceIp = e.SourceIp,
                    Status = e.Status,
                    EventRecordId = e.EventRecordId
                }).ToList(),
                Status = "Open"
            });
        }

        return list;
    }

    private static List<string> SplitServices(string? names) =>
        string.IsNullOrWhiteSpace(names)
            ? []
            : names.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static string? GuessLocalIp(AgentIngestBatch batch) =>
        batch.NetworkConnections
            .Select(n => n.LocalAddress)
            .FirstOrDefault(a => !string.IsNullOrWhiteSpace(a) && a is not "127.0.0.1" and not "0.0.0.0" and not "::1");

    private static List<Incident> Dedup(List<Incident> incidents) =>
        incidents
            .GroupBy(i => i.IncidentId)
            .Select(g => g.OrderByDescending(x => x.FailedAttempts).First())
            .ToList();
}
