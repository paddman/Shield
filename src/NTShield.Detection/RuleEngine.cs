using System.Text.Json;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Detection.Rules;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Detection;

public sealed class RuleEngine : IDetectionEngine
{
    private readonly DetectionOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<RuleEngine> _logger;
    private List<DetectionRuleDefinition> _rules = [];
    private readonly Dictionary<string, DateTimeOffset> _cooldowns = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _seenEventKeys = new(StringComparer.Ordinal);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    public RuleEngine(
        IOptions<DetectionOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<RuleEngine> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        LoadAllowlist();
        var path = ResolvePath(_options.RulesPath, "default-rules.json", "rules.json");
        if (path is null || !File.Exists(path))
        {
            _logger.LogWarning("Rules file not found; using embedded defaults");
            _rules = BuiltInRules.Create();
            return;
        }

        await using var stream = File.OpenRead(path);
        var set = await JsonSerializer.DeserializeAsync<DetectionRuleSet>(stream, JsonOptions, cancellationToken)
                  ?? new DetectionRuleSet();
        _rules = set.Rules.Where(r => r.Enabled).ToList();
        _logger.LogInformation("Loaded {Count} detection rules from {Path}", _rules.Count, path);
    }

    private void LoadAllowlist()
    {
        var path = ResolvePath(_options.AllowlistPath, "allowlist.json");
        if (path is null || !File.Exists(path))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(path);
            var doc = JsonSerializer.Deserialize<AllowlistFile>(json, JsonOptions);
            if (doc?.Usernames is { Count: > 0 })
            {
                _options.AllowlistUsernames = _options.AllowlistUsernames.Concat(doc.Usernames).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

            if (doc?.SourceIps is { Count: > 0 })
            {
                _options.AllowlistSourceIps = _options.AllowlistSourceIps.Concat(doc.SourceIps).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load allowlist");
        }
    }

    private static string? ResolvePath(string configured, params string[] fallbacks)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            candidates.Add(Path.IsPathRooted(configured) ? configured : Path.Combine(AppContext.BaseDirectory, configured));
            candidates.Add(configured);
        }

        foreach (var f in fallbacks)
        {
            candidates.Add(Path.Combine(AppContext.BaseDirectory, f));
            candidates.Add(Path.Combine(AppContext.BaseDirectory, "config", f));
            candidates.Add(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "rules", f)));
            candidates.Add(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", f)));
        }

        return candidates.FirstOrDefault(File.Exists);
    }

    public Task<IReadOnlyList<DetectionAlert>> EvaluateAsync(
        IReadOnlyList<SecurityEventRecord> recentEvents,
        IReadOnlyList<NetworkConnectionRecord> recentConnections,
        CancellationToken cancellationToken)
    {
        // Deduplicate malformed/replayed events
        var deduped = new List<SecurityEventRecord>();
        foreach (var e in recentEvents)
        {
            var key = $"{e.EventRecordId}:{e.EventId}:{e.TimestampUtc:O}:{e.SourceIp}:{e.Username}";
            if (_seenEventKeys.Add(key))
            {
                deduped.Add(e);
            }
        }

        if (_seenEventKeys.Count > 200_000)
        {
            _seenEventKeys.Clear();
        }

        var alerts = new List<DetectionAlert>();
        var now = DateTimeOffset.UtcNow;

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IEnumerable<DetectionAlert> produced = rule.Type.ToLowerInvariant() switch
            {
                "sequence" => EvaluateSequence(rule, deduped, now),
                "network" => EvaluateNetwork(rule, recentConnections, now),
                "presence" => EvaluatePresence(rule, deduped, now),
                "process_match" => EvaluateProcessMatch(rule, deduped, now),
                "event_volume" => EvaluateEventVolume(rule, deduped, now),
                _ => EvaluateThreshold(rule, deduped, now)
            };

            foreach (var alert in produced)
            {
                if (IsAllowlisted(alert))
                {
                    alert.Suppressed = true;
                    continue;
                }

                var cdKey = $"{rule.Id}|{alert.SourceIp}|{alert.DestinationIp}|{alert.Username}";
                if (_cooldowns.TryGetValue(cdKey, out var until) && until > now)
                {
                    alert.Suppressed = true;
                    continue;
                }

                _cooldowns[cdKey] = now.AddMinutes(rule.CooldownMinutes);
                alert.CooldownUntilUtc = _cooldowns[cdKey];
                alerts.Add(alert);
            }
        }

        return Task.FromResult<IReadOnlyList<DetectionAlert>>(alerts);
    }

    private IEnumerable<DetectionAlert> EvaluateThreshold(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var scoped = FilterEvents(rule, events, windowStart, now);

        if (scoped.Count < Math.Max(1, rule.MinEventCount))
        {
            yield break;
        }

        IEnumerable<IGrouping<string, SecurityEventRecord>> groups = rule.Id switch
        {
            "INTERNAL_PASSWORD_SPRAY" => scoped.GroupBy(e => $"{Norm(e.SourceIp)}|{Norm(e.ComputerName)}"),
            "DISTRIBUTED_PASSWORD_SPRAY" => scoped.GroupBy(e => Norm(e.ComputerName)),
            "BRUTE_FORCE_SINGLE_ACCOUNT" => scoped.GroupBy(e => $"{Norm(e.SourceIp)}|{Norm(e.Username)}|{Norm(e.ComputerName)}"),
            "SUSPICIOUS_ACCOUNT_NAMES" => scoped.GroupBy(e => Norm(e.Username)),
            "NETWORK_LOGON_BURST" or "RDP_LOGON_BURST" or "SUCCESSFUL_LOGON_BURST" =>
                scoped.GroupBy(e => $"{Norm(e.SourceIp)}|{Norm(e.ComputerName)}"),
            "PROCESS_CREATION_BURST" or "FIREWALL_ALLOW_BURST" or "FIREWALL_BLOCK_BURST" =>
                scoped.GroupBy(e => Norm(e.ComputerName)),
            "WFP_CONNECTION_TO_AUTH_PORTS" => scoped.GroupBy(e => $"{Norm(e.SourceIp)}|{Norm(e.DestinationIp)}"),
            _ => scoped.GroupBy(e => $"{Norm(e.SourceIp)}|{Norm(e.Username)}|{Norm(e.ProcessPath)}|{e.EventId}")
        };

        foreach (var g in groups)
        {
            var list = g.ToList();
            var distinctUsers = list.Select(x => Norm(x.Username)).Where(x => x != "-").Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var distinctSources = list.Select(x => Norm(x.SourceIp)).Where(x => x != "-").Distinct(StringComparer.OrdinalIgnoreCase).Count();

            if (rule.MinEventCount > 0 && list.Count < rule.MinEventCount)
                continue;
            if (rule.MinDistinctUsernames > 0 && distinctUsers < rule.MinDistinctUsernames)
                continue;
            if (rule.MaxDistinctUsernames > 0 && distinctUsers > rule.MaxDistinctUsernames)
                continue;
            if (rule.MinDistinctSources > 0 && distinctSources < rule.MinDistinctSources)
                continue;

            yield return BuildAlert(rule, list, distinctUsers, 0, now);
        }
    }

    /// <summary>
    /// Presence rules: alert when N occurrences of specific event IDs appear (service install, task, account create).
    /// </summary>
    private IEnumerable<DetectionAlert> EvaluatePresence(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var scoped = FilterEvents(rule, events, windowStart, now);

        if (scoped.Count < Math.Max(1, rule.MinEventCount))
        {
            yield break;
        }

        foreach (var g in scoped.GroupBy(e =>
                     $"{e.EventId}|{Norm(e.ServiceName)}|{Norm(e.TaskName)}|{Norm(e.Username)}|{Norm(e.ProcessPath)}|{Norm(e.ComputerName)}"))
        {
            var list = g.ToList();
            if (list.Count < Math.Max(1, rule.MinEventCount))
            {
                continue;
            }

            yield return BuildAlert(rule, list, 0, 0, now);
        }
    }

    /// <summary>
    /// 4688 / process-oriented matching: path keywords or command-line tokens.
    /// </summary>
    private IEnumerable<DetectionAlert> EvaluateProcessMatch(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var scoped = FilterEvents(rule, events, windowStart, now)
            .Where(e => MatchesProcessCriteria(rule, e))
            .ToList();

        if (scoped.Count < Math.Max(1, rule.MinEventCount))
        {
            yield break;
        }

        foreach (var g in scoped.GroupBy(e => $"{Norm(e.ProcessPath)}|{Norm(e.ComputerName)}|{e.EventId}"))
        {
            var list = g.ToList();
            if (list.Count < Math.Max(1, rule.MinEventCount))
            {
                continue;
            }

            yield return BuildAlert(rule, list, 0, 0, now);
        }
    }

    /// <summary>
    /// High-volume event IDs: alert on abnormal count per host (not every single event).
    /// </summary>
    private IEnumerable<DetectionAlert> EvaluateEventVolume(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var scoped = FilterEvents(rule, events, windowStart, now);
        if (scoped.Count < Math.Max(1, rule.MinEventCount))
        {
            yield break;
        }

        foreach (var g in scoped.GroupBy(e => $"{e.EventId}|{Norm(e.ComputerName)}"))
        {
            var list = g.ToList();
            if (list.Count < Math.Max(1, rule.MinEventCount))
            {
                continue;
            }

            var distinctPaths = list.Select(x => Norm(x.ProcessPath)).Where(x => x != "-")
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (rule.MinDistinctProcessPaths > 0 && distinctPaths < rule.MinDistinctProcessPaths)
            {
                continue;
            }

            yield return BuildAlert(rule, list, 0, 0, now);
        }
    }

    private static List<SecurityEventRecord> FilterEvents(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset windowStart,
        DateTimeOffset now)
    {
        var scoped = events
            .Where(e => e.TimestampUtc >= windowStart && e.TimestampUtc <= now)
            .Where(e => rule.EventIds.Count == 0 || rule.EventIds.Contains(e.EventId))
            .Where(e => rule.LogonTypes.Count == 0 || (e.LogonType.HasValue && rule.LogonTypes.Contains(e.LogonType.Value)))
            .Where(e => rule.DestinationPorts.Count == 0 ||
                        (e.DestinationPort.HasValue && rule.DestinationPorts.Contains(e.DestinationPort.Value)))
            .ToList();

        if (rule.SuspiciousUsernames.Count > 0)
        {
            var set = new HashSet<string>(rule.SuspiciousUsernames, StringComparer.OrdinalIgnoreCase);
            scoped = scoped
                .Where(e =>
                {
                    var u = e.Username ?? e.TargetUserName;
                    return !string.IsNullOrWhiteSpace(u) && set.Contains(u!);
                })
                .ToList();
        }

        return scoped;
    }

    private static bool MatchesProcessCriteria(DetectionRuleDefinition rule, SecurityEventRecord e)
    {
        var haystack = $"{e.ProcessPath}\n{e.RawXml}\n{e.ServiceName}\n{e.TaskName}";
        if (rule.ProcessPathContains.Count == 0 && rule.CommandLineContains.Count == 0)
        {
            return true;
        }

        // OR within each list; AND between path list and cmdline list when both specified.
        var pathOk = rule.ProcessPathContains.Count == 0 ||
                     rule.ProcessPathContains.Any(p => haystack.Contains(p, StringComparison.OrdinalIgnoreCase));
        var cmdOk = rule.CommandLineContains.Count == 0 ||
                    rule.CommandLineContains.Any(p => haystack.Contains(p, StringComparison.OrdinalIgnoreCase));
        return pathOk && cmdOk;
    }

    private IEnumerable<DetectionAlert> EvaluateSequence(
        DetectionRuleDefinition rule,
        IReadOnlyList<SecurityEventRecord> events,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var scoped = events.Where(e => e.TimestampUtc >= windowStart && e.TimestampUtc <= now).ToList();
        var failures = scoped.Where(e => e.EventId == rule.FailureEventId).ToList();
        var successes = scoped.Where(e => e.EventId == rule.SuccessEventId).ToList();
        var privs = rule.PrivilegeEventId > 0
            ? scoped.Where(e => e.EventId == rule.PrivilegeEventId).ToList()
            : [];

        foreach (var success in successes)
        {
            var relatedFailures = failures.Where(f => Matches(rule, f, success)).ToList();
            if (relatedFailures.Count < Math.Max(1, rule.MinFailures))
            {
                continue;
            }

            if (rule.PrivilegeEventId > 0)
            {
                var hasPriv = privs.Any(p =>
                    p.TimestampUtc >= success.TimestampUtc.AddMinutes(-2) &&
                    p.TimestampUtc <= success.TimestampUtc.AddMinutes(2));
                if (!hasPriv)
                {
                    continue;
                }
            }

            var evidence = relatedFailures.Concat(new[] { success }).Concat(privs.Take(3)).ToList();
            yield return BuildAlert(rule, evidence, 1, 0, now);
        }
    }

    private IEnumerable<DetectionAlert> EvaluateNetwork(
        DetectionRuleDefinition rule,
        IReadOnlyList<NetworkConnectionRecord> connections,
        DateTimeOffset now)
    {
        var windowStart = now.AddMinutes(-rule.WindowMinutes);
        var ports = rule.AuthPorts.Count > 0 ? rule.AuthPorts.ToHashSet() : null;
        var scoped = connections
            .Where(c => c.TimestampUtc >= windowStart && c.TimestampUtc <= now && c.IsNew)
            .Where(c => !string.IsNullOrWhiteSpace(c.RemoteAddress) && c.RemoteAddress is not "0.0.0.0" and not "127.0.0.1")
            .Where(c => ports is null || ports.Contains(c.RemotePort))
            .Where(c =>
            {
                // Optional process filter (e.g. IIS w3wp.exe outbound)
                if (rule.ProcessPathContains.Count == 0) return true;
                var hay = $"{c.ProcessName}\n{c.ProcessPath}\n{c.ServiceNames}";
                return rule.ProcessPathContains.Any(p => hay.Contains(p, StringComparison.OrdinalIgnoreCase));
            })
            .ToList();

        foreach (var g in scoped.GroupBy(c => c.ComputerName))
        {
            var dests = g.Select(x => $"{x.RemoteAddress}:{x.RemotePort}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (dests.Count < Math.Max(1, rule.MinDistinctDestinations))
            {
                continue;
            }

            var sample = g.Take(20).ToList();
            yield return new DetectionAlert
            {
                TimestampUtc = now,
                ComputerName = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                RuleId = rule.Id,
                RuleName = rule.Name,
                Severity = rule.ParsedSeverity,
                Title = rule.Name,
                Description = $"{rule.Description} Distinct destinations={dests.Count}",
                SourceIp = sample.FirstOrDefault()?.LocalAddress,
                DestinationIp = string.Join(",", dests.Take(10)),
                EventCount = sample.Count,
                DistinctDestinationCount = dests.Count,
                EvidenceJson = JsonSerializer.Serialize(sample.Select(s => new
                {
                    s.ProcessId,
                    s.ProcessName,
                    s.ServiceNames,
                    s.RemoteAddress,
                    s.RemotePort
                }), JsonOptions)
            };
        }
    }

    private static bool Matches(DetectionRuleDefinition rule, SecurityEventRecord a, SecurityEventRecord b)
    {
        foreach (var field in rule.MatchFields)
        {
            switch (field.ToLowerInvariant())
            {
                case "sourceip":
                    if (!string.Equals(Norm(a.SourceIp), Norm(b.SourceIp), StringComparison.OrdinalIgnoreCase))
                        return false;
                    break;
                case "username":
                    if (!string.Equals(Norm(a.Username), Norm(b.Username), StringComparison.OrdinalIgnoreCase))
                        return false;
                    break;
            }
        }

        return true;
    }

    private DetectionAlert BuildAlert(
        DetectionRuleDefinition rule,
        List<SecurityEventRecord> evidence,
        int distinctUsers,
        int distinctDests,
        DateTimeOffset now)
    {
        return new DetectionAlert
        {
            TimestampUtc = now,
            ComputerName = _agentOptions.ComputerName,
            AgentId = _agentOptions.AgentId,
            RuleId = rule.Id,
            RuleName = rule.Name,
            Severity = rule.ParsedSeverity,
            Title = rule.Name,
            Description = rule.Description,
            SourceIp = evidence.Select(e => e.SourceIp).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)),
            DestinationIp = evidence.Select(e => e.DestinationIp ?? e.ComputerName).FirstOrDefault(),
            Username = evidence.Select(e => e.Username).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)),
            EventCount = evidence.Count,
            DistinctUserCount = distinctUsers,
            DistinctDestinationCount = distinctDests,
            EvidenceJson = JsonSerializer.Serialize(evidence.Take(25).Select(e => new
            {
                e.EventId,
                e.TimestampUtc,
                e.Username,
                e.SourceIp,
                e.LogonType,
                e.LogonProcess,
                e.Status,
                e.ProcessId,
                e.ProcessPath
            }), JsonOptions)
        };
    }

    private bool IsAllowlisted(DetectionAlert alert)
    {
        if (!string.IsNullOrWhiteSpace(alert.Username) &&
            _options.AllowlistUsernames.Any(u => string.Equals(u, alert.Username, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(alert.SourceIp) &&
            _options.AllowlistSourceIps.Any(ip => string.Equals(ip, alert.SourceIp, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static string Norm(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "-" : value.Trim();
}

internal sealed class AllowlistFile
{
    public List<string> Usernames { get; set; } = [];
    public List<string> SourceIps { get; set; } = [];
}

internal static class BuiltInRules
{
    public static List<DetectionRuleDefinition> Create() =>
    [
        new()
        {
            Id = "INTERNAL_PASSWORD_SPRAY",
            Name = "Internal Password Spray",
            Severity = "High",
            EventIds = [4625],
            WindowMinutes = 5,
            MinEventCount = 20,
            MinDistinctUsernames = 5,
            CooldownMinutes = 15,
            Description = "Single source failed logons against many usernames."
        },
        new()
        {
            Id = "BRUTE_FORCE_SINGLE_ACCOUNT",
            Name = "Brute Force Single Account",
            Severity = "High",
            EventIds = [4625],
            WindowMinutes = 5,
            MinEventCount = 20,
            MaxDistinctUsernames = 1,
            CooldownMinutes = 10,
            Description = "Repeated failures for one account."
        },
        new()
        {
            Id = "SPRAY_THEN_SUCCESS",
            Name = "Spray Then Success",
            Type = "sequence",
            Severity = "Critical",
            WindowMinutes = 15,
            FailureEventId = 4625,
            SuccessEventId = 4624,
            MinFailures = 5,
            MatchFields = ["SourceIp", "Username"],
            CooldownMinutes = 30,
            Description = "Failures then success."
        }
    ];
}
