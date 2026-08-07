using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NTShield.Core.Configuration;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Agent;

public sealed record IpLogInspectionResult(
    IReadOnlyList<SecurityEventRecord> Events,
    IReadOnlyList<DetectionAlert> Alerts);

/// <summary>
/// Bounded, read-only inspection of explicitly configured text logs.
/// It extracts IP evidence without uploading raw log lines, which may contain secrets.
/// </summary>
public sealed class IpLogFileInspector
{
    private static readonly Regex Ipv4Candidate = new(
        @"(?<![\w])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Ipv6Candidate = new(
        @"(?<![\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,4}(?![\w])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex WebProbe = new(
        @"(?i)(?:\.\./\.\./|/wp-admin|/wp-login|/xmlrpc\.php|union\s+select|sleep\s*\(|base64_decode|cmd=|/shell|/\.env)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AuthFailure = new(
        @"(?i)(?:failed\s+(?:password|login|authentication)|authentication\s+failure|invalid\s+(?:user|password)|unauthori[sz]ed|login\s+failed|status[=: ]+401|\b401\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Denied = new(
        @"(?i)(?:access\s+denied|blocked|forbidden|refused|status[=: ]+403|\b403\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ServerError = new(
        @"(?i)(?:status[=: ]+5\d\d|\b5\d\d\b|upstream\s+timed\s+out|connection\s+reset)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly IpLogFileInspectorOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<IpLogFileInspector> _logger;
    private readonly Dictionary<string, FileCursor> _cursors = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<IpObservation> _recentObservations = new();
    private readonly Dictionary<string, DateTimeOffset> _cooldowns = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private long _eventSequence;

    public IpLogFileInspector(
        IOptions<IpLogFileInspectorOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<IpLogFileInspector> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public async Task<IpLogInspectionResult> ScanAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return new IpLogInspectionResult([], []);
        }

        await _scanGate.WaitAsync(cancellationToken);
        try
        {
            var events = new List<SecurityEventRecord>();
            var observations = new List<IpObservation>();
            var eventBudget = Math.Clamp(_options.MaxEventsPerCycle, 1, 10_000);

            foreach (var path in ResolveFiles().Take(Math.Clamp(_options.MaxFiles, 1, 256)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var lines = await ReadNewLinesAsync(path, cancellationToken);
                    foreach (var line in lines)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var ips = ExtractIps(line.Text);
                        if (ips.Count == 0)
                        {
                            continue;
                        }

                        var category = Classify(line.Text);
                        var lineHash = HashLine(line.Text);
                        foreach (var ip in ips)
                        {
                            observations.Add(new IpObservation(
                                ip,
                                category,
                                path,
                                lineHash,
                                DateTimeOffset.UtcNow));
                        }

                        if (events.Count >= eventBudget)
                        {
                            continue;
                        }

                        events.Add(new SecurityEventRecord
                        {
                            TimestampUtc = DateTimeOffset.UtcNow,
                            CollectedAtUtc = DateTimeOffset.UtcNow,
                            ComputerName = _agentOptions.ComputerName,
                            AgentId = _agentOptions.AgentId,
                            EventId = 9701,
                            Channel = "IpLogFile",
                            ProviderName = "NTShield.Agent.IpLog",
                            SourceIp = ips[0],
                            DestinationIp = ips.Count > 1 ? string.Join(",", ips.Skip(1).Take(4)) : null,
                            ProcessPath = path,
                            Status = category,
                            SubStatus = $"ips={ips.Count};line_sha256={lineHash}",
                            RawXml = $"file={Path.GetFileName(path)};category={category};ips={string.Join(',', ips.Take(8))};line_sha256={lineHash}",
                            EventRecordId = Interlocked.Increment(ref _eventSequence)
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogDebug(ex, "IP log file is not readable: {Path}", path);
                }
                catch (IOException ex)
                {
                    _logger.LogDebug(ex, "IP log file read failed: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "IP log inspection failed: {Path}", path);
                }
            }

            foreach (var observation in observations)
            {
                _recentObservations.Enqueue(observation);
            }

            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-Math.Clamp(_options.AlertWindowMinutes, 1, 60));
            while (_recentObservations.Count > 0 && _recentObservations.Peek().TimestampUtc < cutoff)
            {
                _recentObservations.Dequeue();
            }

            return new IpLogInspectionResult(events, BuildAlerts(DateTimeOffset.UtcNow));
        }
        finally
        {
            _scanGate.Release();
        }
    }

    private IReadOnlyList<DetectionAlert> BuildAlerts(DateTimeOffset now)
    {
        var alerts = new List<DetectionAlert>();
        var recent = _recentObservations.ToArray();

        foreach (var group in recent
                     .Where(o => o.Category is "auth_failure" or "web_probe")
                     .GroupBy(o => $"{o.Ip}|{o.Category}", StringComparer.OrdinalIgnoreCase))
        {
            var observations = group.ToList();
            var threshold = group.First().Category == "auth_failure"
                ? Math.Clamp(_options.AuthFailureBurstMin, 3, 10_000)
                : Math.Clamp(_options.WebProbeBurstMin, 2, 10_000);
            if (observations.Count < threshold)
            {
                continue;
            }

            var key = group.Key;
            if (_cooldowns.TryGetValue(key, out var cooldown) && cooldown > now)
            {
                continue;
            }

            var category = group.First().Category;
            var ruleId = category == "auth_failure"
                ? "IP_LOG_AUTH_FAILURE_BURST"
                : "IP_LOG_WEB_PROBE_BURST";
            var severity = category == "auth_failure" ? Severity.High : Severity.Medium;
            var files = observations.Select(o => o.Path).Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToArray();
            var evidence = new
            {
                ip = group.First().Ip,
                category,
                count = observations.Count,
                windowMinutes = _options.AlertWindowMinutes,
                files,
                lineHashes = observations.Select(o => o.LineHash).Distinct().Take(20).ToArray()
            };

            alerts.Add(new DetectionAlert
            {
                TimestampUtc = now,
                ComputerName = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                RuleId = ruleId,
                RuleName = category == "auth_failure" ? "IP log authentication failure burst" : "IP log web probe burst",
                Severity = severity,
                Title = category == "auth_failure"
                    ? $"Repeated authentication failures from {group.First().Ip}"
                    : $"Repeated web probe indicators from {group.First().Ip}",
                Description = $"Text log evidence shows {observations.Count} {category.Replace('_', ' ')} entries within {_options.AlertWindowMinutes} minutes.",
                SourceIp = group.First().Ip,
                EventCount = observations.Count,
                DetectionStage = "signature+behavioral",
                EvidenceJson = JsonSerializer.Serialize(evidence)
            });
            _cooldowns[key] = now.AddMinutes(Math.Max(1, _options.AlertWindowMinutes));
        }

        return alerts;
    }

    private async Task<IReadOnlyList<LogLine>> ReadNewLinesAsync(string path, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0)
        {
            return [];
        }

        var maxBytes = Math.Clamp(_options.MaxBytesPerFile, 4 * 1024, 32 * 1024 * 1024);
        var cursor = GetCursor(path);
        var reset = !cursor.Initialized || info.Length < cursor.Offset;
        var start = reset
            ? Math.Max(0, info.Length - maxBytes)
            : cursor.Offset;
        if (info.Length - start > maxBytes)
        {
            start = Math.Max(0, info.Length - maxBytes);
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.SequentialScan | FileOptions.Asynchronous);
        stream.Seek(start, SeekOrigin.Begin);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var text = await reader.ReadToEndAsync(cancellationToken);
        cursor.Offset = stream.Length;
        cursor.Initialized = true;

        var combined = (reset ? string.Empty : cursor.PartialLine) + text;
        if (string.IsNullOrEmpty(combined))
        {
            return [];
        }

        var endsWithNewline = combined.EndsWith('\n');
        var rawLines = combined.Split('\n');
        cursor.PartialLine = endsWithNewline ? string.Empty : rawLines[^1];
        var lineCount = endsWithNewline ? rawLines.Length : rawLines.Length - 1;
        var lines = new List<LogLine>(Math.Min(lineCount, 10_000));
        for (var index = 0; index < lineCount; index++)
        {
            var line = rawLines[index].TrimEnd('\r');
            if (!string.IsNullOrWhiteSpace(line))
            {
                lines.Add(new LogLine(line));
            }
        }

        return lines;
    }

    private FileCursor GetCursor(string path)
    {
        if (!_cursors.TryGetValue(path, out var cursor))
        {
            cursor = new FileCursor();
            _cursors[path] = cursor;
        }

        return cursor;
    }

    private IEnumerable<string> ResolveFiles()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var configured in _options.Paths ?? [])
        {
            if (string.IsNullOrWhiteSpace(configured))
            {
                continue;
            }

            foreach (var path in ExpandPattern(configured))
            {
                if (files.Add(path))
                {
                    yield return path;
                }
            }
        }
    }

    private static IEnumerable<string> ExpandPattern(string configured)
    {
        string full;
        try
        {
            full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(configured.Trim()));
        }
        catch
        {
            yield break;
        }

        if (File.Exists(full))
        {
            yield return full;
            yield break;
        }

        var root = Path.GetPathRoot(full);
        if (string.IsNullOrWhiteSpace(root))
        {
            yield break;
        }

        var relative = full[root.Length..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var segments = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            yield break;
        }

        var directories = new List<string> { root };
        for (var i = 0; i < segments.Length - 1; i++)
        {
            var segment = segments[i];
            var next = new List<string>();
            foreach (var directory in directories)
            {
                try
                {
                    if (HasWildcard(segment))
                    {
                        next.AddRange(Directory.EnumerateDirectories(directory, segment, SearchOption.TopDirectoryOnly));
                    }
                    else
                    {
                        var exact = Path.Combine(directory, segment);
                        if (Directory.Exists(exact)) next.Add(exact);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            directories = next;
            if (directories.Count == 0) yield break;
        }

        var filePattern = segments[^1];
        foreach (var directory in directories)
        {
            var matches = new List<string>();
            try
            {
                if (HasWildcard(filePattern))
                {
                    matches.AddRange(Directory.EnumerateFiles(directory, filePattern, SearchOption.TopDirectoryOnly));
                }
                else
                {
                    var exact = Path.Combine(directory, filePattern);
                    if (File.Exists(exact)) matches.Add(exact);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            foreach (var match in matches)
            {
                yield return match;
            }
        }
    }

    private static bool HasWildcard(string value) => value.Contains('*') || value.Contains('?');

    private static IReadOnlyList<string> ExtractIps(string line)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Ipv4Candidate.Matches(line).Concat(Ipv6Candidate.Matches(line)))
        {
            if (!IPAddress.TryParse(match.Value.Trim('[', ']'), out var address) || IsNoiseAddress(address))
            {
                continue;
            }

            result.Add(address.ToString());
        }

        return result.Take(16).ToArray();
    }

    private static bool IsNoiseAddress(IPAddress address) =>
        IPAddress.IsLoopback(address) ||
        address.Equals(IPAddress.Any) ||
        address.Equals(IPAddress.IPv6Any) ||
        address.IsIPv6LinkLocal ||
        address.IsIPv6Multicast;

    private static string Classify(string line)
    {
        if (WebProbe.IsMatch(line)) return "web_probe";
        if (AuthFailure.IsMatch(line)) return "auth_failure";
        if (Denied.IsMatch(line)) return "access_denied";
        if (ServerError.IsMatch(line)) return "server_error";
        return "ip_observation";
    }

    private static string HashLine(string line)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(line));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed class FileCursor
    {
        public bool Initialized { get; set; }
        public long Offset { get; set; }
        public string PartialLine { get; set; } = string.Empty;
    }

    private sealed record LogLine(string Text);

    private sealed record IpObservation(
        string Ip,
        string Category,
        string Path,
        string LineHash,
        DateTimeOffset TimestampUtc);
}
