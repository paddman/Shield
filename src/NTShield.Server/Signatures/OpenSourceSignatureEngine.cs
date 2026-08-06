using System.Text.Json;
using NTShield.Server.Syslog;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Signatures;

public sealed class SignatureDefinition
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Severity { get; set; } = "Medium";
    public string Category { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string Source { get; set; } = "community";
    public List<string> MatchAny { get; set; } = [];
    public List<string> MatchAll { get; set; } = [];
    public List<string> Keywords { get; set; } = [];
}

public sealed class SignaturePack
{
    public string Pack { get; set; } = "";
    public string Version { get; set; } = "";
    public List<SignatureDefinition> Signatures { get; set; } = [];
}

public sealed class SignatureHit
{
    public required SignatureDefinition Signature { get; init; }
    public required ParsedSyslogMessage Message { get; init; }
}

/// <summary>
/// Lightweight open-source style signature matcher (keyword / substring).
/// Inspired by public Sigma/Snort ideas — not a full Snort/Suricata engine.
/// </summary>
public sealed class OpenSourceSignatureEngine
{
    private readonly ILogger<OpenSourceSignatureEngine> _logger;
    private readonly SyslogOptions _options;
    private List<SignatureDefinition> _sigs = [];
    private DateTime _loadedUtc = DateTime.MinValue;

    public OpenSourceSignatureEngine(IOptions<SyslogOptions> options, ILogger<OpenSourceSignatureEngine> logger)
    {
        _options = options.Value;
        _logger = logger;
        ReloadIfNeeded(force: true);
    }

    public IReadOnlyList<SignatureDefinition> Signatures
    {
        get
        {
            ReloadIfNeeded();
            return _sigs;
        }
    }

    public void ReloadIfNeeded(bool force = false)
    {
        try
        {
            var path = _options.SignaturesPath;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                // try content-root relative
                var alt = Path.Combine(AppContext.BaseDirectory, "signatures", "opensource-signatures.json");
                if (File.Exists(alt))
                {
                    path = alt;
                }
                else
                {
                    return;
                }
            }

            var info = new FileInfo(path);
            if (!force && info.LastWriteTimeUtc <= _loadedUtc)
            {
                return;
            }

            var json = File.ReadAllText(path);
            var pack = JsonSerializer.Deserialize<SignaturePack>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            _sigs = pack?.Signatures.Where(s => s.Enabled).ToList() ?? [];
            _loadedUtc = info.LastWriteTimeUtc;
            _logger.LogInformation("Loaded {Count} open-source signatures from {Path}", _sigs.Count, path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed loading open-source signatures");
        }
    }

    public IEnumerable<SignatureHit> Match(ParsedSyslogMessage msg)
    {
        ReloadIfNeeded();
        var hay = (msg.AppName + " " + msg.Message + " " + msg.Raw).ToLowerInvariant();
        foreach (var sig in _sigs)
        {
            if (sig.Keywords is { Count: > 0 } &&
                !sig.Keywords.Any(k => hay.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                // keywords optional filter — if set, at least one should match OR we still check matchAny on full text
                // keep loose: only use keywords as soft boost, still evaluate matchAny
            }

            if (sig.MatchAll is { Count: > 0 } &&
                !sig.MatchAll.All(m => hay.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (sig.MatchAny is { Count: > 0 })
            {
                if (sig.MatchAny.Any(m => hay.Contains(m, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return new SignatureHit { Signature = sig, Message = msg };
                }
            }
            else if (sig.Keywords is { Count: > 0 } &&
                     sig.Keywords.Any(k => hay.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                yield return new SignatureHit { Signature = sig, Message = msg };
            }
        }
    }

    public static DetectionAlert ToAlert(SignatureHit hit, string agentId = "syslog")
    {
        var sig = hit.Signature;
        var msg = hit.Message;
        var sev = Enum.TryParse<Severity>(sig.Severity, true, out var s) ? s : Severity.Medium;
        return new DetectionAlert
        {
            AlertId = Guid.NewGuid().ToString("N"),
            TimestampUtc = msg.TimestampUtc,
            ComputerName = msg.Host,
            AgentId = agentId,
            RuleId = sig.Id,
            RuleName = sig.Name,
            Severity = sev,
            Title = sig.Name,
            Description = $"Open-source signature hit ({sig.Source}): {sig.Id} MITRE {sig.MitreTechnique}. Msg: {Truncate(msg.Message, 400)}",
            SourceIp = msg.SourceIp ?? ExtractIp(msg.Message),
            EventCount = 1,
            EvidenceJson = JsonSerializer.Serialize(new
            {
                msg.Raw,
                msg.AppName,
                msg.Host,
                sig.Id,
                sig.MitreTechnique,
                sig.Category
            })
        };
    }

    public static Incident ToIncident(SignatureHit hit)
    {
        var alert = ToAlert(hit);
        return new Incident
        {
            IncidentId = Guid.NewGuid().ToString("N"),
            Title = alert.Title,
            RuleId = alert.RuleId,
            Severity = alert.Severity,
            Description = alert.Description,
            SourceIp = alert.SourceIp,
            DestinationHost = hit.Message.Host,
            FirstSeenUtc = alert.TimestampUtc,
            LastSeenUtc = alert.TimestampUtc,
            CorrelationKey = $"sig|{alert.RuleId}|{hit.Message.Host}|{alert.SourceIp}",
            Status = "Open",
            EvidenceJson = alert.EvidenceJson
        };
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) || s.Length <= n ? s : s[..n] + "...";

    private static string? ExtractIp(string msg)
    {
        var m = System.Text.RegularExpressions.Regex.Match(msg,
            @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b");
        return m.Success ? m.Value : null;
    }
}
