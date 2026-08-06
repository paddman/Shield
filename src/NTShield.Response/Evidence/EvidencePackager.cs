using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Core.Security;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Response.Evidence;

public sealed class EvidencePackager : IEvidenceCollector
{
    private readonly ResponseOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILocalStore _store;
    private readonly ILogger<EvidencePackager> _logger;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public EvidencePackager(
        IOptions<ResponseOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILocalStore store,
        ILogger<EvidencePackager> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _store = store;
        _logger = logger;
    }

    public async Task<string> CollectAndExportZipAsync(Incident incident, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_options.EvidenceDirectory);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss");
        var workDir = Path.Combine(_options.EvidenceDirectory, $"tmp-{incident.IncidentId}-{stamp}");
        Directory.CreateDirectory(workDir);

        try
        {
            var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            await Write(workDir, "incident.json", JsonSerializer.Serialize(incident, JsonOptions), files);
            await Write(workDir, "incident-display.txt", incident.FormatDisplay(), files);

            var from = (incident.FirstSeen ?? DateTimeOffset.UtcNow.AddHours(-1)).AddMinutes(-5);
            var to = (incident.LastSeen ?? DateTimeOffset.UtcNow).AddMinutes(5);
            var events = await _store.QuerySecurityEventsAsync(from, to, cancellationToken: cancellationToken);
            await Write(workDir, "security-events.json", JsonSerializer.Serialize(events, JsonOptions), files);

            var xmlDir = Path.Combine(workDir, "event-xml");
            Directory.CreateDirectory(xmlDir);
            var i = 0;
            foreach (var e in events.Take(50))
            {
                var name = $"event-{e.EventId}-{e.EventRecordId}-{i++}.xml";
                var xml = EventDataSanitizer.SanitizeXml(e.RawXml);
                await File.WriteAllTextAsync(Path.Combine(xmlDir, name), xml, cancellationToken);
                files[$"event-xml/{name}"] = Sha256File(Path.Combine(xmlDir, name));
            }

            await Write(workDir, "process.json", JsonSerializer.Serialize(new
            {
                incident.ProcessId,
                incident.ProcessName,
                incident.ProcessPath,
                incident.ProcessCommandLine,
                incident.ExecutableSha256
            }, JsonOptions), files);

            await Write(workDir, "services.json", JsonSerializer.Serialize(new
            {
                incident.Services,
                incident.ServiceAccount
            }, JsonOptions), files);

            await Write(workDir, "metadata.json", JsonSerializer.Serialize(new
            {
                SystemTimeUtc = DateTimeOffset.UtcNow,
                AgentVersion = _agentOptions.Version,
                Hostname = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                incident.SourceIp,
                incident.DestinationIp,
                RuleId = incident.RuleId,
                Title = incident.Title
            }, JsonOptions), files);

            // Firewall status snapshot (best effort)
            try
            {
                var fw = new Firewall.FirewallBlocker(Microsoft.Extensions.Logging.Abstractions.NullLogger<Firewall.FirewallBlocker>.Instance);
                await Write(workDir, "firewall-status.txt", fw.CaptureFirewallStatus(), files);
            }
            catch (Exception ex)
            {
                await Write(workDir, "firewall-status.txt", $"unavailable: {ex.Message}", files);
            }

            var manifest = new
            {
                createdUtc = DateTimeOffset.UtcNow,
                incidentId = incident.IncidentId,
                agentId = _agentOptions.AgentId,
                files = files.Select(kv => new { path = kv.Key, sha256 = kv.Value }).OrderBy(x => x.path).ToList()
            };
            await Write(workDir, "manifest.json", JsonSerializer.Serialize(manifest, JsonOptions), files);
            // re-hash manifest into itself is awkward; store final hashes excluding self update
            manifest = new
            {
                createdUtc = DateTimeOffset.UtcNow,
                incidentId = incident.IncidentId,
                agentId = _agentOptions.AgentId,
                files = files.Where(f => f.Key != "manifest.json")
                    .Select(kv => new { path = kv.Key, sha256 = kv.Value })
                    .Append(new { path = "manifest.json", sha256 = Sha256File(Path.Combine(workDir, "manifest.json")) })
                    .OrderBy(x => x.path)
                    .ToList()
            };
            await File.WriteAllTextAsync(Path.Combine(workDir, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);

            var zipPath = Path.Combine(_options.EvidenceDirectory, $"evidence-{incident.IncidentId}-{stamp}.zip");
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }

            ZipFile.CreateFromDirectory(workDir, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            _logger.LogInformation("Evidence package written to {Path}", zipPath);
            return zipPath;
        }
        finally
        {
            try { Directory.Delete(workDir, true); } catch { /* ignore */ }
        }
    }

    private static async Task Write(string dir, string name, string content, Dictionary<string, string> files)
    {
        var path = Path.Combine(dir, name);
        await File.WriteAllTextAsync(path, content, Encoding.UTF8);
        files[name] = Sha256File(path);
    }

    private static string Sha256File(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }
}
