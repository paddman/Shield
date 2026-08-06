using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Xml.Linq;
using NTShield.Core.Abstractions;
using NTShield.Core.Compatibility;
using NTShield.Core.Configuration;
using NTShield.Core.Security;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Collectors.Windows.Events;

/// <summary>
/// Real-time Windows Event Log collector using EventLogWatcher with record-id bookmark resume.
/// EventLogWatcher / EventLogQuery are available on Windows Server 2012+.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogCollector : IEventLogCollector
{
    private readonly EventLogCollectorOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILocalStore _store;
    private readonly ILogger<WindowsEventLogCollector> _logger;
    private readonly List<EventLogWatcher> _watchers = [];
    private readonly object _sync = new();

    public event EventHandler<SecurityEventRecord>? EventReceived;

    public WindowsEventLogCollector(
        IOptions<EventLogCollectorOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILocalStore store,
        ILogger<WindowsEventLogCollector> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _store = store;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!WindowsCompatibility.SupportsEventLogWatcher)
        {
            throw new PlatformNotSupportedException("EventLogWatcher requires Windows Server 2012 or later.");
        }

        foreach (var channel in _options.Channels)
        {
            if (channel.EventIds.Count == 0)
            {
                continue;
            }

            try
            {
                // Catch up any events written while the service was stopped (bookmark by EventRecordID).
                await CatchUpAsync(channel, cancellationToken);

                var query = BuildQuery(channel);
                var eventQuery = new EventLogQuery(channel.LogName, PathType.LogName, query)
                {
                    ReverseDirection = false
                };

                var watcher = new EventLogWatcher(eventQuery);
                watcher.EventRecordWritten += OnEventRecordWritten;
                watcher.Enabled = true;
                lock (_sync)
                {
                    _watchers.Add(watcher);
                }

                _logger.LogInformation(
                    "EventLogWatcher started for {Log} ids={Ids}",
                    channel.LogName,
                    string.Join(',', channel.EventIds));
            }
            catch (EventLogNotFoundException ex)
            {
                // IIS channels missing when IIS not installed — skip quietly
                _logger.LogInformation(ex, "Event log channel not present (skipped): {Log}", channel.LogName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start EventLogWatcher for {Log} (skipped)", channel.LogName);
            }
        }
    }

    private async Task CatchUpAsync(EventChannelWatch channel, CancellationToken cancellationToken)
    {
        var key = BookmarkKey(channel.LogName);
        var raw = await _store.GetStateAsync(key, cancellationToken);
        if (!long.TryParse(raw, out var lastRecordId))
        {
            lastRecordId = 0;
        }

        var ids = string.Join(" or ", channel.EventIds.Select(id => $"EventID={id}"));
        // RecordId filter in XPath is not always supported; we filter in code after query.
        var queryText = $"*[System[({ids})]]";
        try
        {
            var eventQuery = new EventLogQuery(channel.LogName, PathType.LogName, queryText)
            {
                ReverseDirection = false
            };
            using var reader = new EventLogReader(eventQuery);
            for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    var rid = rec.RecordId ?? 0;
                    if (rid <= lastRecordId)
                    {
                        continue;
                    }

                    var parsed = Parse(rec);
                    EventReceived?.Invoke(this, parsed);
                    await _store.SetStateAsync(key, rid.ToString(), cancellationToken);
                    lastRecordId = rid;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Catch-up read failed for {Log}", channel.LogName);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.Enabled = false;
                    watcher.EventRecordWritten -= OnEventRecordWritten;
                    watcher.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error disposing EventLogWatcher");
                }
            }

            _watchers.Clear();
        }

        return Task.CompletedTask;
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            _logger.LogWarning(e.EventException, "EventLogWatcher error");
            return;
        }

        if (e.EventRecord is null)
        {
            return;
        }

        try
        {
            using var record = e.EventRecord;
            var parsed = Parse(record);
            EventReceived?.Invoke(this, parsed);

            var rid = record.RecordId ?? 0;
            var logName = record.LogName ?? "Security";
            _ = PersistBookmarkAsync(logName, rid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to process event record");
        }
    }

    private async Task PersistBookmarkAsync(string logName, long recordId)
    {
        try
        {
            await _store.SetStateAsync(BookmarkKey(logName), recordId.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to persist bookmark for {Log}", logName);
        }
    }

    private SecurityEventRecord Parse(EventRecord record)
    {
        string rawXml;
        try { rawXml = EventDataSanitizer.SanitizeXml(record.ToXml()); }
        catch { rawXml = string.Empty; }

        Dictionary<string, string> data;
        try { data = ParseEventData(rawXml); }
        catch { data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); }
        var eventId = record.Id;

        var result = new SecurityEventRecord
        {
            TimestampUtc = record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            ComputerName = record.MachineName ?? _agentOptions.ComputerName,
            AgentId = _agentOptions.AgentId,
            EventId = eventId,
            Channel = record.LogName ?? string.Empty,
            ProviderName = record.ProviderName,
            RawXml = rawXml,
            EventRecordId = record.RecordId ?? 0,
            CollectedAtUtc = DateTimeOffset.UtcNow
        };

        result.Username = First(data, "SubjectUserName", "TargetUserName", "AccountName");
        result.Domain = First(data, "SubjectDomainName", "TargetDomainName", "AccountDomain");
        result.TargetUserName = First(data, "TargetUserName");
        result.TargetDomainName = First(data, "TargetDomainName");
        result.SourceIp = First(data, "IpAddress", "SourceAddress", "ClientAddress");
        result.DestinationIp = First(data, "DestAddress");
        result.AuthenticationPackage = First(data, "AuthenticationPackageName", "LmPackageName");
        result.LogonProcess = First(data, "LogonProcessName");
        result.Status = First(data, "Status");
        result.SubStatus = First(data, "SubStatus");
        result.WorkstationName = First(data, "WorkstationName");
        result.ProcessPath = First(data, "ProcessName", "NewProcessName", "ImagePath", "ServiceFileName");
        result.ServiceName = First(data, "ServiceName");
        result.TaskName = First(data, "TaskName");
        // Keep parent path in raw XML; also stamp parent onto ServiceName if empty for IIS w3wp parent matching
        var parent = First(data, "ParentProcessName", "CreatorProcessName");
        if (!string.IsNullOrWhiteSpace(parent) && string.IsNullOrWhiteSpace(result.ServiceName))
            result.ServiceName = "Parent=" + parent;

        if (int.TryParse(First(data, "IpPort", "SourcePort"), out var sport))
            result.SourcePort = sport;
        if (int.TryParse(First(data, "DestPort"), out var dport))
            result.DestinationPort = dport;
        if (int.TryParse(First(data, "LogonType"), out var logonType))
            result.LogonType = logonType;

        var pidRaw = First(data, "ProcessId", "NewProcessId", "SubjectProcessId");
        if (pidRaw is not null)
        {
            result.ProcessId = NormalizePid(pidRaw);
        }

        if (eventId is 4625 or 4624 or 4648)
        {
            result.Username = result.TargetUserName ?? result.Username;
            result.Domain = result.TargetDomainName ?? result.Domain;
        }

        return result;
    }

    private static int NormalizePid(string raw)
    {
        if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(raw.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out var hex))
        {
            return hex;
        }

        return int.TryParse(raw, out var pid) ? pid : 0;
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(xml))
        {
            return map;
        }

        try
        {
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            foreach (var data in doc.Descendants(ns + "Data"))
            {
                var name = data.Attribute("Name")?.Value;
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                map[name] = data.Value?.Trim() ?? string.Empty;
            }
        }
        catch
        {
            // leave empty
        }

        return map;
    }

    private static string? First(Dictionary<string, string> data, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (data.TryGetValue(key, out var value) &&
                !string.IsNullOrWhiteSpace(value) &&
                value is not "-" )
            {
                return value;
            }
        }

        return null;
    }

    private static string BuildQuery(EventChannelWatch channel)
    {
        var ids = string.Join(" or ", channel.EventIds.Select(id => $"EventID={id}"));
        return $"*[System[({ids})]]";
    }

    private static string BookmarkKey(string logName) => $"eventlog.bookmark.{logName}";

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None);
    }
}
