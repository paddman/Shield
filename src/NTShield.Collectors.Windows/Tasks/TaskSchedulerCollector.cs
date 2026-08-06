using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using NTShield.Core.Abstractions;
using NTShield.Core.Compatibility;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Collectors.Windows.Tasks;

/// <summary>
/// Scheduled Task collector via Task Scheduler 2.0 COM (ITaskService) — Server 2012 compatible.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TaskSchedulerCollector : IScheduledTaskCollector
{
    private readonly ScheduledTaskCollectorOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<TaskSchedulerCollector> _logger;
    private Dictionary<string, string> _previous = new(StringComparer.OrdinalIgnoreCase);

    public TaskSchedulerCollector(
        IOptions<ScheduledTaskCollectorOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<TaskSchedulerCollector> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public Task<IReadOnlyList<ScheduledTaskRecord>> CollectChangesAsync(CancellationToken cancellationToken)
    {
        if (!WindowsCompatibility.SupportsTaskSchedulerCom)
        {
            _logger.LogError("Task Scheduler COM not supported");
            return Task.FromResult<IReadOnlyList<ScheduledTaskRecord>>(Array.Empty<ScheduledTaskRecord>());
        }

        var now = DateTimeOffset.UtcNow;
        var current = new Dictionary<string, ScheduledTaskRecord>(StringComparer.OrdinalIgnoreCase);
        var changes = new List<ScheduledTaskRecord>();

        try
        {
            var taskServiceType = Type.GetTypeFromProgID("Schedule.Service");
            if (taskServiceType is null)
            {
                _logger.LogWarning("Schedule.Service ProgID not found");
                return Task.FromResult<IReadOnlyList<ScheduledTaskRecord>>(Array.Empty<ScheduledTaskRecord>());
            }

            dynamic service = Activator.CreateInstance(taskServiceType)!;
            service.Connect();
            dynamic root = service.GetFolder("\\");
            EnumerateFolder(root, "\\", current, now);
            Marshal.FinalReleaseComObject(service);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enumerate scheduled tasks");
            return Task.FromResult<IReadOnlyList<ScheduledTaskRecord>>(Array.Empty<ScheduledTaskRecord>());
        }

        // First run: establish baseline without flooding alerts.
        if (_previous.Count == 0)
        {
            _previous = current.ToDictionary(k => k.Key, v => Fingerprint(v.Value), StringComparer.OrdinalIgnoreCase);
            return Task.FromResult<IReadOnlyList<ScheduledTaskRecord>>(Array.Empty<ScheduledTaskRecord>());
        }

        foreach (var (key, rec) in current)
        {
            var fp = Fingerprint(rec);
            if (!_previous.TryGetValue(key, out var oldFp))
            {
                rec.ChangeType = "Created";
                changes.Add(rec);
            }
            else if (!string.Equals(oldFp, fp, StringComparison.Ordinal))
            {
                rec.ChangeType = "Modified";
                changes.Add(rec);
            }
        }

        foreach (var key in _previous.Keys)
        {
            if (!current.ContainsKey(key))
            {
                var parts = key.Split('\u001f');
                changes.Add(new ScheduledTaskRecord
                {
                    TimestampUtc = now,
                    ComputerName = _agentOptions.ComputerName,
                    AgentId = _agentOptions.AgentId,
                    TaskPath = parts.ElementAtOrDefault(0) ?? "\\",
                    TaskName = parts.ElementAtOrDefault(1) ?? key,
                    Enabled = false,
                    ChangeType = "Deleted"
                });
            }
        }

        _previous = current.ToDictionary(k => k.Key, v => Fingerprint(v.Value), StringComparer.OrdinalIgnoreCase);
        return Task.FromResult<IReadOnlyList<ScheduledTaskRecord>>(changes);
    }

    private void EnumerateFolder(dynamic folder, string path, Dictionary<string, ScheduledTaskRecord> sink, DateTimeOffset now)
    {
        try
        {
            dynamic tasks = folder.GetTasks(0);
            for (var i = 1; i <= tasks.Count; i++)
            {
                dynamic task = tasks[i];
                try
                {
                    string name = task.Name;
                    string taskPath = path;
                    bool enabled = task.Enabled;
                    string definitionXml = task.Xml ?? string.Empty;
                    string runAs = string.Empty;
                    string command = string.Empty;
                    string arguments = string.Empty;
                    string triggers = string.Empty;
                    string lastResult = string.Empty;
                    DateTimeOffset? lastRun = null;

                    try { runAs = task.Definition.Principal.UserId ?? string.Empty; } catch { /* ignore */ }
                    try
                    {
                        dynamic actions = task.Definition.Actions;
                        if (actions.Count >= 1)
                        {
                            dynamic action = actions[1];
                            try { command = action.Path ?? string.Empty; } catch { /* ignore */ }
                            try { arguments = action.Arguments ?? string.Empty; } catch { /* ignore */ }
                        }
                    }
                    catch { /* ignore */ }

                    try
                    {
                        dynamic tr = task.Definition.Triggers;
                        var parts = new List<string>();
                        for (var t = 1; t <= tr.Count; t++)
                        {
                            try { parts.Add(tr[t].Type.ToString()); } catch { /* ignore */ }
                        }

                        triggers = string.Join(",", parts);
                    }
                    catch { /* ignore */ }

                    try { lastResult = Convert.ToString(task.LastTaskResult) ?? string.Empty; } catch { /* ignore */ }
                    try
                    {
                        DateTime lr = task.LastRunTime;
                        if (lr.Year > 1900)
                        {
                            lastRun = new DateTimeOffset(DateTime.SpecifyKind(lr, DateTimeKind.Local)).ToUniversalTime();
                        }
                    }
                    catch { /* ignore */ }

                    var key = $"{taskPath}\u001f{name}";
                    sink[key] = new ScheduledTaskRecord
                    {
                        TimestampUtc = now,
                        ComputerName = _agentOptions.ComputerName,
                        AgentId = _agentOptions.AgentId,
                        TaskPath = taskPath,
                        TaskName = name,
                        Command = command,
                        Arguments = arguments,
                        RunAsAccount = runAs,
                        Triggers = string.IsNullOrEmpty(triggers) ? definitionXml : triggers,
                        Enabled = enabled,
                        LastRunResult = lastResult,
                        LastRunTimeUtc = lastRun
                    };
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Skipping task in {Path}", path);
                }
            }

            dynamic folders = folder.GetFolders(0);
            for (var i = 1; i <= folders.Count; i++)
            {
                dynamic sub = folders[i];
                string subPath = sub.Path;
                EnumerateFolder(sub, subPath, sink, now);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "EnumerateFolder failed for {Path}", path);
        }
    }

    private static string Fingerprint(ScheduledTaskRecord r) =>
        $"{r.Command}|{r.Arguments}|{r.RunAsAccount}|{r.Enabled}|{r.Triggers}";
}
