using System.Management;
using System.Runtime.Versioning;
using NTShield.Collectors.Windows.Native;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Collectors.Windows.Process;

/// <summary>
/// Process collector using System.Diagnostics with WMI/CIM fallback (Server 2012 compatible).
/// Handles AccessDenied and short-lived processes.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WmiProcessCollector : IProcessCollector
{
    private readonly ProcessCollectorOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly IServiceResolver _serviceResolver;
    private readonly ProcessEnricher _enricher;
    private readonly ILogger<WmiProcessCollector> _logger;

    public WmiProcessCollector(
        IOptions<ProcessCollectorOptions> options,
        IOptions<AgentOptions> agentOptions,
        IServiceResolver serviceResolver,
        ProcessEnricher enricher,
        ILogger<WmiProcessCollector> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _serviceResolver = serviceResolver;
        _enricher = enricher;
        _logger = logger;
    }

    public async Task<IReadOnlyList<ProcessRecord>> CollectAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var results = new List<ProcessRecord>();
        var pids = new List<int>();

        try
        {
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    pids.Add(proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Process.GetProcesses failed; falling back to WMI");
            if (_options.UseWmiFallback)
            {
                pids.AddRange(EnumeratePidsViaWmi());
            }
        }

        var serviceMap = await _serviceResolver.ResolveManyAsync(pids, cancellationToken);

        foreach (var pid in pids)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var details = _enricher.GetDetails(pid, _options.HashExecutables);
                serviceMap.TryGetValue(pid, out var services);
                var serviceNames = services is { Count: > 0 }
                    ? string.Join(", ", services.Select(s => s.ServiceName))
                    : null;

                results.Add(new ProcessRecord
                {
                    TimestampUtc = now,
                    ComputerName = _agentOptions.ComputerName,
                    AgentId = _agentOptions.AgentId,
                    ProcessId = pid,
                    ParentProcessId = details.ParentProcessId,
                    ProcessName = details.ProcessName,
                    FullPath = details.ProcessPath,
                    CommandLine = details.CommandLine,
                    User = details.Owner,
                    StartTimeUtc = details.StartTimeUtc.HasValue
                        ? new DateTimeOffset(DateTime.SpecifyKind(details.StartTimeUtc.Value, DateTimeKind.Utc))
                        : null,
                    ExecutableSha256 = details.ExecutableSha256,
                    SignerName = details.SignerName,
                    DigitalSignatureStatus = details.DigitalSignatureStatus,
                    IntegrityLevel = details.IntegrityLevel,
                    ServiceNames = serviceNames
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Skipping process {Pid}", pid);
            }
        }

        return results;
    }

    private static List<int> EnumeratePidsViaWmi()
    {
        var list = new List<int>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                list.Add(Convert.ToInt32(obj["ProcessId"]));
            }
        }
        catch
        {
            // AccessDenied
        }

        return list;
    }
}
