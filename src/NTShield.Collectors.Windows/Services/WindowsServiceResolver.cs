using System.Management;
using System.Runtime.Versioning;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Collectors.Windows.Services;

/// <summary>
/// Resolves PID -&gt; Windows Service(s) using Win32_Service.
/// Supports svchost.exe hosting multiple services in one PID.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceResolver : IServiceResolver
{
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<WindowsServiceResolver> _logger;
    private readonly object _sync = new();
    private Dictionary<int, List<ServiceRecord>>? _cache;
    private DateTimeOffset _cacheAt = DateTimeOffset.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(15);

    public WindowsServiceResolver(IOptions<AgentOptions> agentOptions, ILogger<WindowsServiceResolver> logger)
    {
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public Task<IReadOnlyList<ServiceRecord>> ResolveByProcessIdAsync(int processId, CancellationToken cancellationToken)
    {
        var map = GetMap();
        return Task.FromResult<IReadOnlyList<ServiceRecord>>(
            map.TryGetValue(processId, out var list) ? list : Array.Empty<ServiceRecord>());
    }

    public Task<IReadOnlyDictionary<int, IReadOnlyList<ServiceRecord>>> ResolveManyAsync(
        IEnumerable<int> processIds,
        CancellationToken cancellationToken)
    {
        var map = GetMap();
        var result = new Dictionary<int, IReadOnlyList<ServiceRecord>>();
        foreach (var pid in processIds.Distinct())
        {
            result[pid] = map.TryGetValue(pid, out var list)
                ? list
                : Array.Empty<ServiceRecord>();
        }

        return Task.FromResult<IReadOnlyDictionary<int, IReadOnlyList<ServiceRecord>>>(result);
    }

    private Dictionary<int, List<ServiceRecord>> GetMap()
    {
        lock (_sync)
        {
            if (_cache is not null && DateTimeOffset.UtcNow - _cacheAt < CacheTtl)
            {
                return _cache;
            }

            _cache = LoadFromWmi();
            _cacheAt = DateTimeOffset.UtcNow;
            return _cache;
        }
    }

    private Dictionary<int, List<ServiceRecord>> LoadFromWmi()
    {
        var map = new Dictionary<int, List<ServiceRecord>>();
        try
        {
            // Win32_Service available on Server 2012. ProcessId is 0 when stopped.
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, ProcessId, StartName, PathName, State, StartMode FROM Win32_Service WHERE ProcessId > 0");
            foreach (ManagementObject obj in searcher.Get())
            {
                var pid = Convert.ToInt32(obj["ProcessId"]);
                var record = new ServiceRecord
                {
                    TimestampUtc = DateTimeOffset.UtcNow,
                    ComputerName = _agentOptions.ComputerName,
                    AgentId = _agentOptions.AgentId,
                    ProcessId = pid,
                    ServiceName = obj["Name"]?.ToString() ?? string.Empty,
                    DisplayName = obj["DisplayName"]?.ToString(),
                    StartAccount = obj["StartName"]?.ToString(),
                    ImagePath = obj["PathName"]?.ToString(),
                    State = obj["State"]?.ToString(),
                    StartMode = obj["StartMode"]?.ToString()
                };

                if (!map.TryGetValue(pid, out var list))
                {
                    list = [];
                    map[pid] = list;
                }

                list.Add(record);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to query Win32_Service");
        }

        return map;
    }
}
