using System.Runtime.Versioning;
using NTShield.Collectors.Windows.Native;
using NTShield.Collectors.Windows.Process;
using NTShield.Core.Abstractions;
using NTShield.Core.Compatibility;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Collectors.Windows.Network;

/// <summary>
/// Network collector using GetExtendedTcpTable / GetExtendedUdpTable with snapshot diff.
/// Does not use netstat as the primary method.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpHelperNetworkCollector : INetworkCollector
{
    private readonly NetworkCollectorOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly IServiceResolver _serviceResolver;
    private readonly ProcessEnricher _enricher;
    private readonly ILogger<IpHelperNetworkCollector> _logger;
    private HashSet<string> _previousKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NetworkConnectionRecord> _previousRecords = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _hashedPids = [];

    public IpHelperNetworkCollector(
        IOptions<NetworkCollectorOptions> options,
        IOptions<AgentOptions> agentOptions,
        IServiceResolver serviceResolver,
        ProcessEnricher enricher,
        ILogger<IpHelperNetworkCollector> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _serviceResolver = serviceResolver;
        _enricher = enricher;
        _logger = logger;
    }

    public async Task<IReadOnlyList<NetworkConnectionRecord>> CollectDiffAsync(CancellationToken cancellationToken)
    {
        if (!WindowsCompatibility.SupportsIpHelperExtendedTables)
        {
            _logger.LogError("IP Helper extended tables not supported on this OS");
            return Array.Empty<NetworkConnectionRecord>();
        }

        var now = DateTimeOffset.UtcNow;
        var current = new Dictionary<string, NetworkConnectionRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in IpHelperNative.GetTcpConnections())
        {
            var key = $"TCP|{row.LocalAddress}|{row.LocalPort}|{row.RemoteAddress}|{row.RemotePort}|{row.ProcessId}|{(int)row.State}";
            var rec = new NetworkConnectionRecord
            {
                TimestampUtc = now,
                ComputerName = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                Protocol = "TCP",
                LocalAddress = row.LocalAddress,
                LocalPort = row.LocalPort,
                RemoteAddress = row.RemoteAddress,
                RemotePort = row.RemotePort,
                TcpState = row.State,
                ProcessId = row.ProcessId,
                ConnectionKey = key
            };
            current[key] = rec;
        }

        if (_options.CaptureUdp)
        {
            foreach (var row in IpHelperNative.GetUdpListeners())
            {
                var key = $"UDP|{row.LocalAddress}|{row.LocalPort}|-|-|{row.ProcessId}|0";
                var rec = new NetworkConnectionRecord
                {
                    TimestampUtc = now,
                    ComputerName = _agentOptions.ComputerName,
                    AgentId = _agentOptions.AgentId,
                    Protocol = "UDP",
                    LocalAddress = row.LocalAddress,
                    LocalPort = row.LocalPort,
                    RemoteAddress = string.Empty,
                    RemotePort = 0,
                    ProcessId = row.ProcessId,
                    ConnectionKey = key
                };
                current[key] = rec;
            }
        }

        var diffs = new List<NetworkConnectionRecord>();
        var currentKeys = current.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // New connections
        foreach (var (key, rec) in current)
        {
            if (_previousKeys.Contains(key))
            {
                continue;
            }

            rec.IsNew = true;
            await EnrichAsync(rec, cancellationToken);
            diffs.Add(rec);
        }

        // Closed connections
        foreach (var key in _previousKeys)
        {
            if (currentKeys.Contains(key))
            {
                continue;
            }

            if (_previousRecords.TryGetValue(key, out var prev))
            {
                var closed = Clone(prev);
                closed.TimestampUtc = now;
                closed.IsNew = false;
                closed.IsClosed = true;
                diffs.Add(closed);
            }
        }

        _previousKeys = currentKeys;
        _previousRecords.Clear();
        foreach (var (key, rec) in current)
        {
            _previousRecords[key] = rec;
        }

        return diffs;
    }

    private async Task EnrichAsync(NetworkConnectionRecord rec, CancellationToken cancellationToken)
    {
        if (!_options.ResolveProcessDetails)
        {
            return;
        }

        try
        {
            var hash = _options.HashNewExecutables && _hashedPids.Add(rec.ProcessId);
            var details = _enricher.GetDetails(rec.ProcessId, hash);
            rec.ProcessName = details.ProcessName;
            rec.ProcessPath = details.ProcessPath;
            rec.ProcessCommandLine = details.CommandLine;
            rec.ProcessOwner = details.Owner;
            rec.ParentProcessId = details.ParentProcessId;
            rec.DigitalSignatureStatus = details.DigitalSignatureStatus;
            rec.SignerName = details.SignerName;
            rec.ExecutableSha256 = details.ExecutableSha256;

            if (_options.ResolveServices)
            {
                var services = await _serviceResolver.ResolveByProcessIdAsync(rec.ProcessId, cancellationToken);
                if (services.Count > 0)
                {
                    // Never report only "svchost.exe" — attach all services in the PID.
                    rec.ServiceNames = string.Join(", ", services.Select(s => s.ServiceName));
                    rec.ServiceDisplayNames = string.Join(", ", services.Select(s => s.DisplayName ?? s.ServiceName));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to enrich connection for PID {Pid}", rec.ProcessId);
        }
    }

    private static NetworkConnectionRecord Clone(NetworkConnectionRecord s) => new()
    {
        TimestampUtc = s.TimestampUtc,
        ComputerName = s.ComputerName,
        AgentId = s.AgentId,
        Protocol = s.Protocol,
        LocalAddress = s.LocalAddress,
        LocalPort = s.LocalPort,
        RemoteAddress = s.RemoteAddress,
        RemotePort = s.RemotePort,
        TcpState = s.TcpState,
        ProcessId = s.ProcessId,
        ProcessName = s.ProcessName,
        ProcessPath = s.ProcessPath,
        ProcessCommandLine = s.ProcessCommandLine,
        ProcessOwner = s.ProcessOwner,
        ParentProcessId = s.ParentProcessId,
        DigitalSignatureStatus = s.DigitalSignatureStatus,
        SignerName = s.SignerName,
        ExecutableSha256 = s.ExecutableSha256,
        ServiceNames = s.ServiceNames,
        ServiceDisplayNames = s.ServiceDisplayNames,
        ConnectionKey = s.ConnectionKey
    };
}
