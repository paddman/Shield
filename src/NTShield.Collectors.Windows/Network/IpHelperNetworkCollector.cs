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
    private readonly Dictionary<string, DateTimeOffset> _lastObservationUtc = new(StringComparer.OrdinalIgnoreCase);
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
            // TCP state changes are observations within one lifecycle, not a
            // synthetic close+reopen. A true reconnect receives a new
            // LifecycleId after the tuple disappears from a snapshot.
            var key = BuildConnectionKey(
                "TCP", row.LocalAddress, row.LocalPort, row.RemoteAddress, row.RemotePort, row.ProcessId);
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
            CarryLifecycle(key, rec, now);
            current[key] = rec;
        }

        if (_options.CaptureUdp)
        {
            foreach (var row in IpHelperNative.GetUdpListeners())
            {
                var key = BuildConnectionKey("UDP", row.LocalAddress, row.LocalPort, "", 0, row.ProcessId);
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
                CarryLifecycle(key, rec, now);
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
                var stateChanged = _previousRecords.TryGetValue(key, out var previous) &&
                                   previous.TcpState != rec.TcpState;
                var interval = TimeSpan.FromSeconds(Math.Clamp(
                    _options.ActiveConnectionObservationSeconds, 15, 3_600));
                var lastEmitted = _lastObservationUtc.TryGetValue(key, out var value)
                    ? value
                    : rec.StartedAtUtc ?? now;
                // UDP listener rows do not identify a remote contact, so a
                // periodic listener snapshot would add volume without chain evidence.
                var remoteContact = !string.IsNullOrWhiteSpace(rec.RemoteAddress);
                if (stateChanged || (remoteContact && now - lastEmitted >= interval))
                {
                    rec.IsNew = false;
                    rec.IsClosed = false;
                    diffs.Add(Clone(rec));
                    _lastObservationUtc[key] = now;
                }
                continue;
            }

            rec.IsNew = true;
            await EnrichAsync(rec, cancellationToken);
            diffs.Add(Clone(rec));
            _lastObservationUtc[key] = now;
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
                closed.EndedAtUtc = now;
                closed.IsNew = false;
                closed.IsClosed = true;
                diffs.Add(closed);
            }
            _lastObservationUtc.Remove(key);
        }

        _previousKeys = currentKeys;
        _previousRecords.Clear();
        foreach (var (key, rec) in current)
        {
            _previousRecords[key] = rec;
        }

        return diffs;
    }

    internal static string BuildConnectionKey(
        string protocol,
        string localAddress,
        int localPort,
        string remoteAddress,
        int remotePort,
        int processId) =>
        $"{protocol.ToUpperInvariant()}|{localAddress}|{localPort}|{remoteAddress}|{remotePort}|{processId}";

    private void CarryLifecycle(string key, NetworkConnectionRecord current, DateTimeOffset now)
    {
        if (!_previousRecords.TryGetValue(key, out var previous))
        {
            current.StartedAtUtc = now;
            current.LifecycleId = Guid.NewGuid().ToString("N");
            return;
        }

        current.StartedAtUtc = previous.StartedAtUtc ?? previous.TimestampUtc;
        current.LifecycleId = string.IsNullOrWhiteSpace(previous.LifecycleId)
            ? Guid.NewGuid().ToString("N")
            : previous.LifecycleId;
        current.ProcessName = previous.ProcessName;
        current.ProcessPath = previous.ProcessPath;
        current.ProcessCommandLine = previous.ProcessCommandLine;
        current.ProcessOwner = previous.ProcessOwner;
        current.ParentProcessId = previous.ParentProcessId;
        current.DigitalSignatureStatus = previous.DigitalSignatureStatus;
        current.SignerName = previous.SignerName;
        current.ExecutableSha256 = previous.ExecutableSha256;
        current.ServiceNames = previous.ServiceNames;
        current.ServiceDisplayNames = previous.ServiceDisplayNames;
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
        TenantId = s.TenantId,
        Id = s.Id,
        TimestampUtc = s.TimestampUtc,
        StartedAtUtc = s.StartedAtUtc,
        EndedAtUtc = s.EndedAtUtc,
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
        IsNew = s.IsNew,
        IsClosed = s.IsClosed,
        LifecycleId = s.LifecycleId,
        ConnectionKey = s.ConnectionKey
    };
}
