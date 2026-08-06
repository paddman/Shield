using System.Net;
using System.Net.Sockets;
using System.Text;
using NTShield.Server.Data;
using NTShield.Server.Signatures;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Syslog;

/// <summary>
/// UDP syslog receiver (RFC3164/5424) + open-source signature matching.
/// Agents (or any device) can send syslog here in addition to HTTPS ingest.
/// </summary>
public sealed class SyslogListenerService : BackgroundService
{
    private readonly SyslogOptions _options;
    private readonly OpenSourceSignatureEngine _signatures;
    private readonly ICentralStore _store;
    private readonly ILogger<SyslogListenerService> _logger;
    private UdpClient? _udp;

    public SyslogListenerService(
        IOptions<SyslogOptions> options,
        OpenSourceSignatureEngine signatures,
        ICentralStore store,
        ILogger<SyslogListenerService> logger)
    {
        _options = options.Value;
        _signatures = signatures;
        _store = store;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Syslog listener disabled");
            return;
        }

        try
        {
            _udp = new UdpClient(new IPEndPoint(IPAddress.Any, _options.UdpPort));
            _logger.LogInformation("Syslog UDP listening on 0.0.0.0:{Port} (open-source signatures={On})",
                _options.UdpPort, _options.MatchOpenSourceSignatures);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to bind syslog UDP port {Port}", _options.UdpPort);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await _udp.ReceiveAsync(stoppingToken);
                var raw = Encoding.UTF8.GetString(result.Buffer);
                _ = Task.Run(() => ProcessAsync(raw, result.RemoteEndPoint), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Syslog receive error");
            }
        }
    }

    private async Task ProcessAsync(string raw, IPEndPoint remote)
    {
        try
        {
            var parsed = SyslogParser.Parse(raw, remote);
            var events = new List<SecurityEventRecord>
            {
                new()
                {
                    TimestampUtc = parsed.TimestampUtc,
                    ComputerName = parsed.Host,
                    AgentId = "syslog",
                    EventId = 0,
                    Channel = "Syslog",
                    ProviderName = parsed.AppName,
                    SourceIp = parsed.SourceIp,
                    RawXml = parsed.Raw.Length > 8000 ? parsed.Raw[..8000] : parsed.Raw,
                    EventRecordId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                }
            };

            var batch = new AgentIngestBatch
            {
                AgentId = "syslog",
                ComputerName = parsed.Host,
                AgentVersion = "syslog-1.0",
                SentAtUtc = DateTimeOffset.UtcNow,
                IdempotencyKey = Guid.NewGuid().ToString("N"),
                SecurityEvents = events
            };

            if (_options.MatchOpenSourceSignatures)
            {
                foreach (var hit in _signatures.Match(parsed))
                {
                    var alert = OpenSourceSignatureEngine.ToAlert(hit);
                    batch.Alerts.Add(alert);
                    var incident = OpenSourceSignatureEngine.ToIncident(hit);
                    await _store.UpsertIncidentAsync(incident);
                    _logger.LogWarning(
                        "SYSLOG SIG {Id} {Name} host={Host} from={Ip} sev={Sev}",
                        hit.Signature.Id, hit.Signature.Name, parsed.Host, parsed.SourceIp, hit.Signature.Severity);
                }
            }

            await _store.SaveBatchAsync(batch);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Syslog process failed");
        }
    }

    public override void Dispose()
    {
        _udp?.Dispose();
        base.Dispose();
    }
}
