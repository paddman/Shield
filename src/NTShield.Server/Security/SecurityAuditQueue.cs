using System.Threading.Channels;
using NTShield.Server.Data;

namespace NTShield.Server.Security;

public sealed record SecurityAuditEvent(
    string Actor,
    string Action,
    string? Target,
    string Result,
    string? DetailJson,
    string? SourceIp);

/// <summary>
/// Keeps authentication responses independent from a slow analytics/control-plane store.
/// The bounded queue deliberately drops excess audit events rather than blocking the 401 path;
/// queue saturation is emitted as a critical log signal.
/// </summary>
public sealed class SecurityAuditQueue : BackgroundService
{
    private readonly Channel<SecurityAuditEvent> _queue = Channel.CreateBounded<SecurityAuditEvent>(
        new BoundedChannelOptions(2048)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    private readonly ICentralStore _store;
    private readonly ILogger<SecurityAuditQueue> _logger;
    private long _dropped;

    public SecurityAuditQueue(ICentralStore store, ILogger<SecurityAuditQueue> logger)
    {
        _store = store;
        _logger = logger;
    }

    public bool TryEnqueue(SecurityAuditEvent entry)
    {
        if (_queue.Writer.TryWrite(entry)) return true;
        var dropped = Interlocked.Increment(ref _dropped);
        _logger.LogCritical("Security audit queue saturated; dropped={Dropped}", dropped);
        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var entry in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await _store.AppendAuditAsync(
                    entry.Actor,
                    entry.Action,
                    entry.Target,
                    entry.Result,
                    entry.DetailJson,
                    entry.SourceIp);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unable to persist security audit action={Action}", entry.Action);
            }
        }
    }
}
