using System.Collections.Concurrent;
using System.Threading.Channels;

namespace NTShield.Server.Correlation;

public sealed record TemporalThreatRevisionNotification(
    string CampaignId,
    long Revision,
    DateTimeOffset UpdatedAtUtc);

/// <summary>
/// In-process bounded wake-up channel for SSE clients. Durable truth remains in
/// the v2 tables; subscribers always re-read REST projections after a wake-up.
/// </summary>
public sealed class TemporalThreatRevisionNotifier
{
    private const int MaxSubscribersPerTenant = 100;
    private const int SubscriberCapacity = 32;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<Guid, Channel<TemporalThreatRevisionNotification>>> _tenants =
        new(StringComparer.OrdinalIgnoreCase);

    public Subscription Subscribe(string tenantId)
    {
        tenantId = NormalizeTenant(tenantId);
        var tenant = _tenants.GetOrAdd(tenantId, _ => new());
        if (tenant.Count >= MaxSubscribersPerTenant)
            throw new InvalidOperationException("temporal_stream_capacity");
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<TemporalThreatRevisionNotification>(new BoundedChannelOptions(SubscriberCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });
        if (!tenant.TryAdd(id, channel)) throw new InvalidOperationException("temporal_stream_subscribe_failed");
        return new Subscription(this, tenantId, id, channel.Reader);
    }

    public void Publish(string tenantId, TemporalThreatRevisionNotification notification)
    {
        if (!_tenants.TryGetValue(NormalizeTenant(tenantId), out var subscribers)) return;
        foreach (var channel in subscribers.Values) channel.Writer.TryWrite(notification);
    }

    private void Remove(string tenantId, Guid id)
    {
        if (!_tenants.TryGetValue(tenantId, out var tenant)) return;
        if (tenant.TryRemove(id, out var channel)) channel.Writer.TryComplete();
        if (tenant.IsEmpty) _tenants.TryRemove(tenantId, out _);
    }

    private static string NormalizeTenant(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? "default" : tenantId.Trim().ToLowerInvariant();

    public sealed class Subscription : IDisposable
    {
        private readonly TemporalThreatRevisionNotifier _owner;
        private readonly string _tenantId;
        private readonly Guid _id;
        private int _disposed;

        internal Subscription(
            TemporalThreatRevisionNotifier owner,
            string tenantId,
            Guid id,
            ChannelReader<TemporalThreatRevisionNotification> reader)
        {
            _owner = owner;
            _tenantId = tenantId;
            _id = id;
            Reader = reader;
        }

        public ChannelReader<TemporalThreatRevisionNotification> Reader { get; }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0) _owner.Remove(_tenantId, _id);
        }
    }
}
