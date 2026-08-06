using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Core.Abstractions;

public interface ILocalStore : IAsyncDisposable
{
    Task InitializeAsync(CancellationToken cancellationToken);

    Task SaveSecurityEventsAsync(IEnumerable<SecurityEventRecord> events, CancellationToken cancellationToken);
    Task SaveNetworkConnectionsAsync(IEnumerable<NetworkConnectionRecord> connections, CancellationToken cancellationToken);
    Task SaveProcessesAsync(IEnumerable<ProcessRecord> processes, CancellationToken cancellationToken);
    Task SaveServicesAsync(IEnumerable<ServiceRecord> services, CancellationToken cancellationToken);
    Task SaveScheduledTasksAsync(IEnumerable<ScheduledTaskRecord> tasks, CancellationToken cancellationToken);
    Task SaveAlertAsync(DetectionAlert alert, CancellationToken cancellationToken);
    Task SaveResponseActionAsync(ResponseActionRecord action, CancellationToken cancellationToken);

    Task<IReadOnlyList<SecurityEventRecord>> QuerySecurityEventsAsync(
        DateTimeOffset fromUtc,
        DateTimeOffset toUtc,
        int? eventId = null,
        CancellationToken cancellationToken = default);

    Task<string?> GetStateAsync(string key, CancellationToken cancellationToken = default);
    Task SetStateAsync(string key, string value, CancellationToken cancellationToken = default);

    Task EnqueueOutboundAsync(QueueItemType type, string payloadJson, CancellationToken cancellationToken);
    Task<IReadOnlyList<OutboundQueueItem>> DequeueOutboundBatchAsync(int batchSize, CancellationToken cancellationToken);
    Task MarkOutboundSentAsync(IEnumerable<long> ids, CancellationToken cancellationToken);
    Task MarkOutboundFailedAsync(long id, string error, CancellationToken cancellationToken);
    Task<long> GetOutboundQueueDepthAsync(CancellationToken cancellationToken);

    Task RunMaintenanceAsync(CancellationToken cancellationToken);
    Task<long> GetDatabaseSizeBytesAsync(CancellationToken cancellationToken);

    Task ProtectSecretAsync(string name, string plaintext, CancellationToken cancellationToken);
    Task<string?> UnprotectSecretAsync(string name, CancellationToken cancellationToken);
}

public sealed class OutboundQueueItem
{
    public long Id { get; set; }
    public QueueItemType ItemType { get; set; }
    public string PayloadJson { get; set; } = string.Empty;
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
}
