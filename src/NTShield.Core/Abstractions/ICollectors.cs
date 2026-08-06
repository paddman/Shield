using NTShield.Shared.Models;

namespace NTShield.Core.Abstractions;

public interface IEventLogCollector : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    event EventHandler<SecurityEventRecord>? EventReceived;
}

public interface INetworkCollector
{
    Task<IReadOnlyList<NetworkConnectionRecord>> CollectDiffAsync(CancellationToken cancellationToken);
}

public interface IProcessCollector
{
    Task<IReadOnlyList<ProcessRecord>> CollectAsync(CancellationToken cancellationToken);
}

public interface IServiceResolver
{
    Task<IReadOnlyList<ServiceRecord>> ResolveByProcessIdAsync(int processId, CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<int, IReadOnlyList<ServiceRecord>>> ResolveManyAsync(
        IEnumerable<int> processIds,
        CancellationToken cancellationToken);
}

public interface IScheduledTaskCollector
{
    Task<IReadOnlyList<ScheduledTaskRecord>> CollectChangesAsync(CancellationToken cancellationToken);
}
