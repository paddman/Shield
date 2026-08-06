using NTShield.Shared.Models;

namespace NTShield.Core.Abstractions;

public interface IDetectionEngine
{
    Task InitializeAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<DetectionAlert>> EvaluateAsync(
        IReadOnlyList<SecurityEventRecord> recentEvents,
        IReadOnlyList<NetworkConnectionRecord> recentConnections,
        CancellationToken cancellationToken);
}
