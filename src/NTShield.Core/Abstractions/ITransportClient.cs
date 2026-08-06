using NTShield.Shared.Contracts;

namespace NTShield.Core.Abstractions;

public interface ITransportClient
{
    Task<bool> IsReachableAsync(CancellationToken cancellationToken);
    Task<IngestResponse?> SendBatchAsync(AgentIngestBatch batch, CancellationToken cancellationToken);
    /// <summary>Returns heartbeat response including pending approved actions from Central.</summary>
    Task<HeartbeatResponse?> SendHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken cancellationToken);
    /// <summary>Enroll with Central; may return AgentApiKey to persist.</summary>
    Task<AgentRegistrationResponse?> RegisterAsync(AgentRegistrationRequest request, CancellationToken cancellationToken);
    /// <summary>Update runtime API key header (after enrollment).</summary>
    void SetApiKey(string? apiKey);
}
