using NTShield.Shared.Models;

namespace NTShield.Core.Abstractions;

public interface IResponseExecutor
{
    /// <summary>Default detect-only path for local detections.</summary>
    Task<ResponseActionRecord> ExecuteAsync(DetectionAlert alert, CancellationToken cancellationToken);

    /// <summary>Explicit action from Central (must pass allowlist + approval for destructive ops).</summary>
    Task<ResponseActionRecord> ExecuteRequestAsync(ResponseActionRequest request, CancellationToken cancellationToken);
}

public interface IEvidenceCollector
{
    Task<string> CollectAndExportZipAsync(Incident incident, CancellationToken cancellationToken);
}
