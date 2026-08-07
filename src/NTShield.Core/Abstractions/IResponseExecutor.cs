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

public interface IFileProtectionService
{
    bool DefenderAvailable { get; }
    bool YaraAvailable { get; }
    string ProtectionStatus { get; }
    int RulePackVersion { get; }
    DateTimeOffset? LastScanUtc { get; }

    void Start();
    void Stop();
    IReadOnlyList<DetectionAlert> DrainAlerts();
    Task<FileScanResult> ScanFileAsync(string path, CancellationToken cancellationToken);
    Task<IReadOnlyList<FileScanResult>> ScanPathAsync(string path, CancellationToken cancellationToken);
    Task<QuarantineResult> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken);
    Task<QuarantineResult> RestoreQuarantinedFileAsync(string quarantineId, CancellationToken cancellationToken);
    bool TryApplyProtectionPack(ProtectionPack pack, out string error);
}
