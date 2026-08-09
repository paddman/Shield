using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.AI;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NTShield.Server.Services;

public sealed class IngestService
{
    private static readonly TimeSpan IdempotencyLeaseDuration = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan IdempotencyRenewInterval = TimeSpan.FromSeconds(30);
    private const int MaxIdempotencyKeyLength = 512;
    private readonly ICentralStore _store;
    private readonly CrossHostCorrelator _correlator;
    private readonly LateralMovementTracker _lateral;
    private readonly ILogger<IngestService> _logger;
    private readonly TelemetryFeatureBuilder? _featureBuilder;
    private readonly AiAnomalyProxyService? _anomaly;
    private readonly TemporalAttackChainService? _temporal;

    public IngestService(
        ICentralStore store,
        CrossHostCorrelator correlator,
        LateralMovementTracker lateral,
        ILogger<IngestService> logger,
        TelemetryFeatureBuilder? featureBuilder = null,
        AiAnomalyProxyService? anomaly = null,
        TemporalAttackChainService? temporal = null)
    {
        _store = store;
        _correlator = correlator;
        _lateral = lateral;
        _logger = logger;
        _featureBuilder = featureBuilder;
        _anomaly = anomaly;
        _temporal = temporal;
    }

    public async Task<IngestResponse> IngestAsync(
        AgentIngestBatch batch,
        CancellationToken cancellationToken,
        string tenantId = "default")
    {
        tenantId = NormalizeTenantScope(tenantId);
        var count = batch.SecurityEvents.Count
                    + batch.NetworkConnections.Count
                    + batch.Processes.Count
                    + batch.Services.Count
                    + batch.ScheduledTasks.Count
                    + batch.Alerts.Count;

        string? idempotencyKeyHash = null;
        string? idempotencyAgentId = null;
        string? idempotencyLeaseOwner = null;
        var ownsIdempotencyClaim = false;
        CancellationTokenSource? processingCts = null;
        Task? renewalTask = null;
        var leaseLost = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            if (!string.IsNullOrWhiteSpace(batch.IdempotencyKey))
            {
                idempotencyKeyHash = HashIdempotencyKey(batch.IdempotencyKey);
                idempotencyAgentId = NormalizeAgentScope(batch.AgentId);
                idempotencyLeaseOwner = Guid.NewGuid().ToString("N");
                var claimedAtUtc = DateTimeOffset.UtcNow;
                var claimState = await _store.TryClaimIngestIdempotencyAsync(
                    tenantId,
                    idempotencyAgentId,
                    idempotencyKeyHash,
                    idempotencyLeaseOwner,
                    claimedAtUtc,
                    claimedAtUtc.Add(IdempotencyLeaseDuration),
                    cancellationToken);
                if (claimState == IngestIdempotencyClaimState.Completed)
                {
                    return new IngestResponse
                    {
                        Accepted = true,
                        Duplicate = true,
                        ReceivedCount = 0,
                        Message = "duplicate idempotency key"
                    };
                }
                if (claimState == IngestIdempotencyClaimState.InProgress)
                {
                    return new IngestResponse
                    {
                        Accepted = false,
                        Duplicate = true,
                        ReceivedCount = 0,
                        Message = "idempotency key is already processing; retry"
                    };
                }

                ownsIdempotencyClaim = true;
                processingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                renewalTask = RenewIdempotencyClaimAsync(
                    tenantId,
                    idempotencyAgentId,
                    idempotencyKeyHash,
                    idempotencyLeaseOwner,
                    processingCts,
                    leaseLost);
            }

            var processingToken = processingCts?.Token ?? cancellationToken;
            await _store.SaveBatchAsync(batch, tenantId);
            processingToken.ThrowIfCancellationRequested();

            // Phase 1: observe bounded telemetry features against the Brain's
            // per-tenant/per-asset baseline. This is intentionally fail-open;
            // Central must continue accepting telemetry during AI downtime.
            AiAnomalyObservationResponse? anomaly = null;
            if (_featureBuilder is not null && _anomaly is not null)
            {
                anomaly = await _anomaly.ObserveAsync(
                    tenantId,
                    batch.AgentId,
                    _featureBuilder.Build(batch),
                    batch.SentAtUtc,
                    processingToken);
            }

            var incidents = (await _correlator.CorrelateAsync(batch, processingToken, tenantId)).ToList();

            foreach (var incident in incidents)
            {
                await _store.UpsertIncidentAsync(incident, tenantId);
                _logger.LogWarning("INCIDENT\n{Display}", incident.FormatDisplay());
            }

            // Follow threats across hosts (A→B→C) without performing any offensive action.
            var campaigns = _lateral.IngestIncidents(incidents, tenantId);
            if (anomaly is not null)
            {
                _lateral.ApplyAnomaly(
                    batch.AgentId,
                    anomaly.Score,
                    anomaly.Confidence,
                    anomaly.BaselineSamples,
                    anomaly.Model,
                    batch.SentAtUtc,
                    anomaly.Contributors.Select(item => item.Name),
                    tenantId);
            }

            // Phase 2 work is durably staged before the ingest idempotency key is
            // committed. The worker can therefore retry after process/DB failures,
            // including batches that do not yet match a legacy campaign.
            if (_temporal is not null)
            {
                var campaignSnapshot = _lateral.ListCampaigns(500, tenantId).ToList();
                var envelopeJson = JsonSerializer.Serialize(new TemporalCorrelationEnvelope
                {
                    Batch = CreateTemporalBatch(batch),
                    Incidents = incidents,
                    Campaigns = campaignSnapshot
                }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                var workIdentity = !string.IsNullOrWhiteSpace(batch.IdempotencyKey)
                    ? $"{tenantId}|{idempotencyAgentId}|{idempotencyKeyHash}"
                    : $"{tenantId}|{batch.AgentId}|{batch.SentAtUtc:O}|{Guid.NewGuid():N}";
                var workId = "temporal-" + Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(workIdentity))).ToLowerInvariant()[..32];
                await _store.EnqueueTemporalCorrelationWorkAsync(new TemporalCorrelationWorkItem
                {
                    WorkId = workId,
                    TenantId = tenantId,
                    PayloadJson = envelopeJson,
                    EnqueuedAtUtc = DateTimeOffset.UtcNow
                }, processingToken);
            }

            if (ownsIdempotencyClaim)
            {
                processingCts!.Cancel();
                if (renewalTask is not null) await AwaitRenewalShutdownAsync(renewalTask);
                if (leaseLost.Task.IsCompleted)
                    throw new InvalidOperationException("The ingest idempotency lease was lost before completion.");
                if (!await _store.CompleteIngestIdempotencyClaimAsync(
                        tenantId,
                        idempotencyAgentId!,
                        idempotencyKeyHash!,
                        idempotencyLeaseOwner!,
                        DateTimeOffset.UtcNow,
                        CancellationToken.None))
                {
                    throw new InvalidOperationException("The ingest idempotency claim could not be completed by its owner.");
                }
                ownsIdempotencyClaim = false;
            }
            foreach (var campaign in campaigns.Where(c => c.Hops.Count > 1))
            {
                _logger.LogWarning("LATERAL PATH\n{Display}", campaign.FormatDisplay());
            }

            return new IngestResponse
            {
                Accepted = true,
                ReceivedCount = count,
                Message = campaigns.Count > 0
                    ? $"ok; threats_tracked={campaigns.Count}; multi_hop={campaigns.Count(c => c.Hops.Count > 1)}"
                    : "ok",
                CreatedIncidentIds = incidents.Select(i => i.IncidentId).ToList(),
                AnomalyState = anomaly?.State,
                AnomalyScore = anomaly?.Score,
                AnomalyConfidence = anomaly?.Confidence,
                AnomalyBaselineSamples = anomaly?.BaselineSamples,
                AnomalyModel = anomaly?.Model
            };
        }
        catch (Exception ex)
        {
            processingCts?.Cancel();
            if (renewalTask is not null) await AwaitRenewalShutdownAsync(renewalTask);
            if (ownsIdempotencyClaim)
            {
                try
                {
                    await _store.ReleaseIngestIdempotencyClaimAsync(
                        tenantId,
                        idempotencyAgentId!,
                        idempotencyKeyHash!,
                        idempotencyLeaseOwner!,
                        CancellationToken.None);
                }
                catch (Exception releaseError)
                {
                    _logger.LogError(
                        releaseError,
                        "Failed releasing ingest idempotency claim tenant={Tenant} agent={AgentId}",
                        tenantId,
                        batch.AgentId);
                }
            }
            _logger.LogError(ex, "Ingest failed for agent {AgentId}", batch.AgentId);
            return new IngestResponse
            {
                Accepted = false,
                ReceivedCount = count,
                Message = ex.Message
            };
        }
        finally
        {
            processingCts?.Cancel();
            processingCts?.Dispose();
        }
    }

    private async Task RenewIdempotencyClaimAsync(
        string tenantId,
        string agentId,
        string keyHash,
        string leaseOwner,
        CancellationTokenSource processingCts,
        TaskCompletionSource leaseLost)
    {
        try
        {
            while (!processingCts.IsCancellationRequested)
            {
                await Task.Delay(IdempotencyRenewInterval, processingCts.Token);
                var now = DateTimeOffset.UtcNow;
                if (await _store.RenewIngestIdempotencyClaimAsync(
                        tenantId,
                        agentId,
                        keyHash,
                        leaseOwner,
                        now,
                        now.Add(IdempotencyLeaseDuration),
                        processingCts.Token))
                    continue;

                leaseLost.TrySetResult();
                processingCts.Cancel();
                _logger.LogError(
                    "Lost ingest idempotency lease tenant={Tenant} agent={AgentId}",
                    tenantId,
                    agentId);
                return;
            }
        }
        catch (OperationCanceledException) when (processingCts.IsCancellationRequested)
        {
            // Normal shutdown after completion, request cancellation, or failure.
        }
        catch (Exception ex)
        {
            leaseLost.TrySetResult();
            processingCts.Cancel();
            _logger.LogError(
                ex,
                "Failed renewing ingest idempotency lease tenant={Tenant} agent={AgentId}",
                tenantId,
                agentId);
        }
    }

    private static async Task AwaitRenewalShutdownAsync(Task renewalTask)
    {
        try
        {
            await renewalTask;
        }
        catch (OperationCanceledException)
        {
            // The linked processing token is intentionally cancelled at shutdown.
        }
    }

    private static string HashIdempotencyKey(string key)
    {
        key = key.Trim();
        if (key.Length is < 1 or > MaxIdempotencyKeyLength)
            throw new InvalidDataException(
                $"Idempotency key must contain 1-{MaxIdempotencyKeyLength} characters.");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant();
    }

    private static string NormalizeAgentScope(string agentId)
    {
        agentId = agentId?.Trim().ToLowerInvariant() ?? string.Empty;
        if (agentId.Length is < 1 or > 256)
            throw new InvalidDataException("A valid authenticated agent id is required for idempotent ingest.");
        return agentId;
    }

    private static string NormalizeTenantScope(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? "default" : tenantId.Trim().ToLowerInvariant();

    private static AgentIngestBatch CreateTemporalBatch(AgentIngestBatch batch) => new()
    {
        AgentId = batch.AgentId,
        ComputerName = batch.ComputerName,
        AgentVersion = batch.AgentVersion,
        SentAtUtc = batch.SentAtUtc,
        ClockSkewSeconds = batch.ClockSkewSeconds,
        ClockSkewMeasuredAtUtc = batch.ClockSkewMeasuredAtUtc,
        // The transport idempotency secret is not temporal evidence and must not
        // be copied into a durable outbox payload.
        IdempotencyKey = null,
        SecurityEvents = batch.SecurityEvents,
        NetworkConnections = batch.NetworkConnections,
        Processes = batch.Processes,
        Services = batch.Services,
        ScheduledTasks = batch.ScheduledTasks,
        Alerts = batch.Alerts
    };
}
