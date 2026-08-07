using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.AI;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class IngestService
{
    private readonly ICentralStore _store;
    private readonly CrossHostCorrelator _correlator;
    private readonly LateralMovementTracker _lateral;
    private readonly ILogger<IngestService> _logger;
    private readonly TelemetryFeatureBuilder? _featureBuilder;
    private readonly AiAnomalyProxyService? _anomaly;

    public IngestService(
        ICentralStore store,
        CrossHostCorrelator correlator,
        LateralMovementTracker lateral,
        ILogger<IngestService> logger,
        TelemetryFeatureBuilder? featureBuilder = null,
        AiAnomalyProxyService? anomaly = null)
    {
        _store = store;
        _correlator = correlator;
        _lateral = lateral;
        _logger = logger;
        _featureBuilder = featureBuilder;
        _anomaly = anomaly;
    }

    public async Task<IngestResponse> IngestAsync(
        AgentIngestBatch batch,
        CancellationToken cancellationToken,
        string tenantId = "default")
    {
        var count = batch.SecurityEvents.Count
                    + batch.NetworkConnections.Count
                    + batch.Processes.Count
                    + batch.Services.Count
                    + batch.ScheduledTasks.Count
                    + batch.Alerts.Count;

        try
        {
            if (!string.IsNullOrWhiteSpace(batch.IdempotencyKey))
            {
                if (await _store.HasIdempotencyKeyAsync(batch.IdempotencyKey))
                {
                    return new IngestResponse
                    {
                        Accepted = true,
                        Duplicate = true,
                        ReceivedCount = 0,
                        Message = "duplicate idempotency key"
                    };
                }
            }

            await _store.SaveBatchAsync(batch);

            if (!string.IsNullOrWhiteSpace(batch.IdempotencyKey))
            {
                await _store.SaveIdempotencyKeyAsync(batch.IdempotencyKey);
            }

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
                    cancellationToken);
            }

            var incidents = (await _correlator.CorrelateAsync(batch, cancellationToken)).ToList();

            // Detection alerts are already the agent's correlated output. Keep them
            // visible in the same incident/campaign pipeline as Central-correlated
            // security events instead of only storing them as raw batch telemetry.
            incidents.AddRange(batch.Alerts
                .Where(alert => !alert.Suppressed)
                .Select(alert => IncidentFromAlert(alert, batch)));

            foreach (var incident in incidents)
            {
                await _store.UpsertIncidentAsync(incident);
                _logger.LogWarning("INCIDENT\n{Display}", incident.FormatDisplay());
            }

            // Follow threats across hosts (A→B→C) without performing any offensive action.
            var campaigns = _lateral.IngestIncidents(incidents);
            if (anomaly is not null)
            {
                _lateral.ApplyAnomaly(
                    batch.AgentId,
                    anomaly.Score,
                    anomaly.Confidence,
                    anomaly.BaselineSamples,
                    anomaly.Model,
                    batch.SentAtUtc,
                    anomaly.Contributors.Select(item => item.Name));
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
            _logger.LogError(ex, "Ingest failed for agent {AgentId}", batch.AgentId);
            return new IngestResponse
            {
                Accepted = false,
                ReceivedCount = count,
                Message = ex.Message
            };
        }
    }

    private static Incident IncidentFromAlert(DetectionAlert alert, AgentIngestBatch batch)
    {
        var title = string.IsNullOrWhiteSpace(alert.Title)
            ? (string.IsNullOrWhiteSpace(alert.RuleName) ? alert.RuleId : alert.RuleName)
            : alert.Title;
        var incidentId = string.IsNullOrWhiteSpace(alert.AlertId)
            ? Guid.NewGuid().ToString("N")
            : $"alert-{alert.AlertId}";

        return new Incident
        {
            IncidentId = incidentId,
            Title = string.IsNullOrWhiteSpace(title) ? "Detection alert" : title,
            RuleId = alert.RuleId,
            Severity = alert.Severity,
            SourceIp = alert.SourceIp,
            DestinationIp = alert.DestinationIp,
            DestinationHost = string.IsNullOrWhiteSpace(alert.ComputerName) ? batch.ComputerName : alert.ComputerName,
            DestinationAgentId = string.IsNullOrWhiteSpace(alert.AgentId) ? batch.AgentId : alert.AgentId,
            Username = alert.Username,
            FailedAttempts = alert.EventCount,
            DistinctUsernames = alert.DistinctUserCount,
            FirstSeen = alert.TimestampUtc,
            LastSeen = alert.TimestampUtc,
            Description = alert.Description,
            CorrelationKey = $"alert|{alert.AlertId}",
            EvidenceJson = alert.EvidenceJson,
            Status = "Open"
        };
    }
}
