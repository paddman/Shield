using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;

namespace NTShield.Server.Services;

public sealed class IngestService
{
    private readonly ICentralStore _store;
    private readonly CrossHostCorrelator _correlator;
    private readonly LateralMovementTracker _lateral;
    private readonly ILogger<IngestService> _logger;

    public IngestService(
        ICentralStore store,
        CrossHostCorrelator correlator,
        LateralMovementTracker lateral,
        ILogger<IngestService> logger)
    {
        _store = store;
        _correlator = correlator;
        _lateral = lateral;
        _logger = logger;
    }

    public async Task<IngestResponse> IngestAsync(AgentIngestBatch batch, CancellationToken cancellationToken)
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

            var incidents = await _correlator.CorrelateAsync(batch, cancellationToken);
            foreach (var incident in incidents)
            {
                await _store.UpsertIncidentAsync(incident);
                _logger.LogWarning("INCIDENT\n{Display}", incident.FormatDisplay());
            }

            // Follow threats across hosts (A→B→C) without performing any offensive action.
            var campaigns = _lateral.IngestIncidents(incidents);
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
                CreatedIncidentIds = incidents.Select(i => i.IncidentId).ToList()
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
}
