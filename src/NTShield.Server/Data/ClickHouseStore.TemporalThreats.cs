using NTShield.Shared.Models;

namespace NTShield.Server.Data;

public sealed partial class ClickHouseStore
{
    public Task UpsertThreatCampaignV2SummaryAsync(
        ThreatCampaignV2Summary summary,
        CancellationToken cancellationToken = default) =>
        _control.UpsertThreatCampaignV2SummaryAsync(summary, cancellationToken);

    public Task<ThreatCampaignV2Summary?> GetThreatCampaignV2SummaryAsync(
        string tenantId,
        string campaignId,
        CancellationToken cancellationToken = default) =>
        _control.GetThreatCampaignV2SummaryAsync(tenantId, campaignId, cancellationToken);

    public Task<IReadOnlyList<ThreatCampaignV2Summary>> ListThreatCampaignV2SummariesAsync(
        string tenantId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        string? status,
        string? severity,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterCampaignId,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatCampaignV2SummariesAsync(
            tenantId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc, status, severity,
            afterLastObservedAtUtc, afterCampaignId, take, cancellationToken);

    public Task<long> CountActiveThreatCampaignsAsync(
        string tenantId,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        _control.CountActiveThreatCampaignsAsync(
            tenantId, fromObservedAtUtc, toObservedAtUtc, cancellationToken);

    public async Task<bool> TryAppendThreatObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default)
    {
        var inserted = await _control.TryAppendThreatObservationAsync(observation, cancellationToken);
        if (inserted)
        {
            await WriteAsync(
                "threat_observation_v2",
                observation.ObservationId,
                observation.ObservedAtUtc,
                observation.SourceAgentId ?? observation.DestinationAgentId ?? string.Empty,
                observation,
                observation.TenantId);
        }
        return inserted;
    }

    public Task UpsertThreatObservationMembershipAsync(
        ThreatObservationMembership membership,
        CancellationToken cancellationToken = default) =>
        _control.UpsertThreatObservationMembershipAsync(membership, cancellationToken);

    public async Task<bool> TryAppendThreatCandidateObservationAsync(
        ThreatObservation observation,
        CancellationToken cancellationToken = default)
    {
        var inserted = await _control.TryAppendThreatCandidateObservationAsync(observation, cancellationToken);
        if (inserted)
        {
            await WriteAsync(
                "threat_candidate_observation_v2",
                observation.ObservationId,
                observation.ObservedAtUtc,
                observation.SourceAgentId ?? observation.DestinationAgentId ?? string.Empty,
                observation,
                observation.TenantId);
        }
        return inserted;
    }

    public Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateObservationsAsync(
        string tenantId,
        string contactId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatCandidateObservationsAsync(
            tenantId, contactId, fromObservedAtUtc, toObservedAtUtc, take, cancellationToken);

    public Task<IReadOnlyList<ThreatObservation>> ListThreatCandidateContextObservationsAsync(
        string tenantId,
        string firstNodeId,
        string secondNodeId,
        DateTimeOffset fromObservedAtUtc,
        DateTimeOffset toObservedAtUtc,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatCandidateContextObservationsAsync(
            tenantId, firstNodeId, secondNodeId,
            fromObservedAtUtc, toObservedAtUtc, take, cancellationToken);

    public Task MarkThreatCampaignMergedAsync(
        string tenantId,
        string campaignId,
        string mergedIntoCampaignId,
        DateTimeOffset tombstonedAtUtc,
        CancellationToken cancellationToken = default) =>
        _control.MarkThreatCampaignMergedAsync(
            tenantId, campaignId, mergedIntoCampaignId, tombstonedAtUtc, cancellationToken);

    public Task<IReadOnlyList<ThreatObservation>> ListThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterObservedAtUtc,
        string? afterObservationId,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatObservationsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc,
            afterObservedAtUtc, afterObservationId, take, cancellationToken);

    public Task<long> CountThreatObservationsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        _control.CountThreatObservationsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc, cancellationToken);

    public Task<long> CountThreatObservationDetailsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        _control.CountThreatObservationDetailsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc, cancellationToken);

    public Task<IReadOnlyList<ThreatTimelineBucket>> ListThreatTimelineBucketsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        int resolutionSeconds,
        DateTimeOffset? afterBucketStartUtc,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatTimelineBucketsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc,
            resolutionSeconds, afterBucketStartUtc, take, cancellationToken);

    public Task<IReadOnlyList<ThreatContactAggregate>> ListThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc,
        DateTimeOffset? toObservedAtUtc,
        DateTimeOffset? afterLastObservedAtUtc,
        string? afterContactId,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.ListThreatContactsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc,
            afterLastObservedAtUtc, afterContactId, take, cancellationToken);

    public Task<long> CountThreatContactsAsync(
        string tenantId,
        string campaignId,
        DateTimeOffset watermarkUtc,
        DateTimeOffset? fromObservedAtUtc = null,
        DateTimeOffset? toObservedAtUtc = null,
        CancellationToken cancellationToken = default) =>
        _control.CountThreatContactsAsync(
            tenantId, campaignId, watermarkUtc, fromObservedAtUtc, toObservedAtUtc, cancellationToken);

    public Task EnqueueTemporalCorrelationWorkAsync(
        TemporalCorrelationWorkItem item,
        CancellationToken cancellationToken = default) =>
        _control.EnqueueTemporalCorrelationWorkAsync(item, cancellationToken);

    public Task<IReadOnlyList<TemporalCorrelationWorkItem>> LeaseTemporalCorrelationWorkAsync(
        string leaseOwner,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int take,
        CancellationToken cancellationToken = default) =>
        _control.LeaseTemporalCorrelationWorkAsync(
            leaseOwner, nowUtc, leaseDuration, take, cancellationToken);

    public Task CompleteTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        CancellationToken cancellationToken = default) =>
        _control.CompleteTemporalCorrelationWorkAsync(workId, leaseOwner, cancellationToken);

    public Task FailTemporalCorrelationWorkAsync(
        string workId,
        string leaseOwner,
        DateTimeOffset retryAtUtc,
        string error,
        CancellationToken cancellationToken = default) =>
        _control.FailTemporalCorrelationWorkAsync(
            workId, leaseOwner, retryAtUtc, error, cancellationToken);

    public Task<int> SweepTemporalThreatDataAsync(
        DateTimeOffset detailBeforeUtc,
        DateTimeOffset aggregateBeforeUtc,
        CancellationToken cancellationToken = default) =>
        _control.SweepTemporalThreatDataAsync(
            detailBeforeUtc, aggregateBeforeUtc, cancellationToken);

    public Task<string?> GetTemporalBackfillCursorAsync(CancellationToken cancellationToken = default) =>
        _control.GetTemporalBackfillCursorAsync(cancellationToken);

    public Task SaveTemporalBackfillCursorAsync(
        string? campaignId,
        CancellationToken cancellationToken = default) =>
        _control.SaveTemporalBackfillCursorAsync(campaignId, cancellationToken);
}
