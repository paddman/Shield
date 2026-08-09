using System.Text.Json;
using Microsoft.Extensions.Options;
using NTShield.Server.Data;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;

namespace NTShield.Server.Correlation;

public sealed class TemporalThreatOptions
{
    public const string SectionName = "TemporalThreats";
    public int DetailRetentionDays { get; set; } = 30;
    public int AggregateRetentionDays { get; set; } = 180;
    public int SweepIntervalMinutes { get; set; } = 60;
    public bool EnableLegacyBackfill { get; set; } = true;
    /// <summary>"shadow" keeps v1 authoritative; "v2" is an explicit deployment cutover flag.</summary>
    public string ProjectionMode { get; set; } = "shadow";
}

public sealed class TemporalCorrelationEnvelope
{
    public AgentIngestBatch Batch { get; set; } = new();
    public List<Incident> Incidents { get; set; } = [];
    public List<ThreatCampaign> Campaigns { get; set; } = [];
}

/// <summary>
/// Replays the durable temporal outbox. A lease is persisted in the control DB;
/// process termination therefore delays work until lease expiry instead of losing it.
/// </summary>
public sealed class TemporalCorrelationWorker : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ICentralStore _store;
    private readonly TemporalAttackChainService _service;
    private readonly ILogger<TemporalCorrelationWorker> _logger;
    private readonly TemporalThreatOptions _options;
    private readonly string _leaseOwner = $"{Environment.MachineName}-{Guid.NewGuid():N}";
    private DateTimeOffset _nextSweepUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _nextBackfillUtc = DateTimeOffset.MinValue;

    public TemporalCorrelationWorker(
        ICentralStore store,
        TemporalAttackChainService service,
        IOptions<TemporalThreatOptions> options,
        ILogger<TemporalCorrelationWorker> logger)
    {
        _store = store;
        _service = service;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        while (!stoppingToken.IsCancellationRequested)
        {
            var processed = false;
            try
            {
                var now = DateTimeOffset.UtcNow;
                if (now >= _nextSweepUtc)
                {
                    var detailDays = Math.Clamp(_options.DetailRetentionDays, 1, 365);
                    var aggregateDays = Math.Clamp(
                        _options.AggregateRetentionDays, detailDays, 3_650);
                    var changed = await _store.SweepTemporalThreatDataAsync(
                        now.AddDays(-detailDays), now.AddDays(-aggregateDays), stoppingToken);
                    _nextSweepUtc = now.AddMinutes(Math.Clamp(_options.SweepIntervalMinutes, 5, 1_440));
                    if (changed > 0)
                        _logger.LogInformation("Temporal retention sweep changed {Rows} rows", changed);
                }
                if (_options.EnableLegacyBackfill && now >= _nextBackfillUtc)
                {
                    var cursor = await _store.GetTemporalBackfillCursorAsync(stoppingToken);
                    var rows = await _store.ListCampaignJsonPageAsync(cursor, 500, stoppingToken);
                    var backfilled = 0;
                    foreach (var (campaignId, json) in rows)
                    {
                        var campaign = JsonSerializer.Deserialize<ThreatCampaign>(json, JsonOptions);
                        if (campaign is not null)
                            backfilled += await _service.BackfillLegacyCampaignAsync(campaign, stoppingToken);
                        await _store.SaveTemporalBackfillCursorAsync(campaignId, stoppingToken);
                    }
                    if (rows.Count < 500)
                        await _store.SaveTemporalBackfillCursorAsync(null, stoppingToken);
                    _nextBackfillUtc = now.AddMinutes(15);
                    if (backfilled > 0)
                        _logger.LogInformation(
                            "Temporal legacy backfill appended {Observations} collapsed observations mode={Mode}",
                            backfilled, _options.ProjectionMode);
                }
                var items = await _store.LeaseTemporalCorrelationWorkAsync(
                    _leaseOwner, now, TimeSpan.FromMinutes(5), 1, stoppingToken);
                foreach (var item in items)
                {
                    processed = true;
                    await ProcessAsync(item, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Temporal correlation outbox poll failed");
            }

            if (!processed)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    private async Task ProcessAsync(TemporalCorrelationWorkItem item, CancellationToken cancellationToken)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<TemporalCorrelationEnvelope>(item.PayloadJson, JsonOptions)
                ?? throw new JsonException("Temporal correlation envelope was null.");
            await _service.RecordAsync(
                envelope.Batch,
                envelope.Incidents,
                envelope.Campaigns,
                item.TenantId,
                cancellationToken);
            await _store.CompleteTemporalCorrelationWorkAsync(
                item.WorkId, _leaseOwner, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var exponent = Math.Clamp(item.Attempts, 1, 8);
            var delay = TimeSpan.FromSeconds(Math.Min(300, Math.Pow(2, exponent)));
            await _store.FailTemporalCorrelationWorkAsync(
                item.WorkId,
                _leaseOwner,
                DateTimeOffset.UtcNow.Add(delay),
                ex.Message,
                CancellationToken.None);
            _logger.LogWarning(ex,
                "Temporal correlation outbox item failed work={WorkId} tenant={Tenant} attempt={Attempt}",
                item.WorkId, item.TenantId, item.Attempts);
        }
    }
}
