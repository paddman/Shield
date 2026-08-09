using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.LLM;

namespace NTShield.Server.Services;

public sealed class CentralReadinessState
{
    private readonly object _sync = new();
    private string _store = "pending";
    private string _campaigns = "pending";
    private string _llm = "pending";
    private string? _campaignError;
    private string? _llmError;

    public DateTimeOffset StartedAtUtc { get; } = DateTimeOffset.UtcNow;
    public bool StoreReady { get; private set; }
    private string? _storeError;

    public void MarkStoreReady()
    {
        lock (_sync)
        {
            StoreReady = true;
            _store = "ready";
            _storeError = null;
        }
    }

    public void MarkStoreLoading()
    {
        lock (_sync)
        {
            StoreReady = false;
            _store = "loading";
        }
    }

    public void MarkStoreDegraded(Exception error)
    {
        lock (_sync)
        {
            StoreReady = false;
            _store = "degraded";
            _storeError = error.GetType().Name;
        }
    }

    public void SetCampaigns(string state, Exception? error = null)
    {
        lock (_sync)
        {
            _campaigns = state;
            _campaignError = error?.GetType().Name;
        }
    }

    public void SetLlm(string state, Exception? error = null)
    {
        lock (_sync)
        {
            _llm = state;
            _llmError = error?.GetType().Name;
        }
    }

    public object Snapshot()
    {
        lock (_sync)
        {
            return new
            {
                ready = StoreReady,
                store = _store,
                storeError = _storeError,
                campaigns = _campaigns,
                llm = _llm,
                campaignError = _campaignError,
                llmError = _llmError,
                startedAtUtc = StartedAtUtc,
                utc = DateTimeOffset.UtcNow
            };
        }
    }
}

/// <summary>
/// Opens/migrates the operational store off the web-host startup path. Cheap
/// session/health endpoints can respond while an unavailable production store
/// retries in the background; data widgets degrade independently.
/// </summary>
public sealed class CentralStoreInitializer : BackgroundService
{
    private readonly ICentralStore _store;
    private readonly CentralReadinessState _readiness;
    private readonly ILogger<CentralStoreInitializer> _logger;

    public CentralStoreInitializer(
        ICentralStore store,
        CentralReadinessState readiness,
        ILogger<CentralStoreInitializer> logger)
    {
        _store = store;
        _readiness = readiness;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // BackgroundService.StartAsync invokes ExecuteAsync synchronously until
        // its first incomplete await. Yield before opening/migrating the store
        // so Kestrel can expose the cheap session/health endpoints immediately,
        // even when a SQLite migration completes its "async" calls inline.
        await Task.Yield();
        var delay = TimeSpan.FromSeconds(2);
        while (!stoppingToken.IsCancellationRequested && !_readiness.StoreReady)
        {
            _readiness.MarkStoreLoading();
            try
            {
                await _store.InitializeAsync();
                _readiness.MarkStoreReady();
                _logger.LogInformation("Central operational store is ready");
                return;
            }
            catch (Exception ex)
            {
                _readiness.MarkStoreDegraded(ex);
                _logger.LogError(ex, "Central operational store initialization failed; retrying in {Delay}", delay);
            }

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            delay = TimeSpan.FromSeconds(Math.Min(60, delay.TotalSeconds * 2));
        }
    }
}

/// <summary>
/// Defers nonessential campaign reconstruction and token-store warmup until the
/// host can accept cheap session/health requests.
/// </summary>
public sealed class CentralWarmupService : BackgroundService
{
    private readonly LateralMovementTracker _tracker;
    private readonly LlmGatewayService _llm;
    private readonly CentralReadinessState _readiness;
    private readonly ILogger<CentralWarmupService> _logger;

    public CentralWarmupService(
        LateralMovementTracker tracker,
        LlmGatewayService llm,
        CentralReadinessState readiness,
        ILogger<CentralWarmupService> logger)
    {
        _tracker = tracker;
        _llm = llm;
        _readiness = readiness;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        await Task.WhenAll(WarmCampaignsAsync(stoppingToken), WarmLlmAsync(stoppingToken));
    }

    private async Task WarmCampaignsAsync(CancellationToken stoppingToken)
    {
        _readiness.SetCampaigns("loading");
        try
        {
            while (!_readiness.StoreReady)
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            await _tracker.LoadAsync();
            _readiness.SetCampaigns("ready");
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _readiness.SetCampaigns("degraded", ex);
            _logger.LogError(ex, "Threat campaign warmup failed; summary APIs remain available in degraded mode");
        }
    }

    private async Task WarmLlmAsync(CancellationToken stoppingToken)
    {
        _readiness.SetLlm("loading");
        try
        {
            await _llm.InitializeAsync();
            _readiness.SetLlm("ready");
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _readiness.SetLlm("degraded", ex);
            _logger.LogError(ex, "LLM token-store warmup failed; dashboard core remains available");
        }
    }
}
