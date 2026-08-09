using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using NTShield.Agent.Linux.Collectors;
using NTShield.Agent.Linux.Detection;
using NTShield.Agent.Linux.Response;
using NTShield.Shared;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using NTShield.Shared.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

// NT Shield Linux Agent — metrics + multi-stack logs + allowlisted remediation.
var contentRoot = AppContext.BaseDirectory;
var logDir = Directory.Exists("/var/log/ntshield")
    ? "/var/log/ntshield"
    : Path.Combine(contentRoot, "logs");
Directory.CreateDirectory(logDir);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .WriteTo.File(Path.Combine(logDir, "agent-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
    .CreateLogger();

try
{
    var version = ProductInfo.GetVersion();
    Log.Information("NT Shield Linux Agent v{Version} starting…", version);

    var host = Host.CreateDefaultBuilder(args)
        .UseContentRoot(contentRoot)
        .UseSystemd()
        .UseSerilog()
        .ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.SetBasePath(contentRoot);
            cfg.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
            cfg.AddEnvironmentVariables(prefix: "NTSHIELD_");
            cfg.AddCommandLine(args);
        })
        .ConfigureServices(services =>
        {
            services.AddHostedService<LinuxAgentWorker>();
        })
        .Build();

    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Linux agent terminated");
    Environment.ExitCode = 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

internal sealed class LinuxAgentWorker : BackgroundService
{
    private readonly ILogger<LinuxAgentWorker> _logger;
    private readonly IConfiguration _config;
    private readonly HostMetricsCollector _metrics = new();
    private readonly LogFileTailer _tailer;
    private readonly List<SecurityEventRecord> _eventBuf = [];
    private readonly List<DetectionAlert> _alertBuf = [];
    private readonly object _bufGate = new();
    private readonly Dictionary<string, DateTimeOffset> _remediateCooldown = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastError;
    private HostMetrics? _lastMetrics;
    private string? _apiKey;
    private string? _binarySha256;
    private bool? _isBinarySigned;
    private int _appliedPolicyVersion;
    private bool _autoRemediate;
    private double _cpuAlert = 90, _memAlert = 90, _diskAlert = 90;

    public LinuxAgentWorker(ILogger<LinuxAgentWorker> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
        _tailer = new LogFileTailer(logger);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var url = (_config["Server:Url"] ?? "https://localhost:7443").Trim().TrimEnd('/');
        if (!Uri.TryCreate(url, UriKind.Absolute, out var centralUri) ||
            !string.Equals(centralUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Server:Url must be an absolute HTTPS URL.");
        }

        var allowUntrusted = _config.GetValue("Server:AllowUntrustedServerCertificate", false);
        var caCertificatePath = _config["Server:CaCertificatePath"] ?? string.Empty;
        var heartbeatSec = Math.Max(15, _config.GetValue("Server:HeartbeatIntervalSeconds", 60));
        var metricsSec = Math.Max(5, _config.GetValue("Linux:MetricsIntervalSeconds", 30));
        var logSec = Math.Max(5, _config.GetValue("Linux:LogScanIntervalSeconds", 15));
        var ingestSec = Math.Max(10, _config.GetValue("Linux:IngestIntervalSeconds", 30));
        _autoRemediate = _config.GetValue("Linux:AutoRemediate", false);
        _cpuAlert = _config.GetValue("Linux:CpuAlertPercent", 90.0);
        _memAlert = _config.GetValue("Linux:MemAlertPercent", 90.0);
        _diskAlert = _config.GetValue("Linux:DiskAlertPercent", 90.0);
        var enrollmentToken = _config["Server:EnrollmentToken"] ?? string.Empty;
        _apiKey = _config["Server:ApiKey"] ?? string.Empty;
        var maxEventsBatch = Math.Clamp(_config.GetValue("Linux:MaxEventsPerIngest", 100), 10, 500);
        ProbeSelfIntegrity();

        var agentId = _config["Agent:AgentId"];
        if (string.IsNullOrWhiteSpace(agentId))
        {
            agentId = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(Environment.MachineName + "|linux|ntshield"))).ToLowerInvariant()[..16];
            try { PersistAgentId(agentId); }
            catch (Exception ex) { _logger.LogDebug(ex, "Could not persist AgentId"); }
        }

        var version = ProductInfo.GetVersion() + "-linux";
        var computer = string.IsNullOrWhiteSpace(_config["Agent:ComputerName"])
            ? Environment.MachineName
            : _config["Agent:ComputerName"]!;

        _logger.LogInformation(
            "Linux Agent v{Version} Host={Host} AgentId={Id} Central={Url} AutoRemediate={Auto}",
            version, computer, agentId, url, _autoRemediate);

        using var handler = CreateHttpHandler(allowUntrusted, caCertificatePath);
        if (allowUntrusted)
        {
            _logger.LogCritical(
                "Server:AllowUntrustedServerCertificate=true. Central identity is not verified; never use this outside an isolated migration lab.");
        }
        else if (!string.IsNullOrWhiteSpace(caCertificatePath))
        {
            _logger.LogInformation(
                "Central TLS uses custom trust anchor {Path}",
                Environment.ExpandEnvironmentVariables(caCertificatePath));
        }

        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri(url + "/"),
            Timeout = TimeSpan.FromSeconds(45)
        };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"NTShield-Agent-Linux/{ProductInfo.GetVersion()}");
        ApplyApiKeyHeader(http);

        var response = new LinuxResponseExecutor(_logger, _autoRemediate);
        var logPaths = ResolveLogPaths();

        // Warm metrics (first sample has no rates)
        _lastMetrics = _metrics.Snapshot();

        if (string.IsNullOrWhiteSpace(_apiKey) || !string.IsNullOrWhiteSpace(enrollmentToken))
        {
            try
            {
                var reg = new AgentRegistrationRequest
                {
                    AgentId = agentId,
                    ComputerName = computer,
                    AgentVersion = version,
                    OsVersion = Environment.OSVersion.ToString(),
                    HostIp = TryGetIp(),
                    EnrollmentToken = string.IsNullOrWhiteSpace(enrollmentToken) ? null : enrollmentToken,
                    BinarySha256 = _binarySha256,
                    IsBinarySigned = _isBinarySigned,
                    Platform = "linux",
                    RotateApiKey = string.IsNullOrWhiteSpace(_apiKey)
                };
                using var regResp = await http.PostAsJsonAsync("api/v1/agents/register", reg, stoppingToken);
                _logger.LogInformation("Register → HTTP {Code}", (int)regResp.StatusCode);
                if (regResp.IsSuccessStatusCode)
                {
                    var body = await regResp.Content.ReadFromJsonAsync<AgentRegistrationResponse>(cancellationToken: stoppingToken);
                    if (!string.IsNullOrWhiteSpace(body?.AgentApiKey))
                    {
                        _apiKey = body.AgentApiKey;
                        ApplyApiKeyHeader(http);
                        PersistApiKey(_apiKey);
                        _logger.LogInformation("Agent API key stored; enrollment token removed from local configuration");
                    }

                    if (body?.Policy is not null)
                        ApplyPolicy(body.Policy);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Register failed (agent remains in local monitoring mode)");
                _lastError = "register: " + ex.Message;
            }
        }
        else
        {
            _logger.LogDebug("Skipping re-enrollment; an existing per-agent API key is configured");
        }

        var nextHb = DateTimeOffset.UtcNow;
        var nextMetrics = DateTimeOffset.UtcNow;
        var nextLogs = DateTimeOffset.UtcNow;
        var nextIngest = DateTimeOffset.UtcNow;

        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTimeOffset.UtcNow;

            if (now >= nextMetrics)
            {
                try
                {
                    CollectMetrics(agentId, computer, _cpuAlert, _memAlert, _diskAlert);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Metrics collection error");
                }

                nextMetrics = now.AddSeconds(metricsSec);
            }

            if (now >= nextLogs)
            {
                try
                {
                    await ScanLogsAsync(agentId, computer, logPaths, response, _autoRemediate, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Log scan error");
                }

                nextLogs = now.AddSeconds(logSec);
            }

            if (now >= nextIngest)
            {
                try
                {
                    await FlushIngestAsync(http, agentId, computer, version, maxEventsBatch, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Ingest error");
                    _lastError = "ingest: " + Truncate(ex.Message, 200);
                }

                nextIngest = now.AddSeconds(ingestSec);
            }

            if (now >= nextHb)
            {
                try
                {
                    await HeartbeatAsync(http, agentId, computer, version, url, response, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Heartbeat error");
                    _lastError = "heartbeat: " + Truncate(ex.Message, 200);
                }

                nextHb = now.AddSeconds(heartbeatSec);
            }

            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        }
    }

    private void CollectMetrics(string agentId, string computer, double cpuAlert, double memAlert, double diskAlert)
    {
        var m = _metrics.Snapshot();
        _lastMetrics = m;
        var line = _metrics.FormatStatusLine(m);
        _logger.LogInformation("Metrics {Line}", line);

        // Threshold alerts (cooldown 10 min per type)
        void MaybeAlert(string key, bool hit, Severity sev, string title, string desc)
        {
            if (!hit) return;
            if (_remediateCooldown.TryGetValue("metric:" + key, out var until) && until > DateTimeOffset.UtcNow)
                return;
            _remediateCooldown["metric:" + key] = DateTimeOffset.UtcNow.AddMinutes(10);

            lock (_bufGate)
            {
                _alertBuf.Add(new DetectionAlert
                {
                    AgentId = agentId,
                    ComputerName = computer,
                    RuleId = "LNX_METRIC_" + key.ToUpperInvariant(),
                    RuleName = title,
                    Severity = sev,
                    Title = title,
                    Description = desc,
                    EventCount = 1,
                    EvidenceJson = JsonSerializer.Serialize(new
                    {
                        cpu = m.CpuPercent,
                        mem = m.MemUsedPercent,
                        disk = m.RootDiskUsedPercent,
                        net_rx = m.NetworkRxBytesPerSec,
                        net_tx = m.NetworkTxBytesPerSec,
                        io_r = m.DiskReadBytesPerSec,
                        io_w = m.DiskWriteBytesPerSec,
                        load1 = m.LoadAverage1
                    })
                });
                _eventBuf.Add(new SecurityEventRecord
                {
                    AgentId = agentId,
                    ComputerName = computer,
                    TimestampUtc = DateTimeOffset.UtcNow,
                    Channel = "metrics",
                    ProviderName = "NTShield.Linux.Metrics",
                    EventId = 8000,
                    Status = "LNX_METRIC_" + key.ToUpperInvariant(),
                    SubStatus = title,
                    RawXml = desc
                });
            }
        }

        MaybeAlert("cpu", m.CpuPercent is double c && c >= cpuAlert, Severity.High,
            $"High CPU {m.CpuPercent:F1}%", line);
        MaybeAlert("mem", m.MemUsedPercent is double mem && mem >= memAlert, Severity.High,
            $"High memory {m.MemUsedPercent:F1}%", line);
        MaybeAlert("disk", m.RootDiskUsedPercent is double d && d >= diskAlert, Severity.Critical,
            $"High disk {m.RootMount} {m.RootDiskUsedPercent:F1}%", line);

        WriteLocalStatus(m, line);
    }

    private async Task ScanLogsAsync(
        string agentId,
        string computer,
        IReadOnlyList<string> paths,
        LinuxResponseExecutor response,
        bool autoRemediate,
        CancellationToken ct)
    {
        var lines = _tailer.ReadNewLines(paths);
        if (lines.Count == 0) return;

        var analyzed = 0;
        foreach (var line in lines)
        {
            var result = LinuxLogAnalyzer.Analyze(line, agentId, computer);
            if (result is null) continue;
            analyzed++;

            lock (_bufGate)
            {
                _eventBuf.Add(result.Event);
                if (result.Alert is not null)
                    _alertBuf.Add(result.Alert);
            }

            if (autoRemediate &&
                !string.IsNullOrEmpty(result.SuggestedActionType) &&
                result.SuggestedActionType != "LogOnly")
            {
                var key = $"{result.SuggestedActionType}:{result.SuggestedService ?? string.Empty}";
                if (_remediateCooldown.TryGetValue(key, out var until) && until > DateTimeOffset.UtcNow)
                    continue;
                _remediateCooldown[key] = DateTimeOffset.UtcNow.AddMinutes(15);

                var req = new ResponseActionRequest
                {
                    TargetAgentId = agentId,
                    ActionType = result.SuggestedActionType!,
                    ServiceName = result.SuggestedService,
                    Reason = $"Local policy auto-remediate: {result.Event.SubStatus}",
                    Requester = "linux-agent-auto",
                    AlertId = result.Alert?.AlertId
                };
                _logger.LogWarning("Local auto-remediate {Action} service={Svc} reason={Reason}",
                    req.ActionType, req.ServiceName, req.Reason);
                var rec = await response.ExecuteAsync(req, ct);
                _logger.LogWarning("Local auto-remediate result {Status} {Result} {Error}",
                    rec.Status, rec.Result, rec.Error);
            }
        }

        if (analyzed > 0)
            _logger.LogInformation("Log scan: {Lines} new lines, {Hits} matched", lines.Count, analyzed);
    }

    private async Task FlushIngestAsync(
        HttpClient http,
        string agentId,
        string computer,
        string version,
        int maxEvents,
        CancellationToken ct)
    {
        List<SecurityEventRecord> events;
        List<DetectionAlert> alerts;
        lock (_bufGate)
        {
            if (_eventBuf.Count == 0 && _alertBuf.Count == 0) return;
            var takeE = Math.Min(maxEvents, _eventBuf.Count);
            var takeA = Math.Min(maxEvents, _alertBuf.Count);
            events = _eventBuf.GetRange(0, takeE);
            alerts = _alertBuf.GetRange(0, takeA);
            _eventBuf.RemoveRange(0, takeE);
            _alertBuf.RemoveRange(0, takeA);
        }

        var batch = new AgentIngestBatch
        {
            AgentId = agentId,
            ComputerName = computer,
            AgentVersion = version,
            SentAtUtc = DateTimeOffset.UtcNow,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
            SecurityEvents = events,
            Alerts = alerts
        };

        using var resp = await http.PostAsJsonAsync("api/v1/ingest", batch, ct);
        if (resp.IsSuccessStatusCode)
        {
            _logger.LogInformation("Ingest OK events={E} alerts={A}", events.Count, alerts.Count);
            _lastError = null;
        }
        else
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("Ingest failed HTTP {Code}: {Body}", (int)resp.StatusCode, Truncate(body, 200));
            _lastError = $"ingest HTTP {(int)resp.StatusCode}";
            lock (_bufGate)
            {
                _eventBuf.InsertRange(0, events);
                _alertBuf.InsertRange(0, alerts);
            }
        }
    }

    private async Task HeartbeatAsync(
        HttpClient http,
        string agentId,
        string computer,
        string version,
        string url,
        LinuxResponseExecutor response,
        CancellationToken ct)
    {
        var m = _lastMetrics ?? _metrics.Snapshot();
        long ws;
        try
        {
            using var proc = System.Diagnostics.Process.GetCurrentProcess();
            ws = proc.WorkingSet64;
        }
        catch { ws = 0; }

        var degraded = m.IsDegraded(_cpuAlert, _memAlert, _diskAlert);
        var metricsLine = _metrics.FormatStatusLine(m);
        var status = degraded ? "Degraded" : "Healthy";
        status = $"{status} | {metricsLine}";
        if (status.Length > 240) status = status[..240];

        var hb = new AgentHeartbeat
        {
            AgentId = agentId,
            ComputerName = computer,
            AgentVersion = version,
            OsVersion = Environment.OSVersion.ToString(),
            TimestampUtc = DateTimeOffset.UtcNow,
            Status = status,
            Platform = "linux",
            CentralUrl = url,
            HostIp = TryGetIp(),
            LocalQueueDepth = GetQueueDepth(),
            WorkingSetBytes = m.MemTotalBytes > 0
                ? m.MemTotalBytes - m.MemAvailableBytes
                : ws,
            CpuPercentEstimate = m.CpuPercent,
            LastError = _lastError,
            BinarySha256 = _binarySha256,
            IsBinarySigned = _isBinarySigned,
            AppliedPolicyVersion = _appliedPolicyVersion > 0 ? _appliedPolicyVersion : null,
            MemUsedPercent = m.MemUsedPercent,
            DiskUsedPercent = m.RootDiskUsedPercent,
            NetworkRxBytesPerSec = m.NetworkRxBytesPerSec,
            NetworkTxBytesPerSec = m.NetworkTxBytesPerSec,
            DiskReadBytesPerSec = m.DiskReadBytesPerSec,
            DiskWriteBytesPerSec = m.DiskWriteBytesPerSec,
            LoadAverage1 = m.LoadAverage1,
            HostMemUsedBytes = m.MemTotalBytes > 0 ? m.MemTotalBytes - m.MemAvailableBytes : null,
            HostMemTotalBytes = m.MemTotalBytes > 0 ? m.MemTotalBytes : null,
            MetricsSummary = metricsLine
        };

        using var resp = await http.PostAsJsonAsync("api/v1/agents/heartbeat", hb, ct);
        if (!resp.IsSuccessStatusCode)
        {
            _logger.LogWarning("Heartbeat failed: HTTP {Status}", (int)resp.StatusCode);
            _lastError = $"heartbeat HTTP {(int)resp.StatusCode}";
            return;
        }

        _logger.LogInformation("Heartbeat OK agent={Id} {Status}", agentId, Truncate(status, 120));
        _lastError = null;

        HeartbeatResponse? hbResp = null;
        try
        {
            hbResp = await resp.Content.ReadFromJsonAsync<HeartbeatResponse>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not parse heartbeat response");
        }

        if (hbResp?.Policy is not null)
            ApplyPolicy(hbResp.Policy);

        if (hbResp?.PendingActions is { Count: > 0 } actions)
        {
            foreach (var action in actions)
            {
                try
                {
                    if (!string.Equals(action.TargetAgentId, agentId, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogCritical(
                            "Rejected target-mismatched action id={Id} expected={Expected} target={Target}",
                            action.RequestId,
                            agentId,
                            action.TargetAgentId);
                        continue;
                    }

                    if (ActionApprovalCrypto.RequiresApproval(action.ActionType) && !action.Approved)
                    {
                        _logger.LogCritical(
                            "Rejected unsigned, tampered or expired Central action type={Type} id={Id}",
                            action.ActionType,
                            action.RequestId);
                        continue;
                    }

                    _logger.LogWarning(
                        "Executing verified Central action {Type} target={Ip}:{Port} svc={Svc} id={Id} approvedBy={ApprovedBy} expires={Expires}",
                        action.ActionType,
                        action.TargetIp,
                        action.TargetPort,
                        action.ServiceName,
                        action.RequestId,
                        action.ApprovedBy,
                        action.ExpiresAtUtc);
                    var result = await response.ExecuteAsync(action, ct);
                    _logger.LogWarning("Action result {Type} status={Status} {Result}",
                        result.ActionType, result.Status, result.Result ?? result.Error);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed executing Central action {Type}", action.ActionType);
                }
            }
        }
    }

    private int GetQueueDepth()
    {
        lock (_bufGate)
            return _eventBuf.Count + _alertBuf.Count;
    }

    private IReadOnlyList<string> ResolveLogPaths()
    {
        var configured = _config.GetSection("Linux:LogPaths").Get<string[]>();
        if (configured is { Length: > 0 })
            return configured;

        return
        [
            "/var/log/nginx/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/*.log",
            "/var/log/apache2/error.log",
            "/var/log/httpd/error_log",
            "/var/log/php*-fpm.log",
            "/var/log/php/error.log",
            "/var/log/php8.3-fpm.log",
            "/var/log/php8.2-fpm.log",
            "/var/log/php8.1-fpm.log",
            "/var/log/php-fpm/error.log",
            "/var/log/docker.log",
            "/var/lib/docker/containers/*/*-json.log",
            "/var/log/nodejs/*.log",
            "/root/.pm2/logs/*.log",
            "/home/*/.pm2/logs/*.log",
            "/var/log/pm2/*.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/fail2ban.log",
            "/var/log/mysql/error.log",
            "/var/log/mysqld.log",
            "/var/log/postgresql/*.log",
            "/var/log/redis/redis-server.log",
            "/var/log/caddy/*.log",
            "/var/log/traefik/*.log"
        ];
    }

    private void WriteLocalStatus(HostMetrics m, string metricsLine)
    {
        try
        {
            var dir = Directory.Exists("/var/lib/ntshield")
                ? "/var/lib/ntshield"
                : Path.Combine(AppContext.BaseDirectory, "data");
            Directory.CreateDirectory(dir);
            var payload = new
            {
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Platform = "linux",
                State = "Monitoring",
                Metrics = metricsLine,
                CpuPercent = m.CpuPercent,
                MemUsedPercent = m.MemUsedPercent,
                DiskUsedPercent = m.RootDiskUsedPercent,
                NetworkRxBps = m.NetworkRxBytesPerSec,
                NetworkTxBps = m.NetworkTxBytesPerSec,
                DiskReadBps = m.DiskReadBytesPerSec,
                DiskWriteBps = m.DiskWriteBytesPerSec,
                Load1 = m.LoadAverage1,
                ProcessCount = m.ProcessCount,
                Disks = m.Disks,
                LastError = _lastError,
                QueueDepth = GetQueueDepth()
            };
            var path = Path.Combine(dir, "status.json");
            File.WriteAllText(path, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "status.json write failed");
        }
    }

    private void ApplyApiKeyHeader(HttpClient http)
    {
        http.DefaultRequestHeaders.Remove("X-NTShield-Api-Key");
        if (!string.IsNullOrWhiteSpace(_apiKey))
            http.DefaultRequestHeaders.TryAddWithoutValidation("X-NTShield-Api-Key", _apiKey);
    }

    private void ApplyPolicy(AgentPolicy policy)
    {
        if (policy.PolicyVersion <= _appliedPolicyVersion) return;

        if (!string.IsNullOrWhiteSpace(policy.ActionSigningPublicKeyPem))
        {
            try
            {
                ActionApprovalCrypto.ConfigureTrustedPublicKey(
                    policy.ActionSigningPublicKeyPem,
                    policy.ActionSigningKeyId);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(
                    ex,
                    "Rejected Central policy v{Version}: invalid action-signing public key",
                    policy.PolicyVersion);
                return;
            }
        }
        else
        {
            _logger.LogWarning(
                "Central policy v{Version} contains no action-signing key; destructive Central actions remain disabled",
                policy.PolicyVersion);
        }

        _appliedPolicyVersion = policy.PolicyVersion;
        // Remote policy may reduce local automation. Enabling local automation
        // still requires the explicit local startup configuration used to create
        // LinuxResponseExecutor; this avoids a network policy silently granting
        // itself destructive local authority.
        if (!policy.AutoRemediate)
            _autoRemediate = false;
        if (policy.CpuAlertPercent is double c) _cpuAlert = c;
        if (policy.MemAlertPercent is double m) _memAlert = m;
        if (policy.DiskAlertPercent is double d) _diskAlert = d;
        _logger.LogWarning(
            "Central policy applied v{Ver} localAutoRemediate={Auto} actionKey={KeyId}",
            policy.PolicyVersion,
            _autoRemediate,
            policy.ActionSigningKeyId);
    }

    private static HttpClientHandler CreateHttpHandler(bool allowUntrusted, string? caCertificatePath)
    {
        var handler = new HttpClientHandler();
        if (allowUntrusted)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            return handler;
        }

        if (string.IsNullOrWhiteSpace(caCertificatePath))
            return handler;

        var path = Environment.ExpandEnvironmentVariables(caCertificatePath);
        if (!File.Exists(path))
            throw new FileNotFoundException("Central CA certificate not found", path);

        var trustedCa = LoadTrustCertificate(path);
        handler.ServerCertificateCustomValidationCallback =
            (_, certificate, presentedChain, errors) =>
                ValidateWithCustomTrust(trustedCa, certificate, presentedChain, errors);
        return handler;
    }

    private static X509Certificate2 LoadTrustCertificate(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".pem", StringComparison.OrdinalIgnoreCase)
            ? X509Certificate2.CreateFromPemFile(path)
            : X509CertificateLoader.LoadCertificateFromFile(path);
    }

    private static bool ValidateWithCustomTrust(
        X509Certificate2 trustedCa,
        X509Certificate2? serverCertificate,
        X509Chain? presentedChain,
        SslPolicyErrors errors)
    {
        if (serverCertificate is null ||
            (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 ||
            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        using var customChain = new X509Chain();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(trustedCa);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        customChain.ChainPolicy.DisableCertificateDownloads = true;

        if (presentedChain is not null)
        {
            foreach (var element in presentedChain.ChainElements.Cast<X509ChainElement>().Skip(1))
                customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
        }

        return customChain.Build(serverCertificate);
    }

    private void ProbeSelfIntegrity()
    {
        try
        {
            var path = Environment.ProcessPath
                       ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                       ?? typeof(LinuxAgentWorker).Assembly.Location;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
            using var stream = File.OpenRead(path);
            var hash = System.Security.Cryptography.SHA256.HashData(stream);
            _binarySha256 = Convert.ToHexString(hash).ToLowerInvariant();
            _isBinarySigned = false;
        }
        catch
        {
            // Best-effort integrity telemetry only.
        }
    }

    private void PersistApiKey(string apiKey)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(path)) return;
        var node = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject();
        var server = node["Server"] as JsonObject ?? new JsonObject();
        server["ApiKey"] = apiKey;
        server["EnrollmentToken"] = string.Empty;
        node["Server"] = server;
        File.WriteAllText(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        HardenSettingsFile(path);
    }

    private static void PersistAgentId(string agentId)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(path)) return;
        var node = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject();
        var agent = node["Agent"] as JsonObject ?? new JsonObject();
        agent["AgentId"] = agentId;
        if (string.IsNullOrWhiteSpace(agent["ComputerName"]?.GetValue<string>()))
            agent["ComputerName"] = Environment.MachineName;
        node["Agent"] = agent;
        File.WriteAllText(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        HardenSettingsFile(path);
    }

    private static void HardenSettingsFile(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Installer also enforces mode 0600; runtime hardening is best effort.
        }
    }

    private static string? TryGetIp()
    {
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                        !System.Net.IPAddress.IsLoopback(ua.Address))
                        return ua.Address.ToString();
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s[..max] + "…";
}
