using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using NTShield.Server.AI;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.LLM;
using NTShield.Server.Security;
using NTShield.Server.Services;
using NTShield.Server.Signatures;
using NTShield.Server.Syslog;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Serilog;
using NTShield.Core.Security;

var builder = WebApplication.CreateBuilder(args);

// Allow running as Windows Service (Central install)
builder.Host.UseWindowsService(o => o.ServiceName = "NTShieldCentral");

var logDir = builder.Configuration["LoggingPaths:Directory"] ?? "logs";
Directory.CreateDirectory(logDir);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File(
        path: Path.Combine(logDir, "server-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 31)
    .CreateLogger();

builder.Host.UseSerilog();

builder.Services.Configure<PostgresOptions>(builder.Configuration.GetSection(PostgresOptions.SectionName));
builder.Services.Configure<SqliteCentralOptions>(builder.Configuration.GetSection(SqliteCentralOptions.SectionName));
builder.Services.Configure<ClickHouseOptions>(builder.Configuration.GetSection(ClickHouseOptions.SectionName));
builder.Services.Configure<CorrelationOptions>(builder.Configuration.GetSection(CorrelationOptions.SectionName));
builder.Services.Configure<SyslogOptions>(builder.Configuration.GetSection(SyslogOptions.SectionName));
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection(SecurityOptions.SectionName));
builder.Services.Configure<LlmGatewayOptions>(builder.Configuration.GetSection(LlmGatewayOptions.SectionName));
builder.Services.Configure<AiAnalystOptions>(builder.Configuration.GetSection(AiAnalystOptions.SectionName));
builder.Services.Configure<AiAnomalyOptions>(builder.Configuration.GetSection(AiAnomalyOptions.SectionName));
// Bootstrap secrets into options before DI freezes them
builder.Services.PostConfigure<SecurityOptions>(opts =>
{
    SecretBootstrapper.Apply(builder.Configuration, opts);
});
builder.Services.AddSingleton<OpenSourceSignatureEngine>();
builder.Services.AddHostedService<SyslogListenerService>();

// Default: SQLite (works out of the box). Set Database:Provider=Postgres for PostgreSQL.
var dbProvider = builder.Configuration["Database:Provider"] ?? "Sqlite";
if (string.Equals(dbProvider, "ClickHouse", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<SqliteCentralStore>();
    builder.Services.AddSingleton<ICentralStore, ClickHouseStore>();
    Log.Information("Central database provider: ClickHouse analytics + SQLite control plane");
}
else if (string.Equals(dbProvider, "Postgres", StringComparison.OrdinalIgnoreCase) ||
    string.Equals(dbProvider, "PostgreSQL", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<ICentralStore, PostgresStore>();
    Log.Information("Central database provider: PostgreSQL");
}
else
{
    builder.Services.AddSingleton<ICentralStore, SqliteCentralStore>();
    Log.Information("Central database provider: SQLite (lab/default)");
}

builder.Services.AddSingleton<CrossHostCorrelator>();
builder.Services.AddSingleton<LateralMovementTracker>();
builder.Services.AddSingleton<TelemetryFeatureBuilder>();
builder.Services.AddSingleton<IngestTenantResolver>();
builder.Services.AddSingleton<IngestService>();
builder.Services.AddSingleton<ActionService>();
builder.Services.AddHttpClient("llm-gateway")
    .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
    {
        var llmOptions = serviceProvider.GetRequiredService<IOptions<LlmGatewayOptions>>().Value;
        return new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = llmOptions.SkipTlsVerify
                ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                : null
        };
    });
builder.Services.AddSingleton<LlmGatewayService>();
builder.Services.AddHttpClient("ai-analyst")
    .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
    {
        var aiOptions = serviceProvider.GetRequiredService<IOptions<AiAnalystOptions>>().Value;
        return new HttpClientHandler
        {
            // This applies only to the named Brain bridge client. TLS verification
            // remains enabled by default for every other HTTP client.
            ServerCertificateCustomValidationCallback = aiOptions.SkipTlsVerify
                ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                : null
        };
    });
builder.Services.AddSingleton<AiAnalystProxyService>();
builder.Services.AddHttpClient("ai-anomaly")
    .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
    {
        var aiOptions = serviceProvider.GetRequiredService<IOptions<AiAnomalyOptions>>().Value;
        return new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = aiOptions.SkipTlsVerify
                ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                : null
        };
    });
builder.Services.AddSingleton<AiAnomalyProxyService>();
builder.Services.AddHttpClient("geoip", client =>
{
    client.BaseAddress = new Uri("https://ipwho.is/");
    client.Timeout = TimeSpan.FromSeconds(8);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("NTShield-Central/1.1");
});
builder.Services.AddSingleton<GeoIpService>();
builder.Services.AddSingleton<TopologyService>();
builder.Services.AddSingleton<TenantManagementService>();
builder.Services.AddSingleton<TenantReportService>();

// Agent may send gzip-compressed ingest batches (body > ~4KB). Without this, ASP.NET returns 400 BadRequest.
builder.Services.AddRequestDecompression();
builder.Services.AddResponseCompression(o =>
{
    o.EnableForHttps = true;
    o.Providers.Add<GzipCompressionProvider>();
    o.Providers.Add<BrotliCompressionProvider>();
});
builder.Services.Configure<GzipCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = builder.Configuration.GetValue("Security:MaxRequestBodyBytes", 20 * 1024 * 1024);
    var port = builder.Configuration.GetValue("Kestrel:Port", 7443);
    var enableMtls = builder.Configuration.GetValue("Security:EnableMtls", false);
    var certPath = builder.Configuration["Security:CertificatePath"]
                   ?? @"C:\ProgramData\NTShield\Server\certs\central.pfx";
    var certPassword = builder.Configuration["Security:CertificatePassword"] ?? "NTShield!";
    var forceRegen = builder.Configuration.GetValue("Security:RegenerateCertificate", false);
    var extraSans = builder.Configuration["Security:CertificateExtraSans"]
                    ?? builder.Configuration["Security:PublicHost"]
                    ?? "";
    var serverCert = EnsureServerCertificate(certPath, certPassword, extraSans, forceRegen);
    Log.Information(
        "HTTPS certificate: {Subject} thumbprint={Thumb} SANs={Sans}",
        serverCert.Subject,
        serverCert.Thumbprint,
        DescribeCertificateSans(serverCert));

    void ConfigureHttps(ListenOptions listen)
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCert;
            if (enableMtls)
            {
                https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            }
        });
    }

    var listenAddress = builder.Configuration.GetValue<string>("Kestrel:ListenAddress");
    if (string.Equals(listenAddress, "localhost", StringComparison.OrdinalIgnoreCase))
    {
        options.ListenLocalhost(port, ConfigureHttps);
    }
    else if (IPAddress.TryParse(listenAddress, out var parsedAddress))
    {
        options.Listen(parsedAddress, port, ConfigureHttps);
    }
    else
    {
        options.ListenAnyIP(port, ConfigureHttps);
    }
});

var enableMtlsAuth = builder.Configuration.GetValue("Security:EnableMtls", false);
if (enableMtlsAuth)
{
    builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
        .AddCertificate(options =>
        {
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.RevocationMode = X509RevocationMode.NoCheck;
        });
    builder.Services.AddAuthorization();
}

var app = builder.Build();
// Force secret bootstrap early (PostConfigure runs on first resolve)
_ = app.Services.GetRequiredService<IOptions<SecurityOptions>>().Value;

// The Control Center is served by Central itself so its API key never needs to
// cross an additional web tier. Keep the static shell public; protected API
// routes below still pass through ApiKeyAuthMiddleware.
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
        return Task.CompletedTask;
    });
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = context =>
    {
        var path = context.Context.Request.Path.Value ?? string.Empty;
        context.Context.Response.Headers["Cache-Control"] =
            path.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
                ? "no-cache, no-store"
                : "public, max-age=86400";
    }
});

// Must run before model binding so gzip/br request bodies become readable JSON
app.UseRequestDecompression();
app.UseResponseCompression();
app.UseMiddleware<ApiKeyAuthMiddleware>();
app.Use(async (ctx, next) =>
{
    try
    {
        await next();
    }
    catch (TopologyValidationException ex)
    {
        if (!ctx.Response.HasStarted)
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsJsonAsync(new { error = "validation_error", detail = ex.Message });
        }
    }
});
app.Use(async (ctx, next) =>
{
    // Structured audit for mutating calls
    if (HttpMethods.IsPost(ctx.Request.Method))
    {
        Log.Information("AUDIT {Method} {Path} from {IP} len={Len} enc={Enc}",
            ctx.Request.Method,
            ctx.Request.Path,
            ctx.Connection.RemoteIpAddress,
            ctx.Request.ContentLength,
            ctx.Request.Headers.ContentEncoding.ToString());
    }

    await next();

    // Surface model-binding failures that look like "Agent never talks to Central"
    if (HttpMethods.IsPost(ctx.Request.Method) &&
        ctx.Response.StatusCode == StatusCodes.Status400BadRequest &&
        ctx.Request.Path.StartsWithSegments("/api"))
    {
        Log.Warning("API 400 BadRequest path={Path} enc={Enc} len={Len} (often gzip without request decompression, or JSON schema mismatch)",
            ctx.Request.Path,
            ctx.Request.Headers.ContentEncoding.ToString(),
            ctx.Request.ContentLength);
    }
});

using (var scope = app.Services.CreateScope())
{
    var store = scope.ServiceProvider.GetRequiredService<ICentralStore>();
    await store.InitializeAsync();
    var tracker = scope.ServiceProvider.GetRequiredService<LateralMovementTracker>();
    await tracker.LoadAsync();
    await scope.ServiceProvider.GetRequiredService<LlmGatewayService>().InitializeAsync();
}

if (enableMtlsAuth)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

var securityOpts = app.Services.GetRequiredService<IOptions<SecurityOptions>>().Value;
Log.Information(
    "Security RequireAuth={Require} EnrollmentTokenConfigured={Enroll} OperatorKeyConfigured={Op}",
    securityOpts.RequireAuth,
    !string.IsNullOrWhiteSpace(securityOpts.EnrollmentToken),
    !string.IsNullOrWhiteSpace(securityOpts.OperatorApiKey));

var centralVersion = NTShield.Shared.ProductInfo.GetVersion();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    product = "NT Shield Central",
    version = centralVersion,
    productVersion = centralVersion,
    utc = DateTimeOffset.UtcNow
}));

app.MapGet("/api/v1/health", (IOptions<SyslogOptions> syslog, OpenSourceSignatureEngine sigs) => Results.Ok(new
{
    status = "ok",
    product = "NT Shield Central",
    version = centralVersion,
    productVersion = centralVersion,
    utc = DateTimeOffset.UtcNow,
    syslog = new
    {
        enabled = syslog.Value.Enabled,
        udpPort = syslog.Value.UdpPort,
        signatures = sigs.Signatures.Count
    }
}));

app.MapGet("/api/v1/signatures", (OpenSourceSignatureEngine sigs) =>
    Results.Ok(sigs.Signatures.Select(s => new
    {
        s.Id,
        s.Name,
        s.Severity,
        s.Category,
        s.MitreTechnique,
        s.Source,
        s.Enabled
    })));

app.MapGet("/api/v1/llm/status", async (LlmGatewayService gateway) =>
    Results.Ok(await gateway.GetStatusAsync()));

app.MapGet("/api/v1/llm/tokens", async (LlmGatewayService gateway) =>
    Results.Ok(await gateway.ListTokensAsync()));

app.MapPost("/api/v1/llm/tokens", async (
    LlmTokenCreateRequest request,
    LlmGatewayService gateway,
    ICentralStore store,
    HttpContext http) =>
{
    var issued = await gateway.CreateTokenAsync(request.Name, request.ExpiresInDays);
    var actor = http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var principal)
        ? principal?.ToString() ?? "operator"
        : "operator";
    await store.AppendAuditAsync(
        actor,
        "llm.token.create",
        issued.Summary.TokenId,
        "success",
        JsonSerializer.Serialize(new { issued.Summary.Name, issued.Summary.ExpiresUtc }),
        http.Connection.RemoteIpAddress?.ToString());
    return Results.Created("/api/v1/llm/tokens", new
    {
        issued.Summary,
        token = issued.Token,
        warning = "Copy this token now. It will not be shown again."
    });
});

app.MapDelete("/api/v1/llm/tokens/{tokenId}", async (
    string tokenId,
    LlmGatewayService gateway,
    ICentralStore store,
    HttpContext http) =>
{
    var revoked = await gateway.RevokeTokenAsync(tokenId);
    if (!revoked)
        return Results.NotFound(new { error = "llm_token_not_found_or_already_revoked" });

    var actor = http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var principal)
        ? principal?.ToString() ?? "operator"
        : "operator";
    await store.AppendAuditAsync(
        actor,
        "llm.token.revoke",
        tokenId,
        "success",
        null,
        http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(new { revoked = true, tokenId });
});

app.MapPost("/api/v1/llm/test", async (LlmGatewayService gateway) =>
    Results.Ok(await gateway.TestUpstreamAsync()));

app.MapMethods("/api/v1/llm/v1/{**path}", new[] { HttpMethods.Get, HttpMethods.Post }, async (
    string? path,
    HttpContext http,
    LlmGatewayService gateway) => await gateway.ProxyAsync(http, path));

app.MapPost("/api/v1/agents/register", async (AgentRegistrationRequest req, ICentralStore store, TenantManagementService tenants, IOptions<SecurityOptions> sec, HttpContext http) =>
{
    var s = sec.Value;
    var tokenConfigured = !string.IsNullOrWhiteSpace(s.EnrollmentToken);
    if (s.RequireAuth || tokenConfigured)
    {
        if (string.IsNullOrWhiteSpace(req.EnrollmentToken) ||
            !FixedTimeEquals(req.EnrollmentToken, s.EnrollmentToken))
        {
            await store.AppendAuditAsync("anonymous", "agent.register", req.AgentId, "fail",
                """{"reason":"bad_enrollment_token"}""", http.Connection.RemoteIpAddress?.ToString());
            return Results.Json(new { error = "invalid_enrollment_token" }, statusCode: StatusCodes.Status403Forbidden);
        }
    }

    if (string.IsNullOrWhiteSpace(req.AgentId))
        return Results.BadRequest(new { error = "agent_id_required" });

    if (!string.IsNullOrWhiteSpace(req.TenantId))
    {
        req.TenantId = TopologyService.NormalizeTenantId(req.TenantId);
        if (await tenants.GetAsync(req.TenantId) is null)
            return Results.BadRequest(new { error = "tenant_not_found" });
    }

    await store.RegisterAgentAsync(req);
    await store.UpdateAgentIntegrityAsync(req.AgentId, req.BinarySha256, req.IsBinarySigned, null);

    // Issue new key when rotate requested or first enroll; re-register with RotateApiKey=false keeps existing (returns null).
    var issued = await store.IssueAgentApiKeyAsync(req.AgentId, rotate: req.RotateApiKey);
    if (issued is null && req.RotateApiKey)
        issued = await store.IssueAgentApiKeyAsync(req.AgentId, rotate: true);
    // First-time enroll always needs a key
    if (issued is null)
        issued = await store.IssueAgentApiKeyAsync(req.AgentId, rotate: true);

    var policy = await store.GetActivePolicyAsync(req.AgentId);
    await store.AppendAuditAsync($"agent:{req.AgentId}", "agent.register", req.AgentId, "success",
        JsonSerializer.Serialize(new { req.ComputerName, req.Platform, req.AgentVersion, tenantId = req.TenantId ?? "existing/default" }),
        http.Connection.RemoteIpAddress?.ToString());

    return Results.Ok(new AgentRegistrationResponse
    {
        Accepted = true,
        Message = "registered",
        ServerUtc = DateTimeOffset.UtcNow,
        AgentApiKey = issued,
        Policy = policy
    });
});

app.MapPost("/api/v1/agents/heartbeat", async (AgentHeartbeat hb, ICentralStore store, ActionService actions, IOptions<SecurityOptions> sec, HttpContext http) =>
{
    var s = sec.Value;
    // When RequireAuth, middleware already validated agent key — enforce agentId match if bound
    if (http.Items.TryGetValue(ApiKeyAuthMiddleware.AgentIdItem, out var bound) &&
        bound is string boundId &&
        !string.IsNullOrEmpty(boundId) &&
        !string.Equals(boundId, hb.AgentId, StringComparison.OrdinalIgnoreCase))
    {
        await store.AppendAuditAsync($"agent:{boundId}", "agent.heartbeat", hb.AgentId, "fail",
            """{"reason":"agent_id_mismatch"}""", http.Connection.RemoteIpAddress?.ToString());
        return Results.Json(new { error = "agent_id_mismatch" }, statusCode: StatusCodes.Status403Forbidden);
    }

    if (s.RequireSignedAgent && hb.IsBinarySigned == false)
    {
        return Results.Json(new { error = "unsigned_agent_rejected" }, statusCode: StatusCodes.Status403Forbidden);
    }

    if (s.ApprovedAgentSha256 is { Count: > 0 } && !string.IsNullOrWhiteSpace(hb.BinarySha256))
    {
        var ok = s.ApprovedAgentSha256.Any(a =>
            string.Equals(a.Trim(), hb.BinarySha256, StringComparison.OrdinalIgnoreCase));
        if (!ok)
            return Results.Json(new { error = "agent_hash_not_approved" }, statusCode: StatusCodes.Status403Forbidden);
    }

    await store.UpsertAgentAsync(hb);
    var serverUtc = DateTimeOffset.UtcNow;
    var skew = (hb.TimestampUtc - serverUtc).TotalSeconds;
    var pending = await actions.GetPendingForAgentAsync(hb.AgentId);

    AgentPolicy? policyOut = null;
    string? policyMsg = null;
    var active = await store.GetActivePolicyAsync(hb.AgentId);
    var applied = hb.AppliedPolicyVersion ?? 0;
    if (active.PolicyVersion > applied)
    {
        policyOut = active;
        policyMsg = $"Apply policy {active.PolicyId} v{active.PolicyVersion}";
    }

    return Results.Ok(new HeartbeatResponse
    {
        Accepted = true,
        ServerUtc = serverUtc,
        ClockSkewSeconds = skew,
        PendingActions = pending,
        Policy = policyOut,
        PolicyMessage = policyMsg
    });
});

// Back-compat
app.MapPost("/api/v1/heartbeat", async (AgentHeartbeat hb, ICentralStore store) =>
{
    await store.UpsertAgentAsync(hb);
    return Results.Ok(new { accepted = true, serverUtc = DateTimeOffset.UtcNow });
});

app.MapPost("/api/v1/events/batch", async (EventsBatchRequest req, IngestService ingest, IngestTenantResolver tenantResolver, HttpRequest http) =>
{
    var idem = req.IdempotencyKey ?? http.Headers["Idempotency-Key"].FirstOrDefault();
    var batch = new AgentIngestBatch
    {
        AgentId = req.AgentId,
        ComputerName = req.ComputerName,
        IdempotencyKey = idem,
        SecurityEvents = req.Events
    };
    var tenantId = await tenantResolver.ResolveAsync(http.HttpContext, batch.AgentId);
    return Results.Ok(await ingest.IngestAsync(batch, CancellationToken.None, tenantId));
});

app.MapPost("/api/v1/connections/batch", async (ConnectionsBatchRequest req, IngestService ingest, IngestTenantResolver tenantResolver, HttpRequest http) =>
{
    var idem = req.IdempotencyKey ?? http.Headers["Idempotency-Key"].FirstOrDefault();
    var batch = new AgentIngestBatch
    {
        AgentId = req.AgentId,
        ComputerName = req.ComputerName,
        IdempotencyKey = idem,
        NetworkConnections = req.Connections
    };
    var tenantId = await tenantResolver.ResolveAsync(http.HttpContext, batch.AgentId);
    return Results.Ok(await ingest.IngestAsync(batch, CancellationToken.None, tenantId));
});

app.MapPost("/api/v1/ingest", async (AgentIngestBatch? batch, IngestService ingest, IngestTenantResolver tenantResolver, HttpRequest http) =>
{
    if (batch is null)
    {
        Log.Warning("Ingest body null/unbound — Content-Encoding={Enc} Content-Type={Ct} Length={Len}",
            http.Headers.ContentEncoding.ToString(),
            http.ContentType,
            http.ContentLength);
        return Results.BadRequest(new { error = "invalid_ingest_body", hint = "Enable request decompression for gzip; check JSON schema" });
    }

    batch.IdempotencyKey ??= http.Headers["Idempotency-Key"].FirstOrDefault();
    var tenantId = await tenantResolver.ResolveAsync(http.HttpContext, batch.AgentId);
    var result = await ingest.IngestAsync(batch, CancellationToken.None, tenantId);
    Log.Information(
        "Ingest accepted={Ok} agent={AgentId} events={E} conn={C} proc={P} alerts={A} incidents={I}",
        result.Accepted,
        batch.AgentId,
        batch.SecurityEvents.Count,
        batch.NetworkConnections.Count,
        batch.Processes.Count,
        batch.Alerts.Count,
        result.CreatedIncidentIds.Count);
    return Results.Ok(result);
});

// Customer workspaces, agent ownership and tenant-scoped report generation.
app.MapGet("/api/v1/tenants", async (TenantManagementService tenants) =>
    Results.Ok(await tenants.ListAsync()));

app.MapGet("/api/v1/tenants/agents", async (ICentralStore store) => Results.Ok(new
{
    agents = await store.ListAgentsAsync(),
    assignments = await store.ListAgentAssignmentsAsync()
}));

app.MapGet("/api/v1/tenants/{id}", async (string id, TenantManagementService tenants) =>
{
    var tenant = await tenants.GetAsync(id);
    return tenant is null ? Results.NotFound() : Results.Ok(tenant);
});

app.MapPost("/api/v1/tenants", async (CustomerTenant? tenant, TenantManagementService tenants, ICentralStore store, HttpContext http) =>
{
    if (tenant is null) return Results.BadRequest(new { error = "invalid_customer" });
    var saved = await tenants.SaveAsync(tenant);
    await store.AppendAuditAsync(OperatorActor(http), "tenant.upsert", saved.TenantId, "success",
        JsonSerializer.Serialize(new { saved.Name, saved.Plan, saved.Status }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Created($"/api/v1/tenants/{saved.TenantId}", saved);
});

app.MapPut("/api/v1/tenants/{id}", async (string id, CustomerTenant? tenant, TenantManagementService tenants, ICentralStore store, HttpContext http) =>
{
    if (tenant is null) return Results.BadRequest(new { error = "invalid_customer" });
    tenant.TenantId = id;
    if (await tenants.GetAsync(id) is null) return Results.NotFound();
    var saved = await tenants.SaveAsync(tenant);
    await store.AppendAuditAsync(OperatorActor(http), "tenant.update", saved.TenantId, "success",
        JsonSerializer.Serialize(new { saved.Name, saved.Plan, saved.Status }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(saved);
});

app.MapPut("/api/v1/tenants/{tenantId}/agents/{agentId}", async (
    string tenantId,
    string agentId,
    TenantManagementService tenants,
    ICentralStore store,
    HttpContext http) =>
{
    await tenants.AssignAgentAsync(tenantId, agentId);
    await store.AppendAuditAsync(OperatorActor(http), "tenant.agent.assign", agentId, "success",
        JsonSerializer.Serialize(new { tenantId = TopologyService.NormalizeTenantId(tenantId) }), http.Connection.RemoteIpAddress?.ToString());
    return Results.NoContent();
});

app.MapGet("/api/v1/reports", async (TenantReportService reports, HttpContext http, int take = 50) =>
    Results.Ok(await reports.ListAsync(TopologyService.ResolveTenantId(http), take)));

app.MapPost("/api/v1/reports", async (
    CreateSecurityReportRequest? request,
    TenantReportService reports,
    ICentralStore store,
    HttpContext http) =>
{
    var tenantId = TopologyService.ResolveTenantId(http);
    var report = await reports.GenerateAsync(tenantId, request ?? new CreateSecurityReportRequest());
    await store.AppendAuditAsync(OperatorActor(http), "report.generate", report.ReportId, "success",
        JsonSerializer.Serialize(new { tenantId, report.PeriodStartUtc, report.PeriodEndUtc }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Created($"/api/v1/reports/{report.ReportId}", report);
});

app.MapGet("/api/v1/reports/{id}", async (string id, TenantReportService reports, HttpContext http) =>
{
    var report = await reports.GetAsync(TopologyService.ResolveTenantId(http), id);
    return report is null ? Results.NotFound() : Results.Ok(report);
});

app.MapGet("/api/v1/reports/{id}/download", async (
    string id,
    string? format,
    TenantReportService reports,
    HttpContext http) =>
{
    var report = await reports.GetAsync(TopologyService.ResolveTenantId(http), id);
    if (report is null) return Results.NotFound();
    var safeId = report.ReportId[..Math.Min(12, report.ReportId.Length)];
    return string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase)
        ? Results.File(System.Text.Encoding.UTF8.GetBytes(TenantReportService.RenderCsv(report)), "text/csv; charset=utf-8", $"ntshield-{report.TenantId}-{safeId}.csv")
        : Results.File(System.Text.Encoding.UTF8.GetBytes(TenantReportService.RenderHtml(report)), "text/html; charset=utf-8", $"ntshield-{report.TenantId}-{safeId}.html");
});

// Tenant-scoped infrastructure catalog, Canvas topology and declarative
// detection workflow APIs. The tenant header defaults to "default" for the
// existing single-tenant dashboard; deployments should set it from an
// authenticated tenant claim when the Central identity layer is enabled.
app.MapGet("/api/v1/topology/kinds", () => Results.Ok(TopologyService.NodeKinds));

app.MapGet("/api/v1/assets", async (TopologyService topology, HttpContext http) =>
    Results.Ok(await topology.ListAssetsAsync(TopologyService.ResolveTenantId(http))));

app.MapGet("/api/v1/assets/{id}", async (string id, TopologyService topology, HttpContext http) =>
{
    var asset = await topology.GetAssetAsync(TopologyService.ResolveTenantId(http), id);
    return asset is null ? Results.NotFound() : Results.Ok(asset);
});

app.MapPost("/api/v1/assets", async (TenantAsset? asset, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (asset is null) return Results.BadRequest(new { error = "invalid_asset" });
    var tenantId = TopologyService.ResolveTenantId(http);
    var saved = await topology.SaveAssetAsync(tenantId, asset);
    await store.AppendAuditAsync(OperatorActor(http), "asset.upsert", saved.AssetId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Kind, saved.Name }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Created($"/api/v1/assets/{saved.AssetId}", saved);
});

app.MapPut("/api/v1/assets/{id}", async (string id, TenantAsset? asset, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (asset is null) return Results.BadRequest(new { error = "invalid_asset" });
    asset.AssetId = id;
    var tenantId = TopologyService.ResolveTenantId(http);
    var existing = await topology.GetAssetAsync(tenantId, id);
    if (existing is null) return Results.NotFound();
    var saved = await topology.SaveAssetAsync(tenantId, asset);
    await store.AppendAuditAsync(OperatorActor(http), "asset.update", saved.AssetId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Kind, saved.Name }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(saved);
});

app.MapDelete("/api/v1/assets/{id}", async (string id, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    var tenantId = TopologyService.ResolveTenantId(http);
    var deleted = await topology.DeleteAssetAsync(tenantId, id);
    if (!deleted) return Results.NotFound();
    await store.AppendAuditAsync(OperatorActor(http), "asset.delete", id, "success",
        JsonSerializer.Serialize(new { tenantId }), http.Connection.RemoteIpAddress?.ToString());
    return Results.NoContent();
});

app.MapGet("/api/v1/topologies", async (TopologyService topology, HttpContext http) =>
    Results.Ok(await topology.ListTopologiesAsync(TopologyService.ResolveTenantId(http))));

app.MapGet("/api/v1/topologies/{id}", async (string id, TopologyService topology, HttpContext http) =>
{
    var item = await topology.GetTopologyAsync(TopologyService.ResolveTenantId(http), id);
    return item is null ? Results.NotFound() : Results.Ok(item);
});

app.MapPost("/api/v1/topologies", async (TopologyDocument? document, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (document is null) return Results.BadRequest(new { error = "invalid_topology" });
    var tenantId = TopologyService.ResolveTenantId(http);
    var saved = await topology.SaveTopologyAsync(tenantId, document);
    await store.AppendAuditAsync(OperatorActor(http), "topology.upsert", saved.TopologyId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Name, nodes = saved.Nodes.Count, edges = saved.Edges.Count }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Created($"/api/v1/topologies/{saved.TopologyId}", saved);
});

app.MapPut("/api/v1/topologies/{id}", async (string id, TopologyDocument? document, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (document is null) return Results.BadRequest(new { error = "invalid_topology" });
    var tenantId = TopologyService.ResolveTenantId(http);
    if (await topology.GetTopologyAsync(tenantId, id) is null) return Results.NotFound();
    document.TopologyId = id;
    var saved = await topology.SaveTopologyAsync(tenantId, document);
    await store.AppendAuditAsync(OperatorActor(http), "topology.update", saved.TopologyId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Name, nodes = saved.Nodes.Count, edges = saved.Edges.Count }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(saved);
});

app.MapDelete("/api/v1/topologies/{id}", async (string id, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    var tenantId = TopologyService.ResolveTenantId(http);
    var deleted = await topology.DeleteTopologyAsync(tenantId, id);
    if (!deleted) return Results.NotFound();
    await store.AppendAuditAsync(OperatorActor(http), "topology.delete", id, "success",
        JsonSerializer.Serialize(new { tenantId }), http.Connection.RemoteIpAddress?.ToString());
    return Results.NoContent();
});

app.MapGet("/api/v1/workflows", async (TopologyService topology, HttpContext http) =>
    Results.Ok(await topology.ListWorkflowsAsync(TopologyService.ResolveTenantId(http))));

app.MapGet("/api/v1/workflows/{id}", async (string id, TopologyService topology, HttpContext http) =>
{
    var item = await topology.GetWorkflowAsync(TopologyService.ResolveTenantId(http), id);
    return item is null ? Results.NotFound() : Results.Ok(item);
});

app.MapPost("/api/v1/workflows", async (DetectionWorkflow? workflow, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (workflow is null) return Results.BadRequest(new { error = "invalid_workflow" });
    var tenantId = TopologyService.ResolveTenantId(http);
    var saved = await topology.SaveWorkflowAsync(tenantId, workflow);
    await store.AppendAuditAsync(OperatorActor(http), "workflow.upsert", saved.WorkflowId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Name, saved.Enabled, nodes = saved.Nodes.Count, edges = saved.Edges.Count }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Created($"/api/v1/workflows/{saved.WorkflowId}", saved);
});

app.MapPut("/api/v1/workflows/{id}", async (string id, DetectionWorkflow? workflow, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    if (workflow is null) return Results.BadRequest(new { error = "invalid_workflow" });
    var tenantId = TopologyService.ResolveTenantId(http);
    if (await topology.GetWorkflowAsync(tenantId, id) is null) return Results.NotFound();
    workflow.WorkflowId = id;
    var saved = await topology.SaveWorkflowAsync(tenantId, workflow);
    await store.AppendAuditAsync(OperatorActor(http), "workflow.update", saved.WorkflowId, "success",
        JsonSerializer.Serialize(new { tenantId, saved.Name, saved.Enabled, nodes = saved.Nodes.Count, edges = saved.Edges.Count }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(saved);
});

app.MapDelete("/api/v1/workflows/{id}", async (string id, TopologyService topology, ICentralStore store, HttpContext http) =>
{
    var tenantId = TopologyService.ResolveTenantId(http);
    var deleted = await topology.DeleteWorkflowAsync(tenantId, id);
    if (!deleted) return Results.NotFound();
    await store.AppendAuditAsync(OperatorActor(http), "workflow.delete", id, "success",
        JsonSerializer.Serialize(new { tenantId }), http.Connection.RemoteIpAddress?.ToString());
    return Results.NoContent();
});

app.MapPost("/api/v1/incidents", async (Incident incident, ICentralStore store, LateralMovementTracker tracker) =>
{
    await store.UpsertIncidentAsync(incident);
    tracker.IngestIncidents([incident]);
    Log.Warning("Incident upserted:\n{Display}", incident.FormatDisplay());
    return Results.Ok(incident);
});

app.MapGet("/api/v1/events", async (ICentralStore store, HttpContext http, int take = 250) =>
{
    var events = await store.ListSecurityEventsAsync(
        Math.Clamp(take, 1, 500),
        TopologyService.ResolveTenantId(http));
    return Results.Ok(events);
});

app.MapGet("/api/v1/incidents", async (ICentralStore store, HttpContext http, int take = 100) =>
{
    var incidents = await store.ListIncidentsAsync(
        Math.Clamp(take, 1, 500),
        TopologyService.ResolveTenantId(http));
    return Results.Ok(incidents);
});

app.MapGet("/api/v1/incidents/count", async (ICentralStore store, HttpContext http) =>
{
    var total = await store.CountIncidentsAsync(TopologyService.ResolveTenantId(http));
    return Results.Ok(new { total });
});

app.MapGet("/api/v1/incidents/{id}", async (string id, ICentralStore store, HttpContext http) =>
{
    var incident = await store.GetIncidentAsync(id, TopologyService.ResolveTenantId(http));
    return incident is null ? Results.NotFound() : Results.Ok(incident);
});

app.MapPost("/api/v1/geoip/lookup", async (
    GeoIpLookupRequest request,
    GeoIpService geoIp,
    HttpContext http) =>
{
    var locations = await geoIp.LookupAsync(request.Ips, http.RequestAborted);
    return Results.Ok(locations);
});

app.MapPost("/api/v1/incidents/{id}/ai/analyze", async (
    string id,
    ICentralStore store,
    AiAnalystProxyService analyst,
    HttpContext http) =>
{
    if (await store.GetIncidentAsync(id, TopologyService.ResolveTenantId(http)) is null)
        return Results.NotFound(new { error = "incident_not_found" });

    // The browser's tenant header is not forwarded to Brain. Until Central RBAC
    // supplies a signed tenant claim, the mapping stays server-side in config.
    var tenantId = analyst.TenantId;
    try
    {
        var json = await analyst.AnalyzeIncidentAsync(id, tenantId, http.RequestAborted);
        await store.AppendAuditAsync(
            OperatorActor(http),
            "ai.incident.analyze",
            id,
            "success",
            JsonSerializer.Serialize(new { tenantId, source = "ntshield-brain" }),
            http.Connection.RemoteIpAddress?.ToString());
        return Results.Content(json, "application/json", System.Text.Encoding.UTF8);
    }
    catch (AiAnalystProxyException ex)
    {
        await store.AppendAuditAsync(
            OperatorActor(http),
            "ai.incident.analyze",
            id,
            "fail",
            JsonSerializer.Serialize(new { tenantId, error = ex.Error }),
            http.Connection.RemoteIpAddress?.ToString());
        return Results.Json(new { error = ex.Error }, statusCode: ex.StatusCode);
    }
});

app.MapPost("/api/v1/actions", async (ResponseActionRequest request, ActionService actions, ICentralStore store, HttpContext http) =>
{
    var actor = http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var p) ? p?.ToString() ?? "anonymous" : "anonymous";
    var saved = await actions.EnqueueAsync(request);
    await store.AppendAuditAsync(
        actor == "operator" ? "operator" : actor,
        "action.enqueue",
        request.TargetAgentId ?? request.RequestId,
        "success",
        JsonSerializer.Serialize(new { request.ActionType, request.TargetIp, request.TargetPort, request.ServiceName, request.Approved }),
        http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(saved);
});

app.MapGet("/api/v1/audit", async (ICentralStore store, int take = 100) =>
    Results.Ok(await store.ListAuditAsync(Math.Clamp(take, 1, 500))));

app.MapGet("/api/v1/policy", async (ICentralStore store) =>
    Results.Ok(await store.GetActivePolicyAsync()));

app.MapPut("/api/v1/policy", async (AgentPolicy policy, ICentralStore store, HttpContext http) =>
{
    if (policy.PolicyVersion < 1) policy.PolicyVersion = 1;
    if (string.IsNullOrWhiteSpace(policy.PolicyId)) policy.PolicyId = "default";
    // Bump version if client did not
    var current = await store.GetActivePolicyAsync();
    if (policy.PolicyVersion <= current.PolicyVersion)
        policy.PolicyVersion = current.PolicyVersion + 1;
    await store.UpsertPolicyAsync(policy);
    await store.AppendAuditAsync("operator", "policy.update", policy.PolicyId, "success",
        JsonSerializer.Serialize(new { policy.PolicyVersion, policy.Mode, policy.DetectOnly }),
        http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(policy);
});

app.MapPut("/api/v1/protection-pack", async (ProtectionPack pack, ICentralStore store, IOptions<SecurityOptions> security, HttpContext http) =>
{
    if (string.IsNullOrWhiteSpace(pack.PackId) || pack.Version < 1 || string.IsNullOrWhiteSpace(pack.PayloadJson))
        return Results.BadRequest(new { error = "invalid_protection_pack" });

    var sha = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pack.PayloadJson))).ToLowerInvariant();
    if (!string.Equals(sha, pack.Sha256, StringComparison.OrdinalIgnoreCase))
        return Results.BadRequest(new { error = "protection_pack_sha256_invalid" });
    if (string.IsNullOrWhiteSpace(pack.Signature))
        return Results.BadRequest(new { error = "protection_pack_signature_required" });
    if (string.IsNullOrWhiteSpace(security.Value.PolicySigningPublicKeyPem))
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    if (!UpdatePackageValidator.VerifySignedConfig(pack.PayloadJson, pack.Signature, security.Value.PolicySigningPublicKeyPem))
        return Results.BadRequest(new { error = "protection_pack_signature_invalid" });

    var current = await store.GetActivePolicyAsync();
    current.PolicyVersion = Math.Max(current.PolicyVersion + 1, pack.Version);
    current.ProtectionPack = pack;
    await store.UpsertPolicyAsync(current);
    await store.AppendAuditAsync("operator", "protection_pack.update", pack.PackId, "success",
        JsonSerializer.Serialize(new { pack.Version, pack.Sha256 }), http.Connection.RemoteIpAddress?.ToString());
    return Results.Ok(new { accepted = true, policyVersion = current.PolicyVersion, pack });
});

app.MapGet("/api/v1/actions/{id}", async (string id, ActionService actions) =>
{
    var action = await actions.GetAsync(id);
    return action is null ? Results.NotFound() : Results.Ok(action);
});

app.MapGet("/api/v1/agents", async (ICentralStore store, HttpContext http) =>
    Results.Ok(await store.ListAgentsAsync(TopologyService.ResolveTenantId(http))));

app.MapGet("/api/v1/agents/{agentId}", async (string agentId, ICentralStore store, HttpContext http, int metrics = 60) =>
{
    var item = await store.GetAgentAsync(agentId, Math.Clamp(metrics, 1, 500), TopologyService.ResolveTenantId(http));
    return item is null ? Results.NotFound() : Results.Ok(item);
});

app.MapGet("/api/v1/agents/{agentId}/metrics", async (string agentId, ICentralStore store, HttpContext http, int take = 60) =>
{
    var tenantId = TopologyService.ResolveTenantId(http);
    if (await store.GetAgentAsync(agentId, 1, tenantId) is null) return Results.NotFound();
    return Results.Ok(await store.ListAgentMetricsAsync(agentId, Math.Clamp(take, 1, 500)));
});

// Threat catalog + multi-host lateral tracking (detect/track only)
app.MapGet("/api/v1/threats/catalog", (LateralMovementTracker tracker) =>
    Results.Ok(tracker.GetThreatCatalog()));

app.MapGet("/api/v1/threats", async (LateralMovementTracker tracker, ICentralStore store, HttpContext http, int take = 100) =>
    Results.Ok(await ListTenantCampaignsAsync(store, tracker, TopologyService.ResolveTenantId(http), take)));

app.MapGet("/api/v1/threats/{id}", async (string id, LateralMovementTracker tracker, ICentralStore store, HttpContext http) =>
{
    var c = (await ListTenantCampaignsAsync(store, tracker, TopologyService.ResolveTenantId(http), 500))
        .FirstOrDefault(item => string.Equals(item.CampaignId, id, StringComparison.OrdinalIgnoreCase));
    return c is null ? Results.NotFound() : Results.Ok(c);
});

app.MapGet("/api/v1/threats/{id}/path", async (string id, LateralMovementTracker tracker, ICentralStore store, HttpContext http) =>
{
    var c = (await ListTenantCampaignsAsync(store, tracker, TopologyService.ResolveTenantId(http), 500))
        .FirstOrDefault(item => string.Equals(item.CampaignId, id, StringComparison.OrdinalIgnoreCase));
    if (c is null)
    {
        return Results.NotFound();
    }

    return Results.Ok(new
    {
        campaignId = c.CampaignId,
        display = c.FormatDisplay(),
        hops = c.Hops,
        hosts = c.InvolvedHosts,
        ips = c.InvolvedIps,
        users = c.InvolvedUsernames,
        categories = c.ThreatCategories
    });
});

app.MapGet("/api/v1/threats/by-host/{hostOrIp}", async (string hostOrIp, LateralMovementTracker tracker, ICentralStore store, HttpContext http) =>
{
    var campaigns = await ListTenantCampaignsAsync(store, tracker, TopologyService.ResolveTenantId(http), 500);
    return Results.Ok(campaigns.Where(campaign =>
        campaign.InvolvedIps.Any(ip => string.Equals(ip, hostOrIp, StringComparison.OrdinalIgnoreCase)) ||
        campaign.InvolvedHosts.Any(host => string.Equals(host, hostOrIp, StringComparison.OrdinalIgnoreCase))));
});

Log.Information("NT Shield Server starting");
app.Run();

static bool FixedTimeEquals(string a, string b)
{
    var ba = System.Text.Encoding.UTF8.GetBytes(a ?? "");
    var bb = System.Text.Encoding.UTF8.GetBytes(b ?? "");
    return ba.Length == bb.Length &&
           System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
}

static string OperatorActor(HttpContext http)
{
    return http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var principal)
        ? principal?.ToString() ?? "anonymous"
        : "anonymous";
}

static async Task<IReadOnlyList<ThreatCampaign>> ListTenantCampaignsAsync(
    ICentralStore store,
    LateralMovementTracker tracker,
    string tenantId,
    int take)
{
    var agents = await store.ListAgentsAsync(tenantId);
    var agentIds = agents.OfType<AgentInventoryItem>()
        .Select(agent => agent.AgentId)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);
    var incidents = await store.ListIncidentsAsync(500, tenantId);
    var incidentIds = incidents.Select(item => item.IncidentId).ToHashSet(StringComparer.OrdinalIgnoreCase);
    return tracker.ListCampaigns(500)
        .Where(campaign =>
            campaign.RelatedIncidentIds.Any(incidentIds.Contains) ||
            campaign.Hops.Any(hop =>
                (!string.IsNullOrWhiteSpace(hop.FromAgentId) && agentIds.Contains(hop.FromAgentId)) ||
                (!string.IsNullOrWhiteSpace(hop.ToAgentId) && agentIds.Contains(hop.ToAgentId))))
        .OrderByDescending(campaign => campaign.LastSeenUtc)
        .Take(Math.Clamp(take, 1, 500))
        .ToList();
}

/// <summary>
/// Create or load a durable self-signed HTTPS cert for Windows Service / production lab use
/// (dev-certs are per-user and unavailable under LocalSystem).
/// Includes all local NIC IPs + optional public host/IPs so remote agents can match the cert SAN.
/// </summary>
static X509Certificate2 EnsureServerCertificate(
    string pfxPath,
    string password,
    string? extraSans = null,
    bool forceRegenerate = false)
{
    try
    {
        var dir = Path.GetDirectoryName(pfxPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var desiredDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost" };
        var desiredIps = new HashSet<System.Net.IPAddress>();
        desiredIps.Add(System.Net.IPAddress.Loopback);
        desiredIps.Add(System.Net.IPAddress.IPv6Loopback);

        if (!string.IsNullOrWhiteSpace(Environment.MachineName))
            desiredDns.Add(Environment.MachineName);

        try
        {
            var fqdn = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
            if (!string.IsNullOrWhiteSpace(fqdn))
                desiredDns.Add(fqdn);
        }
        catch
        {
            // ignore DNS lookup failures under service accounts
        }

        // All local NIC addresses (so LAN IP works without manual config)
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType is System.Net.NetworkInformation.NetworkInterfaceType.Loopback
                    or System.Net.NetworkInformation.NetworkInterfaceType.Tunnel)
                    continue;

                var props = ni.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                {
                    var ip = ua.Address;
                    if (ip.AddressFamily is System.Net.Sockets.AddressFamily.InterNetwork
                        or System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        // Skip link-local (APIPA / fe80::)
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                            && ip.ToString().StartsWith("169.254.", StringComparison.Ordinal))
                            continue;
                        if (ip.IsIPv6LinkLocal)
                            continue;
                        desiredIps.Add(ip);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Could not enumerate NIC addresses for certificate SAN");
        }

        foreach (var token in SplitSans(extraSans))
        {
            if (System.Net.IPAddress.TryParse(token, out var ip))
                desiredIps.Add(ip);
            else
                desiredDns.Add(token);
        }

        if (File.Exists(pfxPath) && !forceRegenerate)
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password);
            if (CertificateCoversSans(existing, desiredDns, desiredIps))
            {
                ExportPublicCer(existing, pfxPath);
                return existing;
            }

            // Old cert only had localhost — regenerate so remote IP HTTPS works
            var bak = pfxPath + $".bak.{DateTime.UtcNow:yyyyMMddHHmmss}";
            try
            {
                File.Copy(pfxPath, bak, overwrite: true);
                Log.Warning(
                    "Existing HTTPS cert missing required SANs (desired DNS={Dns} IPs={Ips}). Backed up to {Bak} and regenerating.",
                    string.Join(",", desiredDns),
                    string.Join(",", desiredIps),
                    bak);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Could not backup old certificate before regenerate");
            }

            existing.Dispose();
            try { File.Delete(pfxPath); } catch { /* recreate below */ }
        }
        else if (File.Exists(pfxPath) && forceRegenerate)
        {
            Log.Information("Security:RegenerateCertificate=true — recreating HTTPS certificate");
            try
            {
                File.Copy(pfxPath, pfxPath + $".bak.{DateTime.UtcNow:yyyyMMddHHmmss}", overwrite: true);
                File.Delete(pfxPath);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Could not remove old certificate for forced regenerate");
            }
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=NTShieldCentral",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // serverAuth
                false));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var san = new SubjectAlternativeNameBuilder();
        foreach (var dns in desiredDns.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            san.AddDnsName(dns);
        foreach (var ip in desiredIps.OrderBy(x => x.AddressFamily).ThenBy(x => x.ToString()))
            san.AddIpAddress(ip);
        req.CertificateExtensions.Add(san.Build());

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(pfxPath, pfxBytes);
        var exportable = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
        ExportPublicCer(exportable, pfxPath);
        Log.Information(
            "Created self-signed HTTPS certificate at {Path} SANs={Sans}",
            pfxPath,
            DescribeCertificateSans(exportable));
        return exportable;
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Failed to create/load HTTPS certificate at {Path}", pfxPath);
        throw;
    }
}

static IEnumerable<string> SplitSans(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw))
        yield break;
    foreach (var part in raw.Split([',', ';', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (part.Length > 0)
            yield return part;
    }
}

static bool CertificateCoversSans(
    X509Certificate2 cert,
    HashSet<string> desiredDns,
    HashSet<System.Net.IPAddress> desiredIps)
{
    var haveDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var haveIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var ext in cert.Extensions)
    {
        if (ext is X509SubjectAlternativeNameExtension sanExt)
        {
            foreach (var dns in sanExt.EnumerateDnsNames())
                haveDns.Add(dns);
            foreach (var ip in sanExt.EnumerateIPAddresses())
                haveIps.Add(ip.ToString());
        }
    }

    // Also treat CN as weak DNS fallback
    var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
    if (!string.IsNullOrWhiteSpace(cn))
        haveDns.Add(cn);

    // Require at least one non-loopback IP when machine has one (old certs only had 127.0.0.1)
    var nonLoopbackDesired = desiredIps
        .Where(ip => !System.Net.IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal)
        .Select(ip => ip.ToString())
        .ToList();
    if (nonLoopbackDesired.Count > 0 && !nonLoopbackDesired.Any(haveIps.Contains))
        return false;

    // Extra configured public host/IP must be present
    foreach (var dns in desiredDns)
    {
        if (dns.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            continue;
        if (dns.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            continue;
        // Extra DNS from config
        if (!haveDns.Contains(dns))
            return false;
    }

    foreach (var ip in desiredIps)
    {
        if (System.Net.IPAddress.IsLoopback(ip))
            continue;
        // Only require extras that were explicitly desired and non-link-local
        // Local NIC IPs: require at least one match overall (checked above).
        // Public/extra IPs that are not on NIC still need to be in cert:
        if (!haveIps.Contains(ip.ToString()))
        {
            // If this IP is not a local NIC address we enumerated... still required if in desired set.
            // Soft: if any non-loopback IP is present we're OK for local NICs; extras already checked via dns/ip sets.
            // For public IP that isn't on a NIC (NAT), it must still be in cert.
            var isLocalNic = false;
            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.Equals(ip))
                        {
                            isLocalNic = true;
                            break;
                        }
                    }
                    if (isLocalNic) break;
                }
            }
            catch { /* ignore */ }

            if (!isLocalNic)
                return false;
        }
    }

    return haveDns.Count > 0;
}

static void ExportPublicCer(X509Certificate2 cert, string pfxPath)
{
    try
    {
        var cerPath = Path.ChangeExtension(pfxPath, ".cer");
        File.WriteAllBytes(cerPath, cert.Export(X509ContentType.Cert));
    }
    catch (Exception ex)
    {
        Log.Debug(ex, "Could not export public .cer next to PFX");
    }
}

static string DescribeCertificateSans(X509Certificate2 cert)
{
    try
    {
        var parts = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension sanExt)
            {
                parts.AddRange(sanExt.EnumerateDnsNames().Select(d => "DNS:" + d));
                parts.AddRange(sanExt.EnumerateIPAddresses().Select(ip => "IP:" + ip));
            }
        }
        return parts.Count == 0 ? "(none)" : string.Join(", ", parts);
    }
    catch
    {
        return "(unavailable)";
    }
}

public partial class Program;
