using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
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
builder.Services.AddSingleton<IngestService>();
builder.Services.AddSingleton<ActionService>();

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

app.MapPost("/api/v1/agents/register", async (AgentRegistrationRequest req, ICentralStore store, IOptions<SecurityOptions> sec, HttpContext http) =>
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
        JsonSerializer.Serialize(new { req.ComputerName, req.Platform, req.AgentVersion }),
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

app.MapPost("/api/v1/events/batch", async (EventsBatchRequest req, IngestService ingest, HttpRequest http) =>
{
    var idem = req.IdempotencyKey ?? http.Headers["Idempotency-Key"].FirstOrDefault();
    var batch = new AgentIngestBatch
    {
        AgentId = req.AgentId,
        ComputerName = req.ComputerName,
        IdempotencyKey = idem,
        SecurityEvents = req.Events
    };
    return Results.Ok(await ingest.IngestAsync(batch, CancellationToken.None));
});

app.MapPost("/api/v1/connections/batch", async (ConnectionsBatchRequest req, IngestService ingest, HttpRequest http) =>
{
    var idem = req.IdempotencyKey ?? http.Headers["Idempotency-Key"].FirstOrDefault();
    var batch = new AgentIngestBatch
    {
        AgentId = req.AgentId,
        ComputerName = req.ComputerName,
        IdempotencyKey = idem,
        NetworkConnections = req.Connections
    };
    return Results.Ok(await ingest.IngestAsync(batch, CancellationToken.None));
});

app.MapPost("/api/v1/ingest", async (AgentIngestBatch? batch, IngestService ingest, HttpRequest http) =>
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
    var result = await ingest.IngestAsync(batch, CancellationToken.None);
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

app.MapPost("/api/v1/incidents", async (Incident incident, ICentralStore store) =>
{
    await store.UpsertIncidentAsync(incident);
    Log.Warning("Incident upserted:\n{Display}", incident.FormatDisplay());
    return Results.Ok(incident);
});

app.MapGet("/api/v1/incidents", async (ICentralStore store, int take = 100) =>
{
    var incidents = await store.ListIncidentsAsync(Math.Clamp(take, 1, 500));
    return Results.Ok(incidents);
});

app.MapGet("/api/v1/incidents/{id}", async (string id, ICentralStore store) =>
{
    var incident = await store.GetIncidentAsync(id);
    return incident is null ? Results.NotFound() : Results.Ok(incident);
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

app.MapGet("/api/v1/actions/{id}", async (string id, ActionService actions) =>
{
    var action = await actions.GetAsync(id);
    return action is null ? Results.NotFound() : Results.Ok(action);
});

app.MapGet("/api/v1/agents", async (ICentralStore store) => Results.Ok(await store.ListAgentsAsync()));

app.MapGet("/api/v1/agents/{agentId}", async (string agentId, ICentralStore store, int metrics = 60) =>
{
    var item = await store.GetAgentAsync(agentId, Math.Clamp(metrics, 1, 500));
    return item is null ? Results.NotFound() : Results.Ok(item);
});

app.MapGet("/api/v1/agents/{agentId}/metrics", async (string agentId, ICentralStore store, int take = 60) =>
    Results.Ok(await store.ListAgentMetricsAsync(agentId, Math.Clamp(take, 1, 500))));

// Threat catalog + multi-host lateral tracking (detect/track only)
app.MapGet("/api/v1/threats/catalog", (LateralMovementTracker tracker) =>
    Results.Ok(tracker.GetThreatCatalog()));

app.MapGet("/api/v1/threats", (LateralMovementTracker tracker, int take = 100) =>
    Results.Ok(tracker.ListCampaigns(take)));

app.MapGet("/api/v1/threats/{id}", (string id, LateralMovementTracker tracker) =>
{
    var c = tracker.GetCampaign(id);
    return c is null ? Results.NotFound() : Results.Ok(c);
});

app.MapGet("/api/v1/threats/{id}/path", (string id, LateralMovementTracker tracker) =>
{
    var c = tracker.GetCampaign(id);
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

app.MapGet("/api/v1/threats/by-host/{hostOrIp}", (string hostOrIp, LateralMovementTracker tracker) =>
    Results.Ok(tracker.FindByHostOrIp(hostOrIp)));

Log.Information("NT Shield Server starting");
app.Run();

static bool FixedTimeEquals(string a, string b)
{
    var ba = System.Text.Encoding.UTF8.GetBytes(a ?? "");
    var bb = System.Text.Encoding.UTF8.GetBytes(b ?? "");
    return ba.Length == bb.Length &&
           System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
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
