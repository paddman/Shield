using System.Text.Json;
using NTShield.Server.Data;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Security;

/// <summary>
/// Validates X-NTShield-Api-Key when Security:RequireAuth=true.
/// Sets HttpContext.Items: NTShieldAuthPrincipal (operator|agent|anonymous), NTShieldAgentId.
/// </summary>
public sealed class ApiKeyAuthMiddleware
{
    public const string PrincipalItem = "NTShieldAuthPrincipal";
    public const string AgentIdItem = "NTShieldAgentId";

    private readonly RequestDelegate _next;
    private readonly ILogger<ApiKeyAuthMiddleware> _logger;

    public ApiKeyAuthMiddleware(RequestDelegate next, ILogger<ApiKeyAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext ctx, IOptions<SecurityOptions> securityOpt, ICentralStore store)
    {
        var security = securityOpt.Value;
        var path = ctx.Request.Path.Value ?? "";

        if (IsPublic(path))
        {
            ctx.Items[PrincipalItem] = "anonymous";
            await _next(ctx);
            return;
        }

        // Register: enrollment token validated in handler (body). Allow through.
        if (path.StartsWith("/api/v1/agents/register", StringComparison.OrdinalIgnoreCase) &&
            HttpMethods.IsPost(ctx.Request.Method))
        {
            ctx.Items[PrincipalItem] = "enroll";
            await _next(ctx);
            return;
        }

        if (!security.RequireAuth)
        {
            // Soft mode: still parse key if present for audit actor
            await TryAttachPrincipalAsync(ctx, security, store);
            if (!ctx.Items.ContainsKey(PrincipalItem))
                ctx.Items[PrincipalItem] = "anonymous";
            await _next(ctx);
            return;
        }

        var key = GetApiKey(ctx);
        if (string.IsNullOrWhiteSpace(key))
        {
            await FailAsync(ctx, store, "missing_api_key", path);
            return;
        }

        if (!string.IsNullOrEmpty(security.OperatorApiKey) &&
            FixedTimeEquals(key, security.OperatorApiKey))
        {
            ctx.Items[PrincipalItem] = "operator";
            await _next(ctx);
            return;
        }

        // Agent paths only for agent keys
        if (IsAgentPath(path))
        {
            var agentId = await store.FindAgentIdByApiKeyHashAsync(SecretBootstrapper.HashApiKey(key));
            if (!string.IsNullOrEmpty(agentId))
            {
                ctx.Items[PrincipalItem] = "agent";
                ctx.Items[AgentIdItem] = agentId;
                await _next(ctx);
                return;
            }
        }

        // Operator-only paths reject agent keys
        await FailAsync(ctx, store, "invalid_api_key", path);
    }

    private async Task TryAttachPrincipalAsync(HttpContext ctx, SecurityOptions security, ICentralStore store)
    {
        var key = GetApiKey(ctx);
        if (string.IsNullOrWhiteSpace(key)) return;

        if (!string.IsNullOrEmpty(security.OperatorApiKey) && FixedTimeEquals(key, security.OperatorApiKey))
        {
            ctx.Items[PrincipalItem] = "operator";
            return;
        }

        var agentId = await store.FindAgentIdByApiKeyHashAsync(SecretBootstrapper.HashApiKey(key));
        if (!string.IsNullOrEmpty(agentId))
        {
            ctx.Items[PrincipalItem] = "agent";
            ctx.Items[AgentIdItem] = agentId;
        }
    }

    private async Task FailAsync(HttpContext ctx, ICentralStore store, string reason, string path)
    {
        _logger.LogWarning("Auth failed path={Path} reason={Reason} ip={Ip}",
            path, reason, ctx.Connection.RemoteIpAddress);
        try
        {
            await store.AppendAuditAsync(
                actor: "anonymous",
                action: "auth.fail",
                target: path,
                result: "fail",
                detailJson: JsonSerializer.Serialize(new { reason }),
                sourceIp: ctx.Connection.RemoteIpAddress?.ToString());
        }
        catch
        {
            // ignore audit failures
        }

        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(
            JsonSerializer.Serialize(new { error = "unauthorized", reason }));
    }

    private static string? GetApiKey(HttpContext ctx)
    {
        if (ctx.Request.Headers.TryGetValue(SecurityOptions.ApiKeyHeader, out var h) &&
            !string.IsNullOrWhiteSpace(h))
            return h.ToString().Trim();

        var auth = ctx.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();

        return null;
    }

    private static bool IsPublic(string path) =>
        path.Equals("/health", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase);

    private static bool IsAgentPath(string path) =>
        path.StartsWith("/api/v1/agents/heartbeat", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/heartbeat", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/ingest", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/events/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/connections/", StringComparison.OrdinalIgnoreCase);

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
