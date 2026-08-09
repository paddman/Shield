using System.Text.Json;
using System.Security.Claims;
using NTShield.Server.Data;
using NTShield.Server.LLM;
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

    public async Task InvokeAsync(
        HttpContext ctx,
        IOptions<SecurityOptions> securityOpt,
        ICentralStore store,
        LlmGatewayService llmGateway,
        SecurityAuditQueue auditQueue)
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

        // LLM proxy tokens are separate from operator and Agent keys. They are
        // always required, including when Central is running in soft-auth mode.
        if (IsLlmProxyPath(path))
        {
            var llmToken = GetLlmToken(ctx);
            var authenticated = await llmGateway.AuthenticateTokenAsync(llmToken);
            if (authenticated is not null)
            {
                ctx.Items[PrincipalItem] = "llm-client";
                ctx.Items["NTShieldLlmTokenId"] = authenticated.TokenId;
                await _next(ctx);
                return;
            }

            await FailAsync(ctx, auditQueue, "invalid_llm_token", path);
            return;
        }

        // Agent ingest credentials stay machine-bound even when an operator has
        // an interactive dashboard cookie in the same browser/process.
        if (security.RequireAuth && IsAgentPath(path))
        {
            var agentKey = GetApiKey(ctx);
            var agentId = string.IsNullOrWhiteSpace(agentKey)
                ? null
                : await store.FindAgentIdByApiKeyHashAsync(SecretBootstrapper.HashApiKey(agentKey));
            if (!string.IsNullOrWhiteSpace(agentId))
            {
                ctx.Items[PrincipalItem] = "agent";
                ctx.Items[AgentIdItem] = agentId;
                await _next(ctx);
                return;
            }

            await FailAsync(ctx, auditQueue,
                string.IsNullOrWhiteSpace(agentKey) ? "missing_agent_api_key" : "invalid_agent_api_key",
                path);
            return;
        }

        var dashboardRoles = ctx.User.FindAll(ClaimTypes.Role)
            .Select(claim => claim.Value)
            .Where(DashboardRoles.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (ctx.User.Identity?.IsAuthenticated == true && dashboardRoles.Length > 0)
        {
            var canMutate = dashboardRoles.Contains(DashboardRoles.SocOperator, StringComparer.OrdinalIgnoreCase) ||
                            dashboardRoles.Contains(DashboardRoles.SocAdmin, StringComparer.OrdinalIgnoreCase);
            // Every authenticated dashboard role must be able to revoke its own
            // cookie session. CSRF validation still applies to this POST; the
            // exception only bypasses the SOC mutation-role gate.
            if (!canMutate && IsUnsafeMethod(ctx.Request.Method) && !IsDashboardLogout(ctx))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new { error = "operator_role_read_only" });
                return;
            }

            var subject = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                          ctx.User.FindFirstValue("sub") ??
                          "operator";
            ctx.Items[PrincipalItem] = $"user:{subject}";
            ctx.Items["NTShieldRoles"] = dashboardRoles;
            ctx.Items["NTShieldTenantClaims"] = ctx.User.FindAll(DashboardSessionEndpoints.TenantClaim)
                .Select(claim => claim.Value).ToArray();
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
            await FailAsync(ctx, auditQueue, "missing_api_key", path);
            return;
        }

        if (!string.IsNullOrEmpty(security.OperatorApiKey) &&
            FixedTimeEquals(key, security.OperatorApiKey))
        {
            ctx.Items[PrincipalItem] = "operator";
            await _next(ctx);
            return;
        }

        // Operator-only paths reject agent keys
        await FailAsync(ctx, auditQueue, "invalid_api_key", path);
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

    private async Task FailAsync(HttpContext ctx, SecurityAuditQueue auditQueue, string reason, string path)
    {
        _logger.LogWarning("Auth failed path={Path} reason={Reason} ip={Ip}",
            path, reason, ctx.Connection.RemoteIpAddress);
        auditQueue.TryEnqueue(new SecurityAuditEvent(
            Actor: "anonymous",
            Action: "auth.fail",
            Target: path,
            Result: "fail",
            DetailJson: JsonSerializer.Serialize(new { reason }),
            SourceIp: ctx.Connection.RemoteIpAddress?.ToString()));

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

    private static string? GetLlmToken(HttpContext ctx)
    {
        if (ctx.Request.Headers.TryGetValue("X-NTShield-LLM-Token", out var explicitToken) &&
            !string.IsNullOrWhiteSpace(explicitToken))
            return explicitToken.ToString().Trim();

        var auth = ctx.Request.Headers.Authorization.ToString();
        return auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth["Bearer ".Length..].Trim()
            : null;
    }

    private static bool IsPublic(string path) =>
        path.Equals("/health", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v2/readiness", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v2/session", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v2/session/exchange", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v2/session/local", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/v2/session/login", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/signin-oidc", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/signout-callback-oidc", StringComparison.OrdinalIgnoreCase);

    private static bool IsAgentPath(string path) =>
        path.StartsWith("/api/v1/agents/heartbeat", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/heartbeat", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/ingest", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/events/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/v1/connections/", StringComparison.OrdinalIgnoreCase);

    private static bool IsLlmProxyPath(string path) =>
        path.StartsWith("/api/v1/llm/v1/", StringComparison.OrdinalIgnoreCase);

    private static bool IsUnsafeMethod(string method) =>
        HttpMethods.IsPost(method) ||
        HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method) ||
        HttpMethods.IsDelete(method);

    private static bool IsDashboardLogout(HttpContext context) =>
        HttpMethods.IsPost(context.Request.Method) &&
        context.Request.Path.Equals("/api/v2/session/logout", StringComparison.OrdinalIgnoreCase);

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
