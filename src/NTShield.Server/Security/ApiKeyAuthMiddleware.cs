using System.Text.Json;
using NTShield.Server.Data;
using NTShield.Server.LLM;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Security;

/// <summary>
/// Enforces least-privilege API authentication. Operator APIs always require the
/// operator key. Agent keys are accepted only on telemetry/heartbeat paths.
/// RequireAuth=false is a narrow legacy ingest switch, never an open Control Center.
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
        LlmGatewayService llmGateway)
    {
        var security = securityOpt.Value;
        var path = ctx.Request.Path.Value ?? "";

        if (IsPublic(path))
        {
            ctx.Items[PrincipalItem] = "anonymous";
            await _next(ctx);
            return;
        }

        // First registration is authenticated by the body EnrollmentToken in the
        // endpoint handler. SecretBootstrapper generates that token by default.
        if (path.StartsWith("/api/v1/agents/register", StringComparison.OrdinalIgnoreCase) &&
            HttpMethods.IsPost(ctx.Request.Method))
        {
            ctx.Items[PrincipalItem] = "enroll";
            await _next(ctx);
            return;
        }

        // LLM proxy tokens are separate from operator and agent keys and are
        // required even if Central is placed in explicit legacy ingest mode.
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

            await FailAsync(ctx, store, "invalid_llm_token", path);
            return;
        }

        var key = GetApiKey(ctx);
        var principal = await AuthenticateApiKeyAsync(key, security, store);
        if (principal is not null)
        {
            ctx.Items[PrincipalItem] = principal.Value.Principal;
            if (!string.IsNullOrWhiteSpace(principal.Value.AgentId))
                ctx.Items[AgentIdItem] = principal.Value.AgentId;
        }

        if (security.RequireAuth)
        {
            if (principal?.Principal == "operator")
            {
                await _next(ctx);
                return;
            }

            if (principal?.Principal == "agent" && IsAgentPath(path))
            {
                await _next(ctx);
                return;
            }

            var reason = string.IsNullOrWhiteSpace(key)
                ? "missing_api_key"
                : principal?.Principal == "agent"
                    ? "agent_scope_violation"
                    : "invalid_api_key";
            await FailAsync(ctx, store, reason, path);
            return;
        }

        // Explicit compatibility mode. Operator APIs remain protected. Anonymous
        // telemetry is accepted only when the separate dangerous switch is true
        // and the request did not present a bad key.
        if (principal?.Principal == "operator")
        {
            await _next(ctx);
            return;
        }

        if (IsAgentPath(path))
        {
            if (principal?.Principal == "agent")
            {
                await _next(ctx);
                return;
            }

            if (security.AllowLegacyAnonymousAgentIngest && string.IsNullOrWhiteSpace(key))
            {
                ctx.Items[PrincipalItem] = "legacy-anonymous-agent";
                _logger.LogWarning(
                    "Legacy anonymous agent ingest accepted path={Path} ip={Ip}",
                    path,
                    ctx.Connection.RemoteIpAddress);
                await _next(ctx);
                return;
            }

            await FailAsync(
                ctx,
                store,
                string.IsNullOrWhiteSpace(key)
                    ? "agent_key_required"
                    : "invalid_agent_key",
                path);
            return;
        }

        await FailAsync(ctx, store, "operator_key_required", path);
    }

    private static async Task<(string Principal, string? AgentId)?> AuthenticateApiKeyAsync(
        string? key,
        SecurityOptions security,
        ICentralStore store)
    {
        if (string.IsNullOrWhiteSpace(key))
            return null;

        if (!string.IsNullOrWhiteSpace(security.OperatorApiKey) &&
            FixedTimeEquals(key, security.OperatorApiKey))
        {
            return ("operator", null);
        }

        var agentId = await store.FindAgentIdByApiKeyHashAsync(
            SecretBootstrapper.HashApiKey(key));
        return string.IsNullOrWhiteSpace(agentId)
            ? null
            : ("agent", agentId);
    }

    private async Task FailAsync(HttpContext ctx, ICentralStore store, string reason, string path)
    {
        _logger.LogWarning(
            "Auth failed path={Path} reason={Reason} ip={Ip}",
            path,
            reason,
            ctx.Connection.RemoteIpAddress);
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
            // Authentication must fail even if audit persistence is unavailable.
        }

        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(
            JsonSerializer.Serialize(new { error = "unauthorized", reason }));
    }

    private static string? GetApiKey(HttpContext ctx)
    {
        if (ctx.Request.Headers.TryGetValue(SecurityOptions.ApiKeyHeader, out var header) &&
            !string.IsNullOrWhiteSpace(header))
        {
            return header.ToString().Trim();
        }

        var authorization = ctx.Request.Headers.Authorization.ToString();
        return authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization["Bearer ".Length..].Trim()
            : null;
    }

    private static string? GetLlmToken(HttpContext ctx)
    {
        if (ctx.Request.Headers.TryGetValue("X-NTShield-LLM-Token", out var explicitToken) &&
            !string.IsNullOrWhiteSpace(explicitToken))
        {
            return explicitToken.ToString().Trim();
        }

        var authorization = ctx.Request.Headers.Authorization.ToString();
        return authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization["Bearer ".Length..].Trim()
            : null;
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

    private static bool IsLlmProxyPath(string path) =>
        path.StartsWith("/api/v1/llm/v1/", StringComparison.OrdinalIgnoreCase);

    private static bool FixedTimeEquals(string left, string right)
    {
        var a = System.Text.Encoding.UTF8.GetBytes(left);
        var b = System.Text.Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
    }
}
