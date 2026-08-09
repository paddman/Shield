using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Security;

public sealed record LegacySessionExchangeRequest(string? ApiKey);
public sealed record LocalSessionLoginRequest(string? Username, string? Password, string? Totp);

public static class DashboardSessionEndpoints
{
    public const string CookieScheme = "NTShieldDashboardCookie";
    public const string OidcScheme = "NTShieldDashboardOidc";
    public const string AuthTypeClaim = "ntshield_auth_type";
    public const string TenantClaim = "ntshield_tenant";
    public const string CsrfCookie = "__Host-NTShield.Csrf";
    public const string CsrfHeader = "X-NTShield-CSRF";

    public static IEndpointRouteBuilder MapDashboardSessionEndpoints(
        this IEndpointRouteBuilder endpoints,
        string serverVersion)
    {
        endpoints.MapGet("/api/v2/session", (
            HttpContext http,
            IOptions<SecurityOptions> security,
            IOptions<DashboardAuthOptions> dashboard) =>
        {
            var token = EnsureCsrfToken(http);
            return Results.Ok(BuildSessionResponse(http, security.Value, dashboard.Value, serverVersion, token));
        });

        endpoints.MapPost("/api/v2/session/exchange", async (
            LegacySessionExchangeRequest? request,
            HttpContext http,
            IOptions<SecurityOptions> security,
            IOptions<DashboardAuthOptions> dashboard,
            DashboardLoginAttemptLimiter limiter,
            SecurityAuditQueue audits) =>
        {
            var key = AttemptKey(http, "legacy");
            var now = DateTimeOffset.UtcNow;
            if (!limiter.IsAllowed(key, now, out var retryAfter))
            {
                http.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                return Results.Json(new { error = "login_rate_limited" }, statusCode: StatusCodes.Status429TooManyRequests);
            }

            var opts = dashboard.Value;
            var valid = opts.LegacyKeyExchangeEnabled &&
                        !string.IsNullOrWhiteSpace(security.Value.OperatorApiKey) &&
                        !string.IsNullOrWhiteSpace(request?.ApiKey) &&
                        FixedTimeEquals(request.ApiKey, security.Value.OperatorApiKey);
            if (!valid)
            {
                limiter.RecordFailure(key, now);
                Audit(audits, http, "session.exchange", "fail", "invalid_legacy_key");
                return Results.Json(new { error = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            limiter.RecordSuccess(key);
            await SignInAsync(
                http,
                id: "legacy-operator",
                displayName: "Legacy SOC operator",
                authType: "legacy-key",
                roles: [DashboardRoles.SocAdmin],
                tenants: ["*"],
                opts.SessionHours);
            Audit(audits, http, "session.exchange", "success", null, "legacy-operator");
            var csrf = RotateCsrfToken(http);
            return Results.Ok(BuildSessionResponse(http, security.Value, opts, serverVersion, csrf));
        });

        endpoints.MapPost("/api/v2/session/local", async (
            LocalSessionLoginRequest? request,
            HttpContext http,
            IOptions<SecurityOptions> security,
            IOptions<DashboardAuthOptions> dashboard,
            LocalDashboardCredentialValidator validator,
            DashboardLoginAttemptLimiter limiter,
            SecurityAuditQueue audits) =>
        {
            var username = request?.Username?.Trim() ?? string.Empty;
            // Limit by source rather than attacker-controlled usernames so a
            // username spray cannot create an unbounded limiter dictionary.
            var key = AttemptKey(http, "local");
            var now = DateTimeOffset.UtcNow;
            if (!limiter.IsAllowed(key, now, out var retryAfter))
            {
                http.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                return Results.Json(new { error = "login_rate_limited" }, statusCode: StatusCodes.Status429TooManyRequests);
            }

            if (!validator.Validate(username, request?.Password, request?.Totp, now))
            {
                limiter.RecordFailure(key, now);
                Audit(audits, http, "session.local", "fail", "invalid_credentials");
                return Results.Json(new { error = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            limiter.RecordSuccess(key);
            var local = dashboard.Value.Local;
            await SignInAsync(
                http,
                id: $"local:{local.Username}",
                displayName: local.DisplayName,
                authType: "local-mfa",
                roles: [DashboardRoles.SocAdmin],
                tenants: local.TenantIds.Count == 0 ? ["*"] : local.TenantIds,
                dashboard.Value.SessionHours);
            Audit(audits, http, "session.local", "success", null, $"local:{local.Username}");
            var csrf = RotateCsrfToken(http);
            return Results.Ok(BuildSessionResponse(http, security.Value, dashboard.Value, serverVersion, csrf));
        });

        endpoints.MapGet("/api/v2/session/login", (
            string? returnUrl,
            HttpContext http,
            IOptions<DashboardAuthOptions> dashboard) =>
        {
            if (!dashboard.Value.Oidc.Enabled)
                return Results.NotFound(new { error = "oidc_not_configured" });
            var target = SafeReturnUrl(returnUrl);
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = target },
                [OidcScheme]);
        });

        endpoints.MapPost("/api/v2/session/logout", async (
            HttpContext http,
            IOptions<DashboardAuthOptions> dashboard,
            SecurityAuditQueue audits) =>
        {
            var actor = http.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous";
            await http.SignOutAsync(CookieScheme);
            http.Response.Cookies.Delete(CsrfCookie, new CookieOptions
            {
                Path = "/",
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
            Audit(audits, http, "session.logout", "success", null, actor);
            return Results.Ok(new { signedOut = true, oidc = dashboard.Value.Oidc.Enabled });
        });

        return endpoints;
    }

    public static object BuildSessionResponse(
        HttpContext http,
        SecurityOptions security,
        DashboardAuthOptions dashboard,
        string version,
        string csrfToken)
    {
        var authenticated = http.User.Identity?.IsAuthenticated == true;
        var softLab = !security.RequireAuth && !authenticated;
        var roles = authenticated
            ? http.User.FindAll(ClaimTypes.Role)
                .Select(claim => claim.Value)
                .Where(DashboardRoles.IsKnown)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
            : softLab ? [DashboardRoles.SocAdmin] : Array.Empty<string>();

        var tenants = authenticated
            ? http.User.FindAll(TenantClaim).Select(claim => claim.Value).Where(value => value.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            : softLab ? ["*"] : Array.Empty<string>();
        var actorId = authenticated
            ? http.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? http.User.FindFirstValue("sub") ?? "operator"
            : softLab ? "anonymous-lab" : "anonymous";
        var displayName = authenticated
            ? http.User.Identity?.Name ?? actorId
            : softLab ? "Lab operator" : "Anonymous";
        var authType = authenticated
            ? http.User.FindFirstValue(AuthTypeClaim) ?? "oidc"
            : softLab ? "soft-auth" : "none";

        return new
        {
            authenticated = authenticated || softLab,
            actor = new { id = actorId, displayName, authType },
            roles,
            capabilities = DashboardCapabilities.ForRoles(roles),
            tenantIds = tenants,
            requireAuth = security.RequireAuth,
            authModes = new
            {
                legacyKey = dashboard.LegacyKeyExchangeEnabled,
                oidc = dashboard.Oidc.Enabled,
                local = dashboard.Local.Enabled
            },
            csrfToken,
            serverUtc = DateTimeOffset.UtcNow,
            version
        };
    }

    private static async Task SignInAsync(
        HttpContext http,
        string id,
        string displayName,
        string authType,
        IReadOnlyCollection<string> roles,
        IReadOnlyCollection<string> tenants,
        int sessionHours)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, id),
            new(ClaimTypes.Name, displayName),
            new(AuthTypeClaim, authType)
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        claims.AddRange(tenants.Select(tenant => new Claim(TenantClaim, tenant)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieScheme));
        await http.SignInAsync(CookieScheme, principal, new AuthenticationProperties
        {
            AllowRefresh = true,
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(Math.Clamp(sessionHours, 1, 24))
        });
        // SignInAsync emits the ticket but does not guarantee that the current
        // request's User is replaced. The exchange/local response is built in
        // this same request and must describe the principal just issued.
        http.User = principal;
    }

    public static string EnsureCsrfToken(HttpContext http)
    {
        if (http.Request.Cookies.TryGetValue(CsrfCookie, out var existing) && IsValidToken(existing))
            return existing;
        return RotateCsrfToken(http);
    }

    public static string RotateCsrfToken(HttpContext http)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        http.Response.Cookies.Append(CsrfCookie, token, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            IsEssential = true,
            MaxAge = TimeSpan.FromHours(8)
        });
        return token;
    }

    private static bool IsValidToken(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static string SafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
            return "/";
        return returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal)
            ? returnUrl
            : "/";
    }

    private static string AttemptKey(HttpContext http, string kind) =>
        $"{http.Connection.RemoteIpAddress?.ToString() ?? "unknown"}|{kind}";

    private static bool FixedTimeEquals(string left, string right)
    {
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static void Audit(
        SecurityAuditQueue queue,
        HttpContext http,
        string action,
        string result,
        string? reason,
        string actor = "anonymous")
    {
        queue.TryEnqueue(new SecurityAuditEvent(
            actor,
            action,
            null,
            result,
            reason is null ? null : JsonSerializer.Serialize(new { reason }),
            http.Connection.RemoteIpAddress?.ToString()));
    }
}
