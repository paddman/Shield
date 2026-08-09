using System.Security.Cryptography;
using System.Text;

namespace NTShield.Server.Security;

public sealed class DashboardCsrfMiddleware
{
    private readonly RequestDelegate _next;

    public DashboardCsrfMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!RequiresValidation(context))
        {
            await _next(context);
            return;
        }

        var cookie = context.Request.Cookies[DashboardSessionEndpoints.CsrfCookie];
        var header = context.Request.Headers[DashboardSessionEndpoints.CsrfHeader].ToString();
        if (!FixedTimeEquals(cookie, header))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "csrf_validation_failed" });
            return;
        }

        await _next(context);
    }

    private static bool RequiresValidation(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true) return false;
        if (HttpMethods.IsGet(context.Request.Method) ||
            HttpMethods.IsHead(context.Request.Method) ||
            HttpMethods.IsOptions(context.Request.Method)) return false;
        var path = context.Request.Path.Value ?? string.Empty;
        return !path.Equals("/api/v2/session/exchange", StringComparison.OrdinalIgnoreCase) &&
               !path.Equals("/api/v2/session/local", StringComparison.OrdinalIgnoreCase);
    }

    private static bool FixedTimeEquals(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }
}
