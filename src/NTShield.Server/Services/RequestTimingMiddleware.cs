using System.Diagnostics;
using System.Globalization;

namespace NTShield.Server.Services;

public sealed class RequestTimingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestTimingMiddleware> _logger;

    public RequestTimingMiddleware(RequestDelegate next, ILogger<RequestTimingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var started = Stopwatch.GetTimestamp();
        context.Response.OnStarting(() =>
        {
            var duration = Stopwatch.GetElapsedTime(started);
            context.Response.Headers["Server-Timing"] =
                $"app;dur={duration.TotalMilliseconds.ToString("0.0", CultureInfo.InvariantCulture)}";
            return Task.CompletedTask;
        });
        await _next(context);
        var elapsed = Stopwatch.GetElapsedTime(started);
        if (elapsed >= TimeSpan.FromSeconds(2) && context.Request.Path.StartsWithSegments("/api"))
        {
            _logger.LogWarning(
                "Slow API request method={Method} path={Path} status={Status} elapsedMs={ElapsedMs} responseLength={Length}",
                context.Request.Method,
                context.Request.Path,
                context.Response.StatusCode,
                elapsed.TotalMilliseconds,
                context.Response.ContentLength);
        }
    }
}
