using NTShield.Shared.Contracts;

namespace NTShield.Server.Services;

public static class IngestHttpResponseMapper
{
    private const int BusyRetryAfterSeconds = 2;

    public static IResult ToHttpResult(IngestResponse result, HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(response);

        // An active idempotency lease means another request owns this exact
        // tenant/agent/key. A non-2xx status is required because lightweight
        // agents use the HTTP status to decide whether to restore their buffer.
        if (!result.Accepted && result.Duplicate)
        {
            response.Headers.RetryAfter = BusyRetryAfterSeconds.ToString();
            return Results.Json(result, statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Ok(result);
    }
}
