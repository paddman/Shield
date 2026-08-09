using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using NTShield.Server.Security;
using NTShield.Server.Services;

namespace NTShield.Server.Capture;

public static class CaptureAuthorizationPolicies
{
    public const string PacketAccess = "SocPacketAccess";
    public const string Administration = "SocAdmin";
}

public static class CaptureEndpointExtensions
{
    public static RouteGroupBuilder MapCaptureControlPlane(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api/v2")
            .WithTags("Capture Control")
            .AddEndpointFilter<CaptureEnabledEndpointFilter>()
            .AddEndpointFilter<CaptureExceptionEndpointFilter>();

        var policies = api.MapGroup("/capture-policies");
        api.MapGet("/capture-policies", async (
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.ListAsync(TopologyService.ResolveTenantId(http), cancellationToken)));

        policies.MapGet("/{id}", async (
            string id,
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var item = await service.GetAsync(TopologyService.ResolveTenantId(http), id, cancellationToken);
            return item is null ? Results.NotFound() : Results.Ok(item);
        });

        policies.MapPost("/simulate", async (
            CapturePolicySimulationRequest request,
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.SimulateAsync(
                TopologyService.ResolveTenantId(http), request.Policy, cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.Administration);

        api.MapPost("/capture-policies", async (
            CapturePolicy policy,
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var saved = await service.CreateAsync(
                TopologyService.ResolveTenantId(http), policy, Actor(http), cancellationToken);
            return Results.Created($"/api/v2/capture-policies/{Uri.EscapeDataString(saved.PolicyId)}", saved);
        }).RequireAuthorization(CaptureAuthorizationPolicies.Administration);

        policies.MapPut("/{id}", async (
            string id,
            CapturePolicy policy,
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var saved = await service.UpdateAsync(
                TopologyService.ResolveTenantId(http),
                id,
                policy,
                ResolveExpectedVersion(http, policy.Version),
                Actor(http),
                cancellationToken);
            return Results.Ok(saved);
        }).RequireAuthorization(CaptureAuthorizationPolicies.Administration);

        policies.MapDelete("/{id}", async (
            string id,
            int? version,
            CapturePolicyService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var deleted = await service.DeleteAsync(
                TopologyService.ResolveTenantId(http),
                id,
                ResolveExpectedVersion(http, version ?? 0),
                Actor(http),
                cancellationToken);
            return deleted ? Results.NoContent() : Results.NotFound();
        }).RequireAuthorization(CaptureAuthorizationPolicies.Administration);

        var sessions = api.MapGroup("/packet-sessions");
        api.MapGet("/packet-sessions", async (
            [AsParameters] CaptureSessionQuery query,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.QueryAsync(TopologyService.ResolveTenantId(http), query, cancellationToken)));

        sessions.MapGet("/{id}", async (
            string id,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var item = await service.GetAsync(TopologyService.ResolveTenantId(http), id, cancellationToken);
            return item is null ? Results.NotFound() : Results.Ok(item);
        });

        sessions.MapPost("/{id}/access", async (
            string id,
            PacketAccessRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.CreateSessionAccessAsync(
                TopologyService.ResolveTenantId(http), id, request, Actor(http), cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);

        sessions.MapPost("/{id}/tls-artifact/access", async (
            string id,
            PacketAccessRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.CreateTlsArtifactAccessAsync(
                TopologyService.ResolveTenantId(http), id, request, Actor(http), cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);

        sessions.MapPost("/{id}/tls-preview", async (
            string id,
            PacketAccessRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.GetTlsPreviewAsync(
                TopologyService.ResolveTenantId(http), id, request, Actor(http), cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);

        sessions.MapPost("/{id}/exports", async (
            string id,
            CreateSessionExportRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var job = await service.CreateExportAsync(
                TopologyService.ResolveTenantId(http),
                new CreateCaptureExportRequest
                {
                    SessionIds = [id],
                    Format = request.Format,
                    Purpose = request.Purpose,
                    RetentionHours = request.RetentionHours
                },
                Actor(http),
                cancellationToken);
            return Results.Accepted($"/api/v2/packet-exports/{Uri.EscapeDataString(job.JobId)}", job);
        }).RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);

        var exports = api.MapGroup("/packet-exports")
            .RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);
        api.MapGet("/packet-exports", async (
            int? take,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.ListExportsAsync(
                TopologyService.ResolveTenantId(http), take is null or <= 0 ? 50 : take.Value, cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);
        api.MapPost("/packet-exports", async (
            CreateCaptureExportRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var job = await service.CreateExportAsync(
                TopologyService.ResolveTenantId(http), request, Actor(http), cancellationToken);
            return Results.Accepted($"/api/v2/packet-exports/{Uri.EscapeDataString(job.JobId)}", job);
        }).RequireAuthorization(CaptureAuthorizationPolicies.PacketAccess);
        exports.MapGet("/{id}", async (
            string id,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
        {
            var job = await service.GetExportAsync(TopologyService.ResolveTenantId(http), id, cancellationToken);
            return job is null ? Results.NotFound() : Results.Ok(job);
        });
        exports.MapPost("/{id}/access", async (
            string id,
            PacketAccessRequest request,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.CreateExportAccessAsync(
                TopologyService.ResolveTenantId(http), id, request, Actor(http), cancellationToken)));

        api.MapGet("/capture-health", async (
            CaptureHealthService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.GetSummaryAsync(TopologyService.ResolveTenantId(http), cancellationToken)));
        api.MapGet("/capture-health/visibility-gaps", async (
            bool? openOnly,
            int? take,
            CaptureHealthService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.ListGapsAsync(
                TopologyService.ResolveTenantId(http), openOnly ?? true,
                take is null or <= 0 ? 100 : take.Value, cancellationToken)));
        api.MapGet("/capture-audit", async (
            int? take,
            CaptureSessionService service,
            HttpContext http,
            CancellationToken cancellationToken) =>
            Results.Ok(await service.ListAuditAsync(
                TopologyService.ResolveTenantId(http), take is null or <= 0 ? 100 : take.Value, cancellationToken)))
            .RequireAuthorization(CaptureAuthorizationPolicies.Administration);

        return api;
    }

    private static CaptureActorContext Actor(HttpContext http)
    {
        var actor = http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var principal)
            ? principal?.ToString()
            : null;
        actor ??= http.User.Identity?.Name;
        return new CaptureActorContext(
            string.IsNullOrWhiteSpace(actor) ? "anonymous" : actor,
            http.Connection.RemoteIpAddress?.ToString());
    }

    private static int ResolveExpectedVersion(HttpContext http, int bodyVersion)
    {
        var raw = http.Request.Headers.IfMatch.FirstOrDefault()?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            if (bodyVersion < 1) throw new CaptureValidationException("If-Match or a positive version is required.");
            return bodyVersion;
        }
        if (raw.StartsWith("W/", StringComparison.OrdinalIgnoreCase)) raw = raw[2..];
        raw = raw.Trim().Trim('"');
        if (!int.TryParse(raw, out var parsed) || parsed < 1)
            throw new CaptureValidationException("If-Match must contain a positive capture policy version.");
        return parsed;
    }
}

public sealed class CaptureEnabledEndpointFilter : IEndpointFilter
{
    private readonly IOptions<CaptureControlOptions> _options;

    public CaptureEnabledEndpointFilter(IOptions<CaptureControlOptions> options) => _options = options;

    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next) =>
        _options.Value.Enabled
            ? next(context)
            : ValueTask.FromResult<object?>(Results.Json(
                new { error = "capture_control_disabled" },
                statusCode: StatusCodes.Status503ServiceUnavailable));
}

public sealed class CaptureExceptionEndpointFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (CaptureValidationException ex)
        {
            return Results.BadRequest(new { error = "capture_validation_error", detail = ex.Message });
        }
        catch (CaptureVersionConflictException ex)
        {
            return Results.Conflict(new
            {
                error = "capture_policy_version_conflict",
                detail = ex.Message,
                currentVersion = ex.CurrentVersion
            });
        }
        catch (CaptureCapacityRejectedException ex)
        {
            return Results.Json(new
            {
                error = "capture_capacity_rejected",
                detail = ex.Message,
                admission = ex.Result
            }, statusCode: StatusCodes.Status422UnprocessableEntity);
        }
        catch (CaptureProviderUnavailableException ex)
        {
            return Results.Json(new { error = "capture_provider_unavailable", detail = ex.Message },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        catch (CaptureAuditUnavailableException ex)
        {
            return Results.Json(new { error = "capture_audit_unavailable", detail = ex.Message },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        catch (KeyNotFoundException ex)
        {
            return Results.NotFound(new { error = "capture_resource_not_found", detail = ex.Message });
        }
    }
}
