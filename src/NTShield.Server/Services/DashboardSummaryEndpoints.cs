namespace NTShield.Server.Services;

public static class DashboardSummaryEndpoints
{
    public static IEndpointRouteBuilder MapDashboardSummaryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v2/dashboard/summary", async (
            string? window,
            DashboardSummaryService summaries,
            HttpContext http) =>
        {
            http.Response.Headers.CacheControl = "private, no-store";
            var tenantId = TopologyService.ResolveTenantId(http);
            return Results.Ok(await summaries.GetAsync(
                tenantId,
                string.IsNullOrWhiteSpace(window) ? "24h" : window,
                http.RequestAborted));
        });
        return endpoints;
    }
}
