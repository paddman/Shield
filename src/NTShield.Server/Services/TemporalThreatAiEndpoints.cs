using System.Text.Json;
using NTShield.Server.AI;
using NTShield.Server.Data;
using NTShield.Server.Security;

namespace NTShield.Server.Services;

public static class TemporalThreatAiEndpoints
{
    /// <summary>
    /// Explains a bounded temporal-chain snapshot. Only normalized facts and
    /// citation identifiers cross the Brain boundary; packet/raw payloads and
    /// opaque provider references are not part of this contract.
    /// </summary>
    public static IEndpointRouteBuilder MapTemporalThreatAiEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v2/threats/{campaignId}/ai/explain", async (
            string campaignId,
            HttpContext http,
            ICentralStore store,
            AiAnalystProxyService analyst,
            SecurityAuditQueue audits) =>
        {
            var tenantId = TopologyService.ResolveTenantId(http);
            var summary = await store.GetThreatCampaignV2SummaryAsync(
                tenantId, campaignId, http.RequestAborted);
            if (summary is null)
                return Results.NotFound(new { error = "threat_campaign_not_found" });

            var watermark = DateTimeOffset.UtcNow;
            var observationsTask = store.ListThreatObservationsAsync(
                tenantId, campaignId, watermark, null, null, null, null, 100, http.RequestAborted);
            var contactsTask = store.ListThreatContactsAsync(
                tenantId, campaignId, watermark, null, null, null, null, 50, http.RequestAborted);
            var observationCountTask = store.CountThreatObservationsAsync(
                tenantId, campaignId, watermark, null, null, http.RequestAborted);
            var contactCountTask = store.CountThreatContactsAsync(
                tenantId, campaignId, watermark, null, null, http.RequestAborted);
            await Task.WhenAll(observationsTask, contactsTask, observationCountTask, contactCountTask);

            try
            {
                var json = await analyst.AnalyzeThreatChainAsync(
                    summary,
                    observationsTask.Result,
                    contactsTask.Result,
                    observationCountTask.Result,
                    contactCountTask.Result,
                    tenantId,
                    http.RequestAborted);
                Audit(audits, http, tenantId, campaignId, "success", null);
                return Results.Content(json, "application/json", System.Text.Encoding.UTF8);
            }
            catch (AiAnalystProxyException ex)
            {
                Audit(audits, http, tenantId, campaignId, "fail", ex.Error);
                return Results.Json(new { error = ex.Error }, statusCode: ex.StatusCode);
            }
        });
        return endpoints;
    }

    private static void Audit(
        SecurityAuditQueue queue,
        HttpContext http,
        string tenantId,
        string campaignId,
        string result,
        string? error)
    {
        var actor = http.Items.TryGetValue(ApiKeyAuthMiddleware.PrincipalItem, out var value)
            ? value?.ToString() ?? "operator"
            : "operator";
        queue.TryEnqueue(new SecurityAuditEvent(
            actor,
            "ai.threat_chain.explain",
            campaignId,
            result,
            JsonSerializer.Serialize(new
            {
                tenantId,
                evidencePolicy = "structured_references_only",
                error
            }),
            http.Connection.RemoteIpAddress?.ToString()));
    }
}
