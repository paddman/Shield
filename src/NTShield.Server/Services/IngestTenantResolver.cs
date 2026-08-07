using NTShield.Server.Data;
using NTShield.Server.Security;

namespace NTShield.Server.Services;

/// <summary>
/// Resolves an agent ingest to its Central assignment. Browser-provided tenant
/// headers are deliberately not used for agent telemetry ownership.
/// </summary>
public sealed class IngestTenantResolver
{
    private readonly ICentralStore _store;

    public IngestTenantResolver(ICentralStore store)
    {
        _store = store;
    }

    public async Task<string> ResolveAsync(HttpContext context, string agentId)
    {
        var boundAgentId = context.Items.TryGetValue(ApiKeyAuthMiddleware.AgentIdItem, out var bound)
            ? bound as string
            : null;
        var effectiveAgentId = string.IsNullOrWhiteSpace(boundAgentId) ? agentId : boundAgentId;
        if (string.IsNullOrWhiteSpace(effectiveAgentId)) return "default";

        var assignment = (await _store.ListAgentAssignmentsAsync())
            .FirstOrDefault(item => string.Equals(item.AgentId, effectiveAgentId, StringComparison.OrdinalIgnoreCase));
        return assignment is null
            ? "default"
            : TopologyService.NormalizeTenantId(assignment.TenantId);
    }
}
