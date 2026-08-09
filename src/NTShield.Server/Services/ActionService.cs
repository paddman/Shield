using NTShield.Server.Data;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

/// <summary>
/// Durable pending-actions queue for agents (approval workflow). Survives Central restart.
/// </summary>
public sealed class ActionService
{
    private readonly ICentralStore _store;
    private readonly ILogger<ActionService> _logger;

    public ActionService(ICentralStore store, ILogger<ActionService> logger)
    {
        _store = store;
        _logger = logger;
    }

    private async Task<ResponseActionRequest> EnqueueAsync(ResponseActionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RequestId))
        {
            request.RequestId = Guid.NewGuid().ToString("N");
        }

        if (!request.Approved && NeedsApproval(request.ActionType))
        {
            _logger.LogWarning("Action {Id} type {Type} enqueued without approval flag", request.RequestId, request.ActionType);
        }

        var agentId = request.TargetAgentId!;

        await _store.SavePendingActionAsync(request, agentId);

        _logger.LogWarning(
            "Enqueued action {Type} for agent={Agent} approved={Approved} ip={Ip} port={Port} id={Id}",
            request.ActionType, agentId, request.Approved, request.TargetIp, request.TargetPort, request.RequestId);

        return request;
    }

    /// <summary>
    /// Queues a dashboard response for one agent in the selected tenant. Request
    /// identifiers are server generated so another tenant cannot overwrite a
    /// pending row by supplying a colliding id.
    /// </summary>
    public async Task<ResponseActionRequest?> EnqueueForTenantAsync(
        ResponseActionRequest request,
        string tenantId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var agentId = request.TargetAgentId?.Trim();
        if (string.IsNullOrWhiteSpace(agentId)) return null;
        if (await _store.GetAgentAsync(agentId, 1, tenantId) is null) return null;

        request.RequestId = Guid.NewGuid().ToString("N");
        request.TargetAgentId = agentId;
        request.TenantId = tenantId;
        return await EnqueueAsync(request);
    }

    public Task<ResponseActionRequest?> GetAsync(string id) =>
        _store.GetPendingActionAsync(id);

    public async Task<ResponseActionRequest?> GetForTenantAsync(string id, string tenantId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var action = await _store.GetPendingActionAsync(id);
        if (action is null) return null;
        // Ownership cannot be proven for pre-migration rows. Fail closed rather
        // than exposing an old tenant's response details after reassignment.
        if (string.IsNullOrWhiteSpace(action.TenantId)) return null;
        return string.Equals(action.TenantId, tenantId, StringComparison.OrdinalIgnoreCase)
            ? action
            : null;
    }

    public async Task<List<ResponseActionRequest>> GetPendingForAgentAsync(string agentId)
    {
        var pending = await _store.TakePendingActionsAsync(agentId);
        var assignment = (await _store.ListAgentAssignmentsAsync())
            .FirstOrDefault(item => string.Equals(item.AgentId, agentId, StringComparison.OrdinalIgnoreCase));
        var tenantId = assignment is null
            ? "default"
            : TopologyService.NormalizeTenantId(assignment.TenantId);

        // Tenant-less rows predate durable ownership and cannot be safely
        // attributed after reassignment. They are consumed but quarantined from
        // execution; new rows must match the current server-side assignment.
        var accepted = pending.Where(item =>
                !string.IsNullOrWhiteSpace(item.TenantId) &&
                string.Equals(item.TenantId, tenantId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (accepted.Count != pending.Count)
            _logger.LogWarning(
                "Discarded {Count} pending action(s) with missing or stale tenant ownership for agent={Agent}",
                pending.Count - accepted.Count,
                agentId);
        return accepted;
    }

    private static bool NeedsApproval(string actionType) =>
        actionType is not ("LogOnly" or "ExportEvidence");
}
