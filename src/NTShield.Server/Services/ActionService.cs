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

    public async Task<ResponseActionRequest> EnqueueAsync(ResponseActionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RequestId))
        {
            request.RequestId = Guid.NewGuid().ToString("N");
        }

        if (!request.Approved && NeedsApproval(request.ActionType))
        {
            _logger.LogWarning("Action {Id} type {Type} enqueued without approval flag", request.RequestId, request.ActionType);
        }

        var agentId = !string.IsNullOrWhiteSpace(request.TargetAgentId)
            ? request.TargetAgentId!
            : request.Requester.StartsWith("agent:", StringComparison.OrdinalIgnoreCase)
                ? request.Requester["agent:".Length..]
                : "broadcast";

        await _store.SavePendingActionAsync(request, agentId);

        _logger.LogWarning(
            "Enqueued action {Type} for agent={Agent} approved={Approved} ip={Ip} port={Port} id={Id}",
            request.ActionType, agentId, request.Approved, request.TargetIp, request.TargetPort, request.RequestId);

        return request;
    }

    public Task<ResponseActionRequest?> GetAsync(string id) =>
        _store.GetPendingActionAsync(id);

    public Task<List<ResponseActionRequest>> GetPendingForAgentAsync(string agentId) =>
        _store.TakePendingActionsAsync(agentId);

    private static bool NeedsApproval(string actionType) =>
        actionType is not ("LogOnly" or "ExportEvidence");
}
