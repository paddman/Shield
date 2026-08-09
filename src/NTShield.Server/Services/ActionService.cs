using Microsoft.Extensions.Options;
using NTShield.Core.Security;
using NTShield.Server.Data;
using NTShield.Server.Security;
using NTShield.Shared.Models;
using NTShield.Shared.Security;

namespace NTShield.Server.Services;

/// <summary>
/// Durable pending-actions queue for agents. Executable actions are target-bound;
/// destructive actions must carry a short-lived Central RSA approval signature.
/// </summary>
public sealed class ActionService
{
    private readonly ICentralStore _store;
    private readonly SecurityOptions _security;
    private readonly ILogger<ActionService> _logger;

    public ActionService(
        ICentralStore store,
        IOptions<SecurityOptions> security,
        ILogger<ActionService> logger)
    {
        _store = store;
        _security = security.Value;
        _logger = logger;
    }

    public async Task<ResponseActionRequest> EnqueueAsync(ResponseActionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ActionType = request.ActionType?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(request.ActionType) ||
            !EventDataSanitizer.IsAllowlistedCommand(request.ActionType))
        {
            throw new InvalidOperationException("Response action type is missing or not allowlisted.");
        }

        if (string.IsNullOrWhiteSpace(request.TargetAgentId) ||
            string.Equals(request.TargetAgentId, "broadcast", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "A concrete TargetAgentId is required; broadcast response actions are forbidden.");
        }

        request.TargetAgentId = request.TargetAgentId.Trim();
        request.RequestId = string.IsNullOrWhiteSpace(request.RequestId)
            ? Guid.NewGuid().ToString("N")
            : request.RequestId.Trim();
        request.Requester = "operator";
        request.Reason = EventDataSanitizer.SanitizeForLog(request.Reason, 500);

        if (ActionApprovalCrypto.RequiresApproval(request.ActionType))
        {
            if (!request.ApprovalRequested)
            {
                throw new InvalidOperationException(
                    $"Action {request.ActionType} requires explicit operator approval.");
            }

            if (string.IsNullOrWhiteSpace(request.Reason))
            {
                throw new InvalidOperationException(
                    $"Action {request.ActionType} requires an approval reason.");
            }

            var defaultMinutes = Math.Clamp(_security.ActionLifetimeMinutes, 1, 60);
            var maxMinutes = Math.Clamp(_security.MaxActionLifetimeMinutes, 1, 60);
            var requestedMinutes = request.DurationMinutes <= 0
                ? defaultMinutes
                : request.DurationMinutes;
            request.DurationMinutes = Math.Clamp(requestedMinutes, 1, maxMinutes);

            ActionApprovalCrypto.Sign(
                request,
                approvedBy: "operator",
                lifetime: TimeSpan.FromMinutes(request.DurationMinutes));

            if (!request.Approved)
                throw new InvalidOperationException("Central could not validate its signed action envelope.");
        }
        else
        {
            // Read-only actions do not borrow client-supplied approval metadata.
            request.Approved = false;
            request.ApprovalId = null;
            request.ApprovedBy = null;
            request.ApprovedAtUtc = null;
            request.ExpiresAtUtc = null;
            request.Nonce = null;
            request.ApprovalKeyId = null;
            request.PayloadSha256 = null;
            request.ApprovalSignature = null;
        }

        await _store.SavePendingActionAsync(request, request.TargetAgentId);

        _logger.LogWarning(
            "Enqueued action {Type} for agent={Agent} approved={Approved} expires={Expires} key={KeyId} id={Id}",
            request.ActionType,
            request.TargetAgentId,
            request.Approved,
            request.ExpiresAtUtc,
            request.ApprovalKeyId,
            request.RequestId);

        return request;
    }

    public Task<ResponseActionRequest?> GetAsync(string id) =>
        _store.GetPendingActionAsync(id);

    public async Task<List<ResponseActionRequest>> GetPendingForAgentAsync(string agentId)
    {
        var pending = await _store.TakePendingActionsAsync(agentId);
        var accepted = new List<ResponseActionRequest>(pending.Count);

        foreach (var action in pending)
        {
            if (!string.Equals(action.TargetAgentId, agentId, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogCritical(
                    "Dropped target-mismatched action id={Id} expectedAgent={Expected} actualTarget={Actual}",
                    action.RequestId,
                    agentId,
                    action.TargetAgentId);
                continue;
            }

            if (ActionApprovalCrypto.RequiresApproval(action.ActionType) && !action.Approved)
            {
                _logger.LogCritical(
                    "Dropped unsigned, tampered or expired action id={Id} type={Type} agent={Agent}",
                    action.RequestId,
                    action.ActionType,
                    agentId);
                continue;
            }

            accepted.Add(action);
        }

        return accepted;
    }
}
