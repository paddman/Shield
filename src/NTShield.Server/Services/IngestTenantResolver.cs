using NTShield.Server.Data;
using NTShield.Server.Security;
using NTShield.Shared.Contracts;

namespace NTShield.Server.Services;

public sealed class IngestIdentityException : Exception
{
    public IngestIdentityException(string message) : base(message) { }
}

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
        var effectiveAgentId = ResolveBoundAgentId(context, agentId);

        var assignment = (await _store.ListAgentAssignmentsAsync())
            .FirstOrDefault(item => string.Equals(item.AgentId, effectiveAgentId, StringComparison.OrdinalIgnoreCase));
        return assignment is null
            ? "default"
            : TopologyService.NormalizeTenantId(assignment.TenantId);
    }

    /// <summary>
    /// Binds every nested telemetry record to the authenticated agent. Empty nested
    /// IDs are filled; conflicting IDs are rejected before anything is persisted.
    /// </summary>
    public async Task<string> ResolveAndBindAsync(HttpContext context, AgentIngestBatch batch)
    {
        var effectiveAgentId = ResolveBoundAgentId(context, batch.AgentId);

        batch.AgentId = effectiveAgentId;
        batch.SecurityEvents ??= [];
        batch.NetworkConnections ??= [];
        batch.Processes ??= [];
        batch.Services ??= [];
        batch.ScheduledTasks ??= [];
        batch.Alerts ??= [];

        foreach (var item in batch.SecurityEvents) item.AgentId = Bind(item.AgentId, effectiveAgentId, "security event");
        foreach (var item in batch.NetworkConnections) item.AgentId = Bind(item.AgentId, effectiveAgentId, "network connection");
        foreach (var item in batch.Processes) item.AgentId = Bind(item.AgentId, effectiveAgentId, "process");
        foreach (var item in batch.Services) item.AgentId = Bind(item.AgentId, effectiveAgentId, "service");
        foreach (var item in batch.ScheduledTasks) item.AgentId = Bind(item.AgentId, effectiveAgentId, "scheduled task");
        foreach (var item in batch.Alerts) item.AgentId = Bind(item.AgentId, effectiveAgentId, "detection alert");

        return await ResolveAsync(context, effectiveAgentId);
    }

    /// <summary>
    /// Returns the authenticated agent identity and rejects a conflicting body
    /// identity. Legacy heartbeat and ingest routes share this guard so an agent
    /// key cannot update another endpoint's inventory record.
    /// </summary>
    public static string ResolveBoundAgentId(HttpContext context, string? claimedAgentId)
    {
        var boundAgentId = context.Items.TryGetValue(ApiKeyAuthMiddleware.AgentIdItem, out var bound)
            ? bound as string
            : null;
        var claimed = claimedAgentId?.Trim() ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(boundAgentId) &&
            !string.IsNullOrWhiteSpace(claimed) &&
            !string.Equals(boundAgentId, claimed, StringComparison.OrdinalIgnoreCase))
        {
            throw new IngestIdentityException("The claimed agent id does not match the authenticated agent.");
        }

        var effectiveAgentId = string.IsNullOrWhiteSpace(boundAgentId) ? claimed : boundAgentId.Trim();
        if (string.IsNullOrWhiteSpace(effectiveAgentId))
            throw new IngestIdentityException("An agent id is required.");
        return effectiveAgentId;
    }

    private static string Bind(string? claimedAgentId, string effectiveAgentId, string recordType)
    {
        if (!string.IsNullOrWhiteSpace(claimedAgentId) &&
            !string.Equals(claimedAgentId.Trim(), effectiveAgentId, StringComparison.OrdinalIgnoreCase))
        {
            throw new IngestIdentityException($"Nested {recordType} agent id does not match the ingest identity.");
        }

        return effectiveAgentId;
    }
}
