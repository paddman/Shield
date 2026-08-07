using NTShield.Server.Data;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class TenantManagementService
{
    private static readonly HashSet<string> AllowedPlans = new(StringComparer.OrdinalIgnoreCase)
        { "trial", "standard", "enterprise", "managed" };
    private static readonly HashSet<string> AllowedStatuses = new(StringComparer.OrdinalIgnoreCase)
        { "active", "suspended", "onboarding" };
    private readonly ICentralStore _store;

    public TenantManagementService(ICentralStore store) => _store = store;

    public Task<IReadOnlyList<CustomerTenant>> ListAsync() => _store.ListTenantsAsync();

    public Task<CustomerTenant?> GetAsync(string tenantId) =>
        _store.GetTenantAsync(TopologyService.NormalizeTenantId(tenantId));

    public async Task<CustomerTenant> SaveAsync(CustomerTenant tenant)
    {
        tenant.TenantId = TopologyService.NormalizeTenantId(tenant.TenantId);
        tenant.Name = Required(tenant.Name, "Customer name", 200);
        tenant.LegalName = Optional(tenant.LegalName, 240);
        tenant.ContactName = Optional(tenant.ContactName, 160);
        tenant.ContactEmail = Optional(tenant.ContactEmail, 254);
        if (tenant.ContactEmail is not null && !tenant.ContactEmail.Contains('@'))
            throw new TopologyValidationException("Contact email is invalid.");
        tenant.Plan = Required(tenant.Plan, "Plan", 32).ToLowerInvariant();
        tenant.Status = Required(tenant.Status, "Status", 32).ToLowerInvariant();
        if (!AllowedPlans.Contains(tenant.Plan)) throw new TopologyValidationException("Unknown customer plan.");
        if (!AllowedStatuses.Contains(tenant.Status)) throw new TopologyValidationException("Unknown customer status.");
        tenant.Notes = Optional(tenant.Notes, 4000);

        var existing = await _store.GetTenantAsync(tenant.TenantId);
        tenant.CreatedAtUtc = existing?.CreatedAtUtc ?? DateTimeOffset.UtcNow;
        tenant.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await _store.UpsertTenantAsync(tenant);
        return tenant;
    }

    public async Task AssignAgentAsync(string tenantId, string agentId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        agentId = Required(agentId, "Agent id", 256);
        if (await _store.GetTenantAsync(tenantId) is null)
            throw new TopologyValidationException("Customer tenant does not exist.");
        if (await _store.GetAgentAsync(agentId, 1) is null)
            throw new TopologyValidationException("Agent does not exist.");
        await _store.AssignAgentToTenantAsync(tenantId, agentId);
    }

    private static string Required(string? value, string field, int maxLength)
    {
        var text = value?.Trim();
        if (string.IsNullOrWhiteSpace(text)) throw new TopologyValidationException($"{field} is required.");
        if (text.Length > maxLength) throw new TopologyValidationException($"{field} must be at most {maxLength} characters.");
        return text;
    }

    private static string? Optional(string? value, int maxLength)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text)) return null;
        if (text.Length > maxLength) throw new TopologyValidationException($"Text must be at most {maxLength} characters.");
        return text;
    }
}
