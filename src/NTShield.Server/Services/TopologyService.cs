using System.Text.RegularExpressions;
using NTShield.Server.Data;
using NTShield.Server.Security;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class TopologyValidationException : Exception
{
    public TopologyValidationException(string message) : base(message) { }
}

public sealed class TenantAccessDeniedException : Exception
{
    public TenantAccessDeniedException(string message) : base(message) { }
}

/// <summary>
/// Tenant-scoped orchestration and guardrails for the asset/topology/workflow
/// APIs. Persistence remains behind ICentralStore so SQLite, PostgreSQL and
/// ClickHouse control-plane mode share the same API contract.
/// </summary>
public sealed class TopologyService
{
    private static readonly Regex TenantPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.Compiled);
    private readonly ICentralStore _store;
    private readonly ILogger<TopologyService> _logger;

    public TopologyService(ICentralStore store, ILogger<TopologyService> logger)
    {
        _store = store;
        _logger = logger;
    }

    public static string ResolveTenantId(HttpContext context)
    {
        var raw = context.Request.Headers["X-NTShield-Tenant"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(raw)) raw = "default";
        var tenantId = NormalizeTenantId(raw);

        var dashboardUser = context.User.Identity?.IsAuthenticated == true &&
                            context.User.FindAll(System.Security.Claims.ClaimTypes.Role)
                                .Any(claim => DashboardRoles.IsKnown(claim.Value));
        if (!dashboardUser) return tenantId;

        var allowed = context.User.FindAll(DashboardSessionEndpoints.TenantClaim)
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!allowed.Contains("*") && !allowed.Contains(tenantId))
            throw new TenantAccessDeniedException("The authenticated operator is not assigned to this tenant.");
        return tenantId;
    }

    public static string NormalizeTenantId(string value)
    {
        value = value.Trim().ToLowerInvariant();
        if (!TenantPattern.IsMatch(value))
            throw new TopologyValidationException("Tenant id must be 1-128 characters using letters, numbers, '.', '_', ':' or '-'.");
        return value;
    }

    public static IReadOnlyList<TopologyNodeKindDefinition> NodeKinds { get; } =
    [
        new() { Kind = "internet", Label = "Internet", Category = "edge", Icon = "◎" },
        new() { Kind = "dns", Label = "DNS", Category = "edge", Icon = "D" },
        new() { Kind = "cdn", Label = "CDN", Category = "edge", Icon = "◌" },
        new() { Kind = "waf", Label = "WAF / AI-WAF", Category = "security", Icon = "W" },
        new() { Kind = "api-gateway", Label = "API Gateway", Category = "application", Icon = "A" },
        new() { Kind = "load-balancer", Label = "Load Balancer", Category = "network", Icon = "⇄" },
        new() { Kind = "web-server", Label = "Web Server", Category = "application", Icon = "WEB" },
        new() { Kind = "application", Label = "Application / API", Category = "application", Icon = "APP" },
        new() { Kind = "database", Label = "Database", Category = "data", Icon = "DB" },
        new() { Kind = "cache", Label = "Cache / Queue", Category = "data", Icon = "C" },
        new() { Kind = "endpoint", Label = "Endpoint / Server", Category = "endpoint", Icon = "EP" },
        new() { Kind = "kubernetes", Label = "Kubernetes / Container", Category = "endpoint", Icon = "K8S" },
        new() { Kind = "router", Label = "Router", Category = "network", Icon = "R" },
        new() { Kind = "switch", Label = "Switch", Category = "network", Icon = "SW" },
        new() { Kind = "firewall", Label = "Firewall", Category = "security", Icon = "FW" },
        new() { Kind = "vpn", Label = "VPN", Category = "security", Icon = "VPN" },
        new() { Kind = "mikrotik", Label = "Mikrotik", Category = "network", Icon = "MT" },
        new() { Kind = "identity", Label = "AD / LDAP / IdP", Category = "identity", Icon = "ID" },
        new() { Kind = "sensor", Label = "Suricata / Zeek / EDR", Category = "security", Icon = "S" },
        new() { Kind = "central", Label = "NT Shield Central", Category = "security", Icon = "NT" },
        new() { Kind = "cloud", Label = "Cloud / SaaS", Category = "cloud", Icon = "☁" },
        new() { Kind = "backup", Label = "Backup / Storage", Category = "data", Icon = "B" },
        new() { Kind = "custom", Label = "Custom", Category = "custom", Icon = "◇" }
    ];

    public Task<IReadOnlyList<TenantAsset>> ListAssetsAsync(string tenantId) => _store.ListAssetsAsync(tenantId);

    public Task<TenantAsset?> GetAssetAsync(string tenantId, string assetId) =>
        _store.GetAssetAsync(tenantId, ValidateId(assetId, "assetId"));

    public async Task<TenantAsset> SaveAssetAsync(string tenantId, TenantAsset asset)
    {
        tenantId = ValidateTenant(tenantId);
        asset.AssetId = string.IsNullOrWhiteSpace(asset.AssetId) ? Guid.NewGuid().ToString("N") : ValidateId(asset.AssetId, "assetId");
        asset.Name = RequiredText(asset.Name, "name", 200);
        asset.Kind = RequiredText(asset.Kind, "kind", 64).ToLowerInvariant();
        asset.Hostname = OptionalText(asset.Hostname, 255);
        asset.Address = OptionalText(asset.Address, 255);
        asset.Environment = OptionalText(asset.Environment, 64) ?? "production";
        asset.Criticality = OptionalText(asset.Criticality, 32) ?? "medium";
        asset.Status = OptionalText(asset.Status, 32) ?? "unknown";
        asset.Description = OptionalText(asset.Description, 2000);
        asset.Tags = (asset.Tags ?? []).Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(50).ToList();
        asset.Metadata = (asset.Metadata ?? new Dictionary<string, string>())
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
            .Take(50)
            .ToDictionary(pair => pair.Key.Trim(), pair => pair.Value?.Trim() ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        var existing = await _store.GetAssetAsync(tenantId, asset.AssetId);
        asset.TenantId = tenantId;
        asset.CreatedAtUtc = existing?.CreatedAtUtc ?? DateTimeOffset.UtcNow;
        asset.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await _store.UpsertAssetAsync(tenantId, asset);
        return asset;
    }

    public Task<bool> DeleteAssetAsync(string tenantId, string assetId) =>
        _store.DeleteAssetAsync(ValidateTenant(tenantId), ValidateId(assetId, "assetId"));

    public Task<IReadOnlyList<TopologyDocument>> ListTopologiesAsync(string tenantId) =>
        _store.ListTopologiesAsync(ValidateTenant(tenantId));

    public Task<TopologyDocument?> GetTopologyAsync(string tenantId, string topologyId) =>
        _store.GetTopologyAsync(ValidateTenant(tenantId), ValidateId(topologyId, "topologyId"));

    public async Task<TopologyDocument> SaveTopologyAsync(string tenantId, TopologyDocument topology)
    {
        tenantId = ValidateTenant(tenantId);
        topology.TopologyId = string.IsNullOrWhiteSpace(topology.TopologyId)
            ? Guid.NewGuid().ToString("N")
            : ValidateId(topology.TopologyId, "topologyId");
        topology.Name = RequiredText(topology.Name, "name", 200);
        topology.Description = OptionalText(topology.Description, 2000);
        topology.Nodes ??= [];
        topology.Edges ??= [];
        if (topology.Nodes.Count > 500) throw new TopologyValidationException("A topology can contain at most 500 nodes.");
        if (topology.Edges.Count > 1000) throw new TopologyValidationException("A topology can contain at most 1,000 edges.");

        var nodeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in topology.Nodes)
        {
            node.NodeId = string.IsNullOrWhiteSpace(node.NodeId) ? Guid.NewGuid().ToString("N") : ValidateId(node.NodeId, "nodeId");
            if (!nodeIds.Add(node.NodeId)) throw new TopologyValidationException($"Duplicate topology node id: {node.NodeId}.");
            node.Label = RequiredText(node.Label, "node label", 200);
            node.Kind = RequiredText(node.Kind, "node kind", 64).ToLowerInvariant();
            node.Category = OptionalText(node.Category, 64) ?? "custom";
            node.Status = OptionalText(node.Status, 32) ?? "unknown";
            node.TelemetrySourceIds = (node.TelemetrySourceIds ?? [])
                .Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(50).ToList();
            node.Metadata = (node.Metadata ?? new Dictionary<string, string>())
                .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
                .Take(50)
                .ToDictionary(pair => pair.Key.Trim(), pair => pair.Value?.Trim() ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        }

        foreach (var edge in topology.Edges)
        {
            edge.EdgeId = string.IsNullOrWhiteSpace(edge.EdgeId) ? Guid.NewGuid().ToString("N") : ValidateId(edge.EdgeId, "edgeId");
            edge.SourceNodeId = ValidateId(edge.SourceNodeId, "sourceNodeId");
            edge.TargetNodeId = ValidateId(edge.TargetNodeId, "targetNodeId");
            if (!nodeIds.Contains(edge.SourceNodeId) || !nodeIds.Contains(edge.TargetNodeId))
                throw new TopologyValidationException($"Edge {edge.EdgeId} references a node that is not in the topology.");
            if (string.Equals(edge.SourceNodeId, edge.TargetNodeId, StringComparison.OrdinalIgnoreCase))
                throw new TopologyValidationException($"Edge {edge.EdgeId} cannot connect a node to itself.");
            edge.Label = OptionalText(edge.Label, 120);
            edge.Protocol = OptionalText(edge.Protocol, 64);
        }

        if (topology.Nodes.Any(node => !string.IsNullOrWhiteSpace(node.AssetId)))
        {
            var assets = (await _store.ListAssetsAsync(tenantId)).Select(asset => asset.AssetId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var node in topology.Nodes.Where(node => !string.IsNullOrWhiteSpace(node.AssetId)))
            {
                node.AssetId = ValidateId(node.AssetId!, "assetId");
                if (!assets.Contains(node.AssetId))
                    throw new TopologyValidationException($"Topology node {node.NodeId} references an asset outside this tenant or an unknown asset.");
            }
        }

        var existing = await _store.GetTopologyAsync(tenantId, topology.TopologyId);
        topology.TenantId = tenantId;
        topology.CreatedAtUtc = existing?.CreatedAtUtc ?? DateTimeOffset.UtcNow;
        topology.Version = existing is null ? Math.Max(1, topology.Version) : existing.Version + 1;
        topology.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await _store.UpsertTopologyAsync(tenantId, topology);
        _logger.LogInformation("Topology {TopologyId} saved for tenant {TenantId} with {Nodes} nodes and {Edges} edges",
            topology.TopologyId, tenantId, topology.Nodes.Count, topology.Edges.Count);
        return topology;
    }

    public Task<bool> DeleteTopologyAsync(string tenantId, string topologyId) =>
        _store.DeleteTopologyAsync(ValidateTenant(tenantId), ValidateId(topologyId, "topologyId"));

    public Task<IReadOnlyList<DetectionWorkflow>> ListWorkflowsAsync(string tenantId) =>
        _store.ListWorkflowsAsync(ValidateTenant(tenantId));

    public Task<DetectionWorkflow?> GetWorkflowAsync(string tenantId, string workflowId) =>
        _store.GetWorkflowAsync(ValidateTenant(tenantId), ValidateId(workflowId, "workflowId"));

    public async Task<DetectionWorkflow> SaveWorkflowAsync(string tenantId, DetectionWorkflow workflow)
    {
        tenantId = ValidateTenant(tenantId);
        workflow.WorkflowId = string.IsNullOrWhiteSpace(workflow.WorkflowId)
            ? Guid.NewGuid().ToString("N")
            : ValidateId(workflow.WorkflowId, "workflowId");
        workflow.Name = RequiredText(workflow.Name, "name", 200);
        workflow.Description = OptionalText(workflow.Description, 2000);
        workflow.TopologyId = string.IsNullOrWhiteSpace(workflow.TopologyId) ? null : ValidateId(workflow.TopologyId, "topologyId");
        workflow.Nodes ??= [];
        workflow.Edges ??= [];
        if (workflow.Nodes.Count > 200) throw new TopologyValidationException("A workflow can contain at most 200 nodes.");
        if (workflow.Edges.Count > 500) throw new TopologyValidationException("A workflow can contain at most 500 edges.");

        if (workflow.TopologyId is not null && await _store.GetTopologyAsync(tenantId, workflow.TopologyId) is null)
            throw new TopologyValidationException("Workflow topologyId must refer to a topology in the same tenant.");

        var nodeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in workflow.Nodes)
        {
            node.NodeId = string.IsNullOrWhiteSpace(node.NodeId) ? Guid.NewGuid().ToString("N") : ValidateId(node.NodeId, "workflow nodeId");
            if (!nodeIds.Add(node.NodeId)) throw new TopologyValidationException($"Duplicate workflow node id: {node.NodeId}.");
            node.Type = RequiredText(node.Type, "workflow node type", 64).ToLowerInvariant();
            node.Label = RequiredText(node.Label, "workflow node label", 200);
            node.Config = (node.Config ?? new Dictionary<string, string>())
                .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
                .Take(50)
                .ToDictionary(pair => pair.Key.Trim(), pair => pair.Value?.Trim() ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        }

        foreach (var edge in workflow.Edges)
        {
            edge.EdgeId = string.IsNullOrWhiteSpace(edge.EdgeId) ? Guid.NewGuid().ToString("N") : ValidateId(edge.EdgeId, "workflow edgeId");
            edge.SourceNodeId = ValidateId(edge.SourceNodeId, "workflow sourceNodeId");
            edge.TargetNodeId = ValidateId(edge.TargetNodeId, "workflow targetNodeId");
            if (!nodeIds.Contains(edge.SourceNodeId) || !nodeIds.Contains(edge.TargetNodeId))
                throw new TopologyValidationException($"Workflow edge {edge.EdgeId} references a node that is not in the workflow.");
            if (string.Equals(edge.SourceNodeId, edge.TargetNodeId, StringComparison.OrdinalIgnoreCase))
                throw new TopologyValidationException($"Workflow edge {edge.EdgeId} cannot connect a node to itself.");
            edge.Label = OptionalText(edge.Label, 120);
        }

        var existing = await _store.GetWorkflowAsync(tenantId, workflow.WorkflowId);
        workflow.TenantId = tenantId;
        workflow.CreatedAtUtc = existing?.CreatedAtUtc ?? DateTimeOffset.UtcNow;
        workflow.Version = existing is null ? Math.Max(1, workflow.Version) : existing.Version + 1;
        workflow.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await _store.UpsertWorkflowAsync(tenantId, workflow);
        _logger.LogInformation("Detection workflow {WorkflowId} saved for tenant {TenantId} with {Nodes} nodes and {Edges} edges",
            workflow.WorkflowId, tenantId, workflow.Nodes.Count, workflow.Edges.Count);
        return workflow;
    }

    public Task<bool> DeleteWorkflowAsync(string tenantId, string workflowId) =>
        _store.DeleteWorkflowAsync(ValidateTenant(tenantId), ValidateId(workflowId, "workflowId"));

    private static string ValidateTenant(string value)
        => NormalizeTenantId(value);

    private static string ValidateId(string value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > 128)
            throw new TopologyValidationException($"{field} is required and must be at most 128 characters.");
        return value.Trim();
    }

    private static string RequiredText(string? value, string field, int maxLength)
    {
        var result = value?.Trim();
        if (string.IsNullOrWhiteSpace(result)) throw new TopologyValidationException($"{field} is required.");
        if (result.Length > maxLength) throw new TopologyValidationException($"{field} must be at most {maxLength} characters.");
        return result;
    }

    private static string? OptionalText(string? value, int maxLength)
    {
        var result = value?.Trim();
        if (result is not null && result.Length > maxLength)
            throw new TopologyValidationException($"Text value must be at most {maxLength} characters.");
        return string.IsNullOrWhiteSpace(result) ? null : result;
    }
}
