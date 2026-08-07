namespace NTShield.Shared.Models;

/// <summary>
/// Customer-owned infrastructure asset. It is intentionally separate from an
/// installed NT Shield Agent so network, cloud and appliance assets can be
/// represented before a collector is connected.
/// </summary>
public sealed class TenantAsset
{
    public string AssetId { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = string.Empty;
    public string Kind { get; set; } = "custom";
    public string? Hostname { get; set; }
    public string? Address { get; set; }
    public string Environment { get; set; } = "production";
    public string Criticality { get; set; } = "medium";
    public string Status { get; set; } = "unknown";
    public string? Description { get; set; }
    public List<string> Tags { get; set; } = [];
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// A persisted customer topology that can be edited from the Control Center.
/// Coordinates are canvas coordinates, not network coordinates.
/// </summary>
public sealed class TopologyDocument
{
    public string TopologyId { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = "Infrastructure map";
    public string? Description { get; set; }
    public int Version { get; set; } = 1;
    public List<TopologyNode> Nodes { get; set; } = [];
    public List<TopologyEdge> Edges { get; set; } = [];
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class TopologyNode
{
    public string NodeId { get; set; } = Guid.NewGuid().ToString("N");
    public string Label { get; set; } = "New asset";
    /// <summary>
    /// Examples: internet, dns, cdn, waf, api-gateway, load-balancer,
    /// web-server, application, database, cache, endpoint, kubernetes,
    /// router, switch, firewall, vpn, mikrotik, identity, sensor, cloud, custom.
    /// </summary>
    public string Kind { get; set; } = "custom";
    public string Category { get; set; } = "custom";
    public string? AssetId { get; set; }
    public double X { get; set; }
    public double Y { get; set; }
    public string Status { get; set; } = "unknown";
    public List<string> TelemetrySourceIds { get; set; } = [];
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class TopologyNodeKindDefinition
{
    public string Kind { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Icon { get; set; } = "◇";
}

public sealed class TopologyEdge
{
    public string EdgeId { get; set; } = Guid.NewGuid().ToString("N");
    public string SourceNodeId { get; set; } = string.Empty;
    public string TargetNodeId { get; set; } = string.Empty;
    public string? Label { get; set; }
    public string? Protocol { get; set; }
    public bool Bidirectional { get; set; }
}

/// <summary>
/// Declarative detection workflow graph. The first slice stores and displays
/// the graph; execution is deliberately kept behind the existing detection and
/// response guardrails until a workflow engine is added.
/// </summary>
public sealed class DetectionWorkflow
{
    public string WorkflowId { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = "New detection workflow";
    public string? Description { get; set; }
    public string? TopologyId { get; set; }
    public bool Enabled { get; set; }
    public int Version { get; set; } = 1;
    public List<WorkflowNode> Nodes { get; set; } = [];
    public List<WorkflowEdge> Edges { get; set; } = [];
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class WorkflowNode
{
    public string NodeId { get; set; } = Guid.NewGuid().ToString("N");
    /// <summary>trigger, filter, enrich, correlate, ai, approval, response, notify.</summary>
    public string Type { get; set; } = "trigger";
    public string Label { get; set; } = "New step";
    public double X { get; set; }
    public double Y { get; set; }
    public Dictionary<string, string> Config { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class WorkflowEdge
{
    public string EdgeId { get; set; } = Guid.NewGuid().ToString("N");
    public string SourceNodeId { get; set; } = string.Empty;
    public string TargetNodeId { get; set; } = string.Empty;
    public string? Label { get; set; }
}
