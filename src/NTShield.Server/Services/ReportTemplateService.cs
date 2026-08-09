using System.Text.Json;
using System.Text.RegularExpressions;
using NTShield.Server.Data;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

public sealed class ReportTemplateReadOnlyException : Exception
{
    public ReportTemplateReadOnlyException() : base("Built-in report templates are read-only.") { }
}

public sealed class ReportTemplateVersionConflictException : Exception
{
    public ReportTemplateVersionConflictException(int currentVersion)
        : base("The report template changed after this editor loaded it.")
    {
        CurrentVersion = currentVersion;
    }

    public int CurrentVersion { get; }
}

/// <summary>
/// Owns the allowlisted Report Template Studio contract. Templates are data,
/// never executable markup or queries.
/// </summary>
public sealed class ReportTemplateService
{
    public const string DefaultTemplateId = "builtin-executive";
    private const int MaxBlocks = 24;
    private static readonly Regex IdPattern = new(
        "^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ColorPattern = new(
        "^#[0-9a-fA-F]{6}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly Dictionary<string, string> BlockSources = new(StringComparer.OrdinalIgnoreCase)
    {
        ["header"] = "report.identity",
        ["metrics"] = "report.metrics",
        ["severity"] = "report.severityCounts",
        ["incidents"] = "report.priorityIncidents",
        ["topSources"] = "report.topSourceIps",
        ["topEvents"] = "report.topEventIds",
        ["recommendations"] = "report.recommendations",
        ["coverage"] = "report.coverage"
    };

    private static readonly HashSet<string> SourceFreeBlocks = new(
        ["divider", "text"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Widths = new(
        ["full", "half", "third"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Styles = new(
        ["default", "card", "plain", "accent"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Presets = new(
        ["executive", "technical", "midnight", "signal", "minimal", "classic", "custom"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Fonts = new(
        ["system", "arial", "georgia", "mono"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Sizes = new(
        ["a4", "letter"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Orientations = new(
        ["portrait", "landscape"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Margins = new(
        ["compact", "normal", "spacious"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> Densities = new(
        ["compact", "comfortable"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> MetricKeys = new(
    [
        "agents", "onlineAgents", "assets", "threatEvents", "incidents", "openIncidents",
        "threatCampaigns", "defenseScore", "critical", "high", "medium", "low"
    ], StringComparer.OrdinalIgnoreCase);

    private static readonly IReadOnlyList<ReportTemplateDataSource> DataSourceCatalog =
    [
        Source("report.identity", "Report identity", "Customer, report title and UTC period.", "identity", "header", 1),
        Source("report.metrics", "Security metrics", "Bounded report KPI values.", "metrics", "metrics", 12,
            [.. MetricKeys.OrderBy(item => item, StringComparer.OrdinalIgnoreCase)]),
        Source("report.severityCounts", "Severity counts", "Critical, high, medium and low incident totals.", "risk", "severity", 4),
        Source("report.priorityIncidents", "Priority incidents", "Highest priority incident snapshot rows.", "incidents", "incidents", 50),
        Source("report.topSourceIps", "Top source IPs", "Ranked source IP counts from the report snapshot.", "rankings", "topSources", 50),
        Source("report.topEventIds", "Top event IDs", "Ranked Windows/security event IDs from the report snapshot.", "rankings", "topEvents", 50),
        Source("report.recommendations", "Recommendations", "Server-generated defensive recommendations.", "guidance", "recommendations", 20),
        Source("report.coverage", "Coverage note", "Report sampling and period coverage statement.", "narrative", "coverage", 1)
    ];

    private readonly ICentralStore _store;

    public ReportTemplateService(ICentralStore store)
    {
        _store = store;
    }

    public IReadOnlyList<ReportTemplateDataSource> ListDataSources() => DataSourceCatalog;

    public async Task<IReadOnlyList<ReportTemplateDefinition>> ListAsync(string tenantId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var builtIns = BuildBuiltIns(tenantId);
        var custom = await _store.ListReportTemplatesAsync(tenantId);
        return builtIns.Concat(custom.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    public async Task<ReportTemplateDefinition?> GetAsync(string tenantId, string templateId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        if (string.IsNullOrWhiteSpace(templateId) || templateId.Length > 128) return null;
        var builtIn = BuildBuiltIns(tenantId).FirstOrDefault(item =>
            string.Equals(item.TemplateId, templateId, StringComparison.OrdinalIgnoreCase));
        return builtIn ?? await _store.GetReportTemplateAsync(tenantId, templateId);
    }

    public async Task<ReportTemplateDefinition> CreateAsync(
        string tenantId,
        ReportTemplateDefinition input)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        if (await _store.GetTenantAsync(tenantId) is null)
            throw new TopologyValidationException("Customer tenant does not exist.");

        var now = DateTimeOffset.UtcNow;
        input.TemplateId = $"tpl-{Guid.NewGuid():N}";
        input.TenantId = tenantId;
        input.IsBuiltIn = false;
        input.Version = 1;
        input.CreatedAtUtc = now;
        input.UpdatedAtUtc = now;
        ValidateAndNormalize(input);
        await _store.UpsertReportTemplateAsync(tenantId, input);
        return input;
    }

    public async Task<ReportTemplateDefinition?> UpdateAsync(
        string tenantId,
        string templateId,
        ReportTemplateDefinition input)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        EnsureWritable(templateId);
        var existing = await _store.GetReportTemplateAsync(tenantId, templateId);
        if (existing is null) return null;
        var expectedVersion = input.Version;
        if (expectedVersion is < 1 or int.MaxValue)
            throw new TopologyValidationException("Template version must be between 1 and 2,147,483,646.");

        input.TemplateId = existing.TemplateId;
        input.TenantId = tenantId;
        input.IsBuiltIn = false;
        input.Version = expectedVersion + 1;
        input.CreatedAtUtc = existing.CreatedAtUtc;
        input.UpdatedAtUtc = DateTimeOffset.UtcNow;
        ValidateAndNormalize(input);
        if (!await _store.TryUpdateReportTemplateAsync(tenantId, input, expectedVersion))
        {
            var current = await _store.GetReportTemplateAsync(tenantId, templateId);
            if (current is null) return null;
            throw new ReportTemplateVersionConflictException(current.Version);
        }
        return input;
    }

    public async Task<ReportTemplateDefinition?> DuplicateAsync(
        string tenantId,
        string templateId,
        string? requestedName)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var source = await GetAsync(tenantId, templateId);
        if (source is null) return null;
        var copy = DeepClone(source);
        var sourceName = source.Name ?? "Template";
        copy.Name = string.IsNullOrWhiteSpace(requestedName)
            ? $"{sourceName[..Math.Min(sourceName.Length, 95)]} Copy"
            : requestedName;
        return await CreateAsync(tenantId, copy);
    }

    public async Task<bool> DeleteAsync(string tenantId, string templateId)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        EnsureWritable(templateId);
        return await _store.DeleteReportTemplateAsync(tenantId, templateId);
    }

    public async Task<ReportTemplateDefinition> ResolveForReportAsync(
        string tenantId,
        string? templateId)
    {
        var selected = string.IsNullOrWhiteSpace(templateId) ? DefaultTemplateId : templateId.Trim();
        var template = await GetAsync(tenantId, selected);
        if (template is null)
            throw new TopologyValidationException("Report template does not exist for this tenant.");
        ValidateAndNormalize(template);
        return DeepClone(template);
    }

    public static bool IsBuiltInId(string? templateId) =>
        !string.IsNullOrWhiteSpace(templateId) &&
        BuildBuiltIns("default").Any(item =>
            string.Equals(item.TemplateId, templateId, StringComparison.OrdinalIgnoreCase));

    public static ReportTemplateDefinition DeepClone(ReportTemplateDefinition template) =>
        JsonSerializer.Deserialize<ReportTemplateDefinition>(
            JsonSerializer.Serialize(template, JsonOptions), JsonOptions)!;

    private static void EnsureWritable(string templateId)
    {
        if (IsBuiltInId(templateId)) throw new ReportTemplateReadOnlyException();
    }

    private static void ValidateAndNormalize(ReportTemplateDefinition template)
    {
        template.Name = Required(template.Name, "Template name", 100);
        template.Description = Optional(template.Description, "Template description", 500);
        template.Theme ??= new ReportTemplateTheme();
        template.Page ??= new ReportTemplatePage();
        template.Blocks ??= [];
        if (template.Blocks.Count is < 1 or > MaxBlocks)
            throw new TopologyValidationException($"A report template must contain 1-{MaxBlocks} blocks.");

        template.Theme.Preset = Allowed(template.Theme.Preset, Presets, "Theme preset");
        template.Theme.FontFamily = Allowed(template.Theme.FontFamily, Fonts, "Font family");
        template.Theme.PrimaryColor = Color(template.Theme.PrimaryColor, "Primary color");
        template.Theme.AccentColor = Color(template.Theme.AccentColor, "Accent color");
        template.Theme.BackgroundColor = Color(template.Theme.BackgroundColor, "Background color");
        template.Theme.TextColor = Color(template.Theme.TextColor, "Text color");

        template.Page.Size = Allowed(template.Page.Size, Sizes, "Page size");
        template.Page.Orientation = Allowed(template.Page.Orientation, Orientations, "Page orientation");
        template.Page.Margin = Allowed(template.Page.Margin, Margins, "Page margin");
        template.Page.Density = Allowed(template.Page.Density, Densities, "Page density");
        if (template.Page.Columns is < 1 or > 2)
            throw new TopologyValidationException("Page columns must be 1 or 2.");

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var block in template.Blocks)
        {
            if (block is null) throw new TopologyValidationException("Template blocks cannot be null.");
            block.BlockId = Required(block.BlockId, "Block id", 64);
            if (!IdPattern.IsMatch(block.BlockId))
                throw new TopologyValidationException("Block id contains unsupported characters.");
            if (!ids.Add(block.BlockId))
                throw new TopologyValidationException("Block ids must be unique.");

            block.Type = CanonicalBlockType(block.Type);
            block.Width = Allowed(block.Width, Widths, "Block width");
            block.Style = Allowed(block.Style, Styles, "Block style");
            block.Title = string.IsNullOrWhiteSpace(block.Title)
                ? null
                : Optional(block.Title, "Block title", 120);
            block.MetricKeys ??= [];
            if (block.MetricKeys.Count > 12 || block.MetricKeys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != block.MetricKeys.Count)
                throw new TopologyValidationException("Metric keys must be unique and contain at most 12 entries.");

            if (BlockSources.TryGetValue(block.Type, out var requiredSource))
            {
                if (!string.Equals(block.DataSourceId, requiredSource, StringComparison.OrdinalIgnoreCase))
                    throw new TopologyValidationException($"Block type '{block.Type}' requires data source '{requiredSource}'.");
                block.DataSourceId = requiredSource;
            }
            else if (SourceFreeBlocks.Contains(block.Type))
            {
                if (!string.IsNullOrWhiteSpace(block.DataSourceId))
                    throw new TopologyValidationException($"Block type '{block.Type}' does not accept a data source.");
                block.DataSourceId = null;
            }

            var maxLimit = DataSourceCatalog.FirstOrDefault(item =>
                string.Equals(item.DataSourceId, block.DataSourceId, StringComparison.OrdinalIgnoreCase))?.MaxLimit ?? 100;
            if (block.Limit is < 1 || block.Limit > maxLimit)
                throw new TopologyValidationException($"Block limit must be between 1 and {maxLimit}.");

            if (string.Equals(block.Type, "metrics", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var key in block.MetricKeys)
                    if (!MetricKeys.Contains(key))
                        throw new TopologyValidationException($"Metric key '{key}' is not allowlisted.");
                block.MetricKeys = block.MetricKeys
                    .Select(CanonicalMetricKey)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
            else if (block.MetricKeys.Count > 0)
            {
                throw new TopologyValidationException("Metric keys are only valid for metrics blocks.");
            }

            if (!string.Equals(block.Type, "text", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(block.Text))
                throw new TopologyValidationException("Plain text is only valid for text blocks.");
            block.Text = string.Equals(block.Type, "text", StringComparison.OrdinalIgnoreCase)
                ? Optional(block.Text, "Block text", 2_000)
                : null;
        }
    }

    private static string CanonicalBlockType(string? value)
    {
        var all = BlockSources.Keys.Concat(SourceFreeBlocks);
        var match = all.FirstOrDefault(item => string.Equals(item, value?.Trim(), StringComparison.OrdinalIgnoreCase));
        return match ?? throw new TopologyValidationException("Unsupported report block type.");
    }

    private static string CanonicalMetricKey(string key) =>
        MetricKeys.First(item => string.Equals(item, key.Trim(), StringComparison.OrdinalIgnoreCase));

    private static string Allowed(string? value, HashSet<string> allowed, string field)
    {
        var match = allowed.FirstOrDefault(item => string.Equals(item, value?.Trim(), StringComparison.OrdinalIgnoreCase));
        return match ?? throw new TopologyValidationException($"{field} is not supported.");
    }

    private static string Color(string? value, string field)
    {
        value = value?.Trim() ?? string.Empty;
        if (!ColorPattern.IsMatch(value))
            throw new TopologyValidationException($"{field} must be a #RRGGBB color.");
        return value.ToUpperInvariant();
    }

    private static string Required(string? value, string field, int maxLength)
    {
        value = value?.Trim() ?? string.Empty;
        if (value.Length is < 1 || value.Length > maxLength)
            throw new TopologyValidationException($"{field} is required and must be at most {maxLength} characters.");
        return value;
    }

    private static string Optional(string? value, string field, int maxLength)
    {
        value = value?.Trim() ?? string.Empty;
        if (value.Length > maxLength)
            throw new TopologyValidationException($"{field} must be at most {maxLength} characters.");
        return value;
    }

    private static IReadOnlyList<ReportTemplateDefinition> BuildBuiltIns(string tenantId)
    {
        var created = DateTimeOffset.UnixEpoch;
        return
        [
            new ReportTemplateDefinition
            {
                TemplateId = DefaultTemplateId,
                TenantId = tenantId,
                Name = "Executive Security Brief",
                Description = "Customer-ready scorecard, priority incidents and recommendations.",
                IsBuiltIn = true,
                Theme = new ReportTemplateTheme { Preset = "executive" },
                Page = new ReportTemplatePage { Columns = 1 },
                Blocks =
                [
                    Block("identity", "header", "report.identity", 1),
                    Block("kpis", "metrics", "report.metrics", 12, metricKeys:
                        ["threatEvents", "incidents", "threatCampaigns", "defenseScore", "onlineAgents", "assets", "critical", "high"]),
                    Block("severity", "severity", "report.severityCounts", 4, width: "half"),
                    Block("recommendations", "recommendations", "report.recommendations", 10, width: "half"),
                    Block("incidents", "incidents", "report.priorityIncidents", 12),
                    Block("coverage", "coverage", "report.coverage", 1, style: "plain")
                ],
                CreatedAtUtc = created,
                UpdatedAtUtc = created
            },
            new ReportTemplateDefinition
            {
                TemplateId = "builtin-technical",
                TenantId = tenantId,
                Name = "Technical Investigation",
                Description = "Dense incident evidence and ranked telemetry for SOC review.",
                IsBuiltIn = true,
                Theme = new ReportTemplateTheme
                {
                    Preset = "technical",
                    PrimaryColor = "#123B5D",
                    AccentColor = "#2F80ED",
                    BackgroundColor = "#F7F8FA",
                    TextColor = "#252C38",
                    FontFamily = "mono"
                },
                Page = new ReportTemplatePage { Orientation = "landscape", Columns = 2, Density = "compact" },
                Blocks =
                [
                    Block("identity", "header", "report.identity", 1),
                    Block("kpis", "metrics", "report.metrics", 12),
                    Block("sources", "topSources", "report.topSourceIps", 10, width: "half"),
                    Block("events", "topEvents", "report.topEventIds", 10, width: "half"),
                    Block("incidents", "incidents", "report.priorityIncidents", 25),
                    Block("coverage", "coverage", "report.coverage", 1, style: "plain")
                ],
                CreatedAtUtc = created,
                UpdatedAtUtc = created
            },
            new ReportTemplateDefinition
            {
                TemplateId = "builtin-compact",
                TenantId = tenantId,
                Name = "Compact Status Update",
                Description = "Short operational update optimized for fast review.",
                IsBuiltIn = true,
                Theme = new ReportTemplateTheme
                {
                    Preset = "minimal",
                    PrimaryColor = "#334155",
                    AccentColor = "#16A36A",
                    BackgroundColor = "#FFFFFF",
                    TextColor = "#252C38"
                },
                Page = new ReportTemplatePage { Margin = "compact", Density = "compact" },
                Blocks =
                [
                    Block("identity", "header", "report.identity", 1, style: "plain"),
                    Block("kpis", "metrics", "report.metrics", 6, metricKeys:
                        ["defenseScore", "incidents", "openIncidents", "onlineAgents", "assets", "critical"]),
                    Block("incidents", "incidents", "report.priorityIncidents", 6),
                    Block("recommendations", "recommendations", "report.recommendations", 5)
                ],
                CreatedAtUtc = created,
                UpdatedAtUtc = created
            },
            new ReportTemplateDefinition
            {
                TemplateId = "builtin-risk-exposure",
                TenantId = tenantId,
                Name = "Risk & Exposure Review",
                Description = "Risk-led view of severity, exposed sources and unresolved incidents.",
                IsBuiltIn = true,
                Theme = new ReportTemplateTheme
                {
                    Preset = "midnight",
                    PrimaryColor = "#0F172A",
                    AccentColor = "#8B5CF6",
                    BackgroundColor = "#0F172A",
                    TextColor = "#F8FAFC"
                },
                Page = new ReportTemplatePage { Orientation = "landscape", Columns = 2 },
                Blocks =
                [
                    Block("identity", "header", "report.identity", 1),
                    Block("risk-kpis", "metrics", "report.metrics", 8, metricKeys:
                        ["defenseScore", "critical", "high", "openIncidents", "incidents", "threatCampaigns", "assets", "onlineAgents"]),
                    Block("severity", "severity", "report.severityCounts", 4, width: "half", style: "accent"),
                    Block("sources", "topSources", "report.topSourceIps", 10, width: "half"),
                    Block("incidents", "incidents", "report.priorityIncidents", 20),
                    Block("recommendations", "recommendations", "report.recommendations", 10)
                ],
                CreatedAtUtc = created,
                UpdatedAtUtc = created
            },
            new ReportTemplateDefinition
            {
                TemplateId = "builtin-client-review",
                TenantId = tenantId,
                Name = "Client & Compliance Review",
                Description = "Formal customer review with control coverage and remediation priorities.",
                IsBuiltIn = true,
                Theme = new ReportTemplateTheme
                {
                    Preset = "classic",
                    PrimaryColor = "#6B4F00",
                    AccentColor = "#8B5CF6",
                    BackgroundColor = "#FFF9E5",
                    TextColor = "#252C38",
                    FontFamily = "georgia"
                },
                Page = new ReportTemplatePage { Margin = "spacious" },
                Blocks =
                [
                    Block("identity", "header", "report.identity", 1, style: "plain"),
                    Block("service-kpis", "metrics", "report.metrics", 8, metricKeys:
                        ["agents", "onlineAgents", "assets", "threatEvents", "incidents", "openIncidents", "critical", "defenseScore"]),
                    Block("severity", "severity", "report.severityCounts", 4, width: "half"),
                    Block("recommendations", "recommendations", "report.recommendations", 10, width: "half"),
                    Block("incidents", "incidents", "report.priorityIncidents", 10),
                    Block("coverage", "coverage", "report.coverage", 1, style: "plain")
                ],
                CreatedAtUtc = created,
                UpdatedAtUtc = created
            }
        ];
    }

    private static ReportTemplateBlock Block(
        string blockId,
        string type,
        string? source,
        int limit,
        string width = "full",
        string style = "card",
        List<string>? metricKeys = null) => new()
    {
        BlockId = blockId,
        Type = type,
        DataSourceId = source,
        Limit = limit,
        Width = width,
        Style = style,
        MetricKeys = metricKeys ?? []
    };

    private static ReportTemplateDataSource Source(
        string id,
        string label,
        string description,
        string category,
        string blockType,
        int maxLimit,
        List<string>? metricKeys = null) => new()
    {
        DataSourceId = id,
        Label = label,
        Description = description,
        Category = category,
        AllowedBlockTypes = [blockType],
        MaxLimit = maxLimit,
        MetricKeys = metricKeys ?? []
    };
}
