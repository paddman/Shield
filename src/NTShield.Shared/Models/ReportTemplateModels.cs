namespace NTShield.Shared.Models;

/// <summary>
/// Declarative report layout. It intentionally has no raw HTML, script, CSS,
/// query, expression, or URL fields.
/// </summary>
public sealed class ReportTemplateDefinition
{
    public string TemplateId { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsBuiltIn { get; set; }
    public int Version { get; set; } = 1;
    public ReportTemplateTheme Theme { get; set; } = new();
    public ReportTemplatePage Page { get; set; } = new();
    public List<ReportTemplateBlock> Blocks { get; set; } = [];
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ReportTemplateTheme
{
    public string Preset { get; set; } = "executive";
    public string PrimaryColor { get; set; } = "#18202B";
    public string AccentColor { get; set; } = "#EFB900";
    public string BackgroundColor { get; set; } = "#FFFFFF";
    public string TextColor { get; set; } = "#252C38";
    public string FontFamily { get; set; } = "system";
}

public sealed class ReportTemplatePage
{
    public string Size { get; set; } = "a4";
    public string Orientation { get; set; } = "portrait";
    public string Margin { get; set; } = "normal";
    public int Columns { get; set; } = 1;
    public string Density { get; set; } = "comfortable";
    public bool ShowHeader { get; set; } = true;
    public bool ShowFooter { get; set; } = true;
}

public sealed class ReportTemplateBlock
{
    public string BlockId { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string? DataSourceId { get; set; }
    public string? Title { get; set; }
    public string Width { get; set; } = "full";
    public string Style { get; set; } = "default";
    public int Limit { get; set; } = 10;
    public bool Visible { get; set; } = true;
    public bool PageBreakBefore { get; set; }
    public List<string> MetricKeys { get; set; } = [];
    /// <summary>Plain text only; always HTML-encoded by the renderer.</summary>
    public string? Text { get; set; }
}

public sealed class ReportTemplateDataSource
{
    public string DataSourceId { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = "report";
    public List<string> AllowedBlockTypes { get; set; } = [];
    public int MaxLimit { get; set; }
    public List<string> MetricKeys { get; set; } = [];
}

public sealed class DuplicateReportTemplateRequest
{
    public string? Name { get; set; }
}
