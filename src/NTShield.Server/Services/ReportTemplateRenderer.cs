using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using NTShield.Shared.Models;

namespace NTShield.Server.Services;

internal static class ReportTemplateRenderer
{
    private static readonly Regex SafeColorPattern = new(
        "^#[0-9a-fA-F]{6}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string Render(SecurityReportRecord report)
    {
        var template = report.TemplateSnapshot!;
        var theme = template.Theme ?? new ReportTemplateTheme();
        var page = template.Page ?? new ReportTemplatePage();
        var primary = SafeColor(theme.PrimaryColor, "#252C38");
        var accent = SafeColor(theme.AccentColor, "#EFB900");
        var background = SafeColor(theme.BackgroundColor, "#FFFFFF");
        var text = SafeColor(theme.TextColor, "#252C38");
        var darkBackground = IsDark(background);
        var surface = darkBackground ? "#1F2937" : "#FFFFFF";
        var muted = darkBackground ? "#CBD5E1" : "#687386";
        var border = darkBackground ? "#475569" : "#D9DEE7";
        var chromeText = RelativeLuminance(primary) > .179 ? "#111827" : "#FFFFFF";
        var heading = ReadableAcrossSurfaces(primary, text, background, surface);
        var font = SafeFont(theme.FontFamily);
        var pageSize = string.Equals(page.Size, "letter", StringComparison.OrdinalIgnoreCase) ? "Letter" : "A4";
        var orientation = string.Equals(page.Orientation, "landscape", StringComparison.OrdinalIgnoreCase)
            ? "landscape"
            : "portrait";
        var margin = page.Margin?.ToLowerInvariant() switch
        {
            "compact" => "9mm",
            "spacious" => "20mm",
            _ => "14mm"
        };
        var gap = string.Equals(page.Density, "compact", StringComparison.OrdinalIgnoreCase) ? "8px" : "14px";
        var padding = string.Equals(page.Density, "compact", StringComparison.OrdinalIgnoreCase) ? "10px" : "14px";
        var columnsClass = page.Columns == 2 ? "columns-2" : "columns-1";

        var blocks = new List<string>();
        foreach (var block in (template.Blocks ?? []).Where(item => item is not null && item.Visible).Take(24))
        {
            var content = RenderBlock(report, block);
            if (content is null) continue;
            var width = block.Width?.ToLowerInvariant() switch
            {
                "half" => "span-half",
                "third" => "span-third",
                _ => "span-full"
            };
            var style = block.Style?.ToLowerInvariant() switch
            {
                "plain" => "style-plain",
                "accent" => "style-accent",
                "card" => "style-card",
                _ => "style-default"
            };
            var breakClass = block.PageBreakBefore ? " page-break" : string.Empty;
            blocks.Add($"<section class=\"report-block {width} {style}{breakClass}\">{content}</section>");
        }

        var footer = page.ShowFooter
            ? $"<footer>Generated {report.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC · Report {E(report.ReportId)}</footer>"
            : string.Empty;
        var chrome = page.ShowHeader
            ? "<div class=\"report-chrome\"><span>NT SHIELD</span><small>SECURITY REPORT</small></div>"
            : string.Empty;
        var styleSheet = $$$"""
            <style>
            :root{--primary:{{{primary}}};--accent:{{{accent}}};--background:{{{background}}};--surface:{{{surface}}};--text:{{{text}}};--heading:{{{heading}}};--muted:{{{muted}}};--border:{{{border}}};--chrome-text:{{{chromeText}}}}
            @page{size:{{{pageSize}}} {{{orientation}}};margin:{{{margin}}}}
            *{box-sizing:border-box}body{font:14px/1.5 {{{font}}};color:var(--text);background:var(--background);margin:{{{margin}}}}
            .report-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:{{{gap}}};align-items:start}
            .report-chrome{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;background:var(--primary);color:var(--chrome-text);border-bottom:4px solid var(--accent);font-weight:800;letter-spacing:.12em}.report-chrome small{opacity:.72}
            .span-full{grid-column:span 6}.columns-2 .span-half{grid-column:span 3}.columns-2 .span-third{grid-column:span 2}
            .columns-1 .span-half,.columns-1 .span-third{grid-column:span 6}
            .report-block{min-width:0;padding:{{{padding}}}}.style-card,.style-accent{border:1px solid var(--border);border-radius:10px;background:var(--surface)}
            .style-accent{border-top:4px solid var(--accent)}.style-plain{padding-inline:0}.page-break{break-before:page}
            header{border-bottom:3px solid var(--accent);padding-bottom:14px}header h1{margin:2px 0;color:var(--heading)}header p{margin:5px 0;color:var(--muted)}
            h2{margin:0 0 9px;color:var(--heading);font-size:17px}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:8px}
            .metric{border:1px solid var(--border);border-radius:8px;padding:9px;background:var(--surface)}.metric small,.metric b{display:block}.metric small{color:var(--muted)}.metric b{font-size:22px;color:var(--heading)}
            table{width:100%;border-collapse:collapse;font-size:12px;background:var(--surface)}th,td{padding:7px;border-bottom:1px solid var(--border);text-align:left;overflow-wrap:anywhere}
            ul,ol{margin:0;padding-left:20px}.ranked{padding:0;list-style:none}.ranked li,.severity li{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid var(--border)}
            .severity{padding:0;list-style:none}.plain-text{white-space:pre-line;overflow-wrap:anywhere}.coverage{color:var(--muted)}hr{border:0;border-top:1px solid var(--border)}footer{margin-top:24px;color:var(--muted);font-size:11px}
            @media(max-width:760px){.report-grid{display:block}.report-block{margin-bottom:10px}}@media print{body{margin:0}.report-block{break-inside:avoid}}
            </style>
            """;
        return $"""
            <!doctype html><html lang="th"><head><meta charset="utf-8"><title>{E(report.Title)}</title>{styleSheet}</head>
            <body class="{columnsClass}">{chrome}<main class="report-grid">{string.Join(string.Empty, blocks)}</main>{footer}</body></html>
            """;
    }

    private static string? RenderBlock(SecurityReportRecord report, ReportTemplateBlock block)
    {
        var limit = Math.Clamp(block.Limit, 1, 100);
        return block.Type?.ToLowerInvariant() switch
        {
            "header" => RenderHeader(report),
            "metrics" => RenderMetrics(report, block, limit),
            "severity" => RenderSeverity(report, block),
            "incidents" => RenderIncidents(report, block, limit),
            "topsources" => RenderRanked(block, report.TopSourceIps, "Top source IPs", limit),
            "topevents" => RenderRanked(block, report.TopEventIds, "Top event IDs", limit),
            "recommendations" => RenderRecommendations(report, block, limit),
            "coverage" => $"<h2>{Title(block, "Coverage")}</h2><p class=\"coverage\">{E(report.CoverageNote)}</p>",
            "divider" => "<hr>",
            "text" => $"<h2>{Title(block, "Notes")}</h2><p class=\"plain-text\">{E(Bound(block.Text, 2_000))}</p>",
            _ => null
        };
    }

    private static string RenderHeader(SecurityReportRecord report) =>
        $"<header class=\"report-identity\"><h1>{E(report.Title)}</h1>" +
        $"<p>{E(report.CustomerName)} · {report.PeriodStartUtc:yyyy-MM-dd} – {report.PeriodEndUtc:yyyy-MM-dd} UTC</p></header>";

    private static string RenderMetrics(SecurityReportRecord report, ReportTemplateBlock block, int limit)
    {
        var keys = block.MetricKeys is { Count: > 0 }
            ? block.MetricKeys
            : ["threatEvents", "incidents", "threatCampaigns", "defenseScore", "onlineAgents", "assets"];
        var items = keys.Take(limit).Select(key => Metric(report, key)).Where(item => item is not null)
            .Select(item => $"<div class=\"metric\"><small>{E(item!.Value.Label)}</small><b>{E(item.Value.Value)}</b></div>");
        return $"<h2>{Title(block, "Security metrics")}</h2><div class=\"metrics\">{string.Join(string.Empty, items)}</div>";
    }

    private static (string Label, string Value)? Metric(SecurityReportRecord report, string key) =>
        key.ToLowerInvariant() switch
        {
            "agents" => ("Agents", N(report.Metrics.Agents)),
            "onlineagents" => ("Agents online", $"{N(report.Metrics.OnlineAgents)}/{N(report.Metrics.Agents)}"),
            "assets" => ("Assets", N(report.Metrics.Assets)),
            "threatevents" => ("Threat events", N(report.Metrics.ThreatEvents)),
            "incidents" => ("Incidents", N(report.Metrics.Incidents)),
            "openincidents" => ("Open incidents", N(report.Metrics.OpenIncidents)),
            "threatcampaigns" => ("Threat campaigns", N(report.Metrics.ThreatCampaigns)),
            "defensescore" => ("Defense score", $"{report.Metrics.DefenseScore}%"),
            "critical" => ("Critical", N(report.SeverityCounts.GetValueOrDefault("critical"))),
            "high" => ("High", N(report.SeverityCounts.GetValueOrDefault("high"))),
            "medium" => ("Medium", N(report.SeverityCounts.GetValueOrDefault("medium"))),
            "low" => ("Low", N(report.SeverityCounts.GetValueOrDefault("low"))),
            _ => null
        };

    private static string RenderSeverity(SecurityReportRecord report, ReportTemplateBlock block)
    {
        var rows = new[] { "critical", "high", "medium", "low" }.Select(key =>
            $"<li><span>{E(CultureInfo.InvariantCulture.TextInfo.ToTitleCase(key))}</span><b>{N(report.SeverityCounts.GetValueOrDefault(key))}</b></li>");
        return $"<h2>{Title(block, "Severity")}</h2><ul class=\"severity\">{string.Join(string.Empty, rows)}</ul>";
    }

    private static string RenderIncidents(SecurityReportRecord report, ReportTemplateBlock block, int limit)
    {
        var rows = report.PriorityIncidents.Take(limit).Select(item =>
            $"<tr><td>{E(item.Severity.ToString())}</td><td>{E(item.Title)}</td><td>{E(item.SourceIp)}</td>" +
            $"<td>{E(item.DestinationIp)}</td><td>{E(item.Status)}</td><td>{item.LastSeenUtc:yyyy-MM-dd HH:mm} UTC</td></tr>");
        return $"<h2>{Title(block, "Priority incidents")}</h2><table><thead><tr><th>Severity</th><th>Incident</th>" +
               $"<th>Source</th><th>Destination</th><th>Status</th><th>Last seen</th></tr></thead><tbody>{string.Join(string.Empty, rows)}</tbody></table>";
    }

    private static string RenderRanked(
        ReportTemplateBlock block,
        IEnumerable<SecurityReportCountItem> values,
        string defaultTitle,
        int limit)
    {
        var rows = values.Take(limit).Select(item => $"<li><code>{E(item.Value)}</code><b>{N(item.Count)}</b></li>");
        return $"<h2>{Title(block, defaultTitle)}</h2><ul class=\"ranked\">{string.Join(string.Empty, rows)}</ul>";
    }

    private static string RenderRecommendations(SecurityReportRecord report, ReportTemplateBlock block, int limit)
    {
        var rows = report.Recommendations.Take(limit).Select(item => $"<li>{E(item)}</li>");
        return $"<h2>{Title(block, "Recommendations")}</h2><ol>{string.Join(string.Empty, rows)}</ol>";
    }

    private static string Title(ReportTemplateBlock block, string fallback) =>
        E(string.IsNullOrWhiteSpace(block.Title) ? fallback : Bound(block.Title, 120));

    private static string Bound(string? value, int length)
    {
        value ??= string.Empty;
        return value.Length <= length ? value : value[..length];
    }

    private static string SafeColor(string? value, string fallback) =>
        !string.IsNullOrWhiteSpace(value) && SafeColorPattern.IsMatch(value) ? value : fallback;

    private static bool IsDark(string color) => RelativeLuminance(color) < .35;

    private static string ReadableAcrossSurfaces(
        string preferred,
        string fallback,
        string background,
        string surface)
    {
        static double MinimumContrast(string foreground, string first, string second) =>
            Math.Min(ContrastRatio(foreground, first), ContrastRatio(foreground, second));

        if (MinimumContrast(preferred, background, surface) >= 4.5) return preferred;
        if (MinimumContrast(fallback, background, surface) >= 4.5) return fallback;
        return new[] { "#111827", "#FFFFFF" }
            .OrderByDescending(candidate => MinimumContrast(candidate, background, surface))
            .First();
    }

    private static double ContrastRatio(string first, string second)
    {
        var firstLuminance = RelativeLuminance(first);
        var secondLuminance = RelativeLuminance(second);
        return (Math.Max(firstLuminance, secondLuminance) + .05) /
               (Math.Min(firstLuminance, secondLuminance) + .05);
    }

    private static double RelativeLuminance(string color)
    {
        static double Linear(byte component)
        {
            var value = component / 255d;
            return value <= .04045 ? value / 12.92 : Math.Pow((value + .055) / 1.055, 2.4);
        }

        var red = Convert.ToByte(color.Substring(1, 2), 16);
        var green = Convert.ToByte(color.Substring(3, 2), 16);
        var blue = Convert.ToByte(color.Substring(5, 2), 16);
        return (.2126 * Linear(red)) + (.7152 * Linear(green)) + (.0722 * Linear(blue));
    }

    private static string SafeFont(string? value) => value?.ToLowerInvariant() switch
    {
        "arial" => "Arial,sans-serif",
        "georgia" => "Georgia,serif",
        "mono" => "ui-monospace,SFMono-Regular,Consolas,monospace",
        _ => "system-ui,-apple-system,Segoe UI,Arial,sans-serif"
    };

    private static string N(long value) => value.ToString("N0", CultureInfo.InvariantCulture);
    private static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
