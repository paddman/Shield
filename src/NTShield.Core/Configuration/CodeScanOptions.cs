namespace NTShield.Core.Configuration;

public sealed class CodeScanOptions
{
    public const string SectionName = "CodeScan";

    public bool Enabled { get; set; }
    public bool AutoDiscoverWebRoots { get; set; } = true;
    public int IntervalHours { get; set; } = 6;
    public int MaxProjectsPerRun { get; set; } = 12;
    public int MaxAutoDiscoveredRoots { get; set; } = 12;
    public int MaxDiscoveryDepth { get; set; } = 4;
    public int MaxFilesPerProject { get; set; } = 20_000;
    public int MaxFileBytes { get; set; } = 1_000_000;
    public int MaxFindingsPerProject { get; set; } = 500;
    public bool IncludeSnippets { get; set; } = true;

    /// <summary>Brain service endpoint; Brain then uses the configured Central LLM Gateway.</summary>
    public string BrainUrl { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;

    public List<string> Paths { get; set; } = [];
    public List<string> DiscoveryBasePaths { get; set; } =
    [
        @"C:\inetpub",
        @"C:\Web",
        @"C:\Sites"
    ];

    public List<string> ExcludeDirectories { get; set; } =
    [
        ".git", ".svn", "node_modules", "vendor", "bin", "obj", ".venv", "venv",
        "dist", "build", "coverage", "cache", "tmp", "temp", "logs", "uploads",
        @"wwwroot\uploads", "App_Data"
    ];

    public List<string> Extensions { get; set; } =
    [
        ".cs", ".cshtml", ".js", ".jsx", ".ts", ".tsx", ".php", ".py", ".java",
        ".go", ".rb", ".json", ".xml", ".yml", ".yaml", ".config", ".ini", ".toml",
        ".sql", ".html", ".htm", ".vue", ".svelte", ".properties", ".lock"
    ];
}
