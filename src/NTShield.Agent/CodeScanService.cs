using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NTShield.Core.Configuration;

namespace NTShield.Agent;

public sealed record CodeScanRunResult(
    string Project,
    string Root,
    int FilesScanned,
    int FilesSkipped,
    int Findings,
    bool Sent,
    bool LlmUsed,
    string Verdict,
    string Model,
    string? Error);

/// <summary>
/// Bounded local source scanner for web projects. It produces sanitized findings
/// and sends only the report to Brain; it never executes or modifies source code.
/// </summary>
public sealed class CodeScanService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly HashSet<string> SpecialFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".env", ".env.local", ".env.production", "web.config", "appsettings.json",
        "appsettings.production.json", "dockerfile", "docker-compose.yml", "docker-compose.yaml"
    };

    private static readonly IReadOnlyList<ScanRule> Rules =
    [
        new(
            "SECRET.PRIVATE_KEY",
            "Private key material in source",
            "critical",
            "CWE-321",
            "A07:2021",
            ["*"],
            new Regex(@"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PRIVATE)\s+KEY-----", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["secret", "credential"]),
        new(
            "SECRET.HARDCODED",
            "Hard-coded credential or token",
            "high",
            "CWE-798",
            "A07:2021",
            ["*"],
            new Regex(@"\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token|private[_-]?key)\b\s*[:=]\s*(?:[""'][^""'\r\n]{8,}[""']|[A-Za-z0-9._~+/=-]{12,})", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["secret", "credential"]),
        new(
            "WEB.COMMAND_INJECTION",
            "User-controlled data may reach command execution",
            "high",
            "CWE-78",
            "A03:2021-Injection",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"\b(?:child_process\.(?:exec|execFile|spawn)|exec|system|shell_exec|passthru|popen|Process\.Start|Runtime\.getRuntime\(\)\.exec|subprocess\.(?:run|Popen|call))\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["command-injection", "rce"]),
        new(
            "WEB.SQL_INJECTION",
            "SQL query appears to be built from concatenated or formatted input",
            "high",
            "CWE-89",
            "A03:2021-Injection",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby", "sql"],
            new Regex(@"(?i)(?:select|insert|update|delete|from)\b.*(?:\+|\$\{|String\.Format|format\(|request\.|req\.|params\.|query\.)|(?:query|execute|raw|FromSqlRaw)\s*\([^\r\n]*(?:\+|request\.|req\.|params\.|query\.)", RegexOptions.Compiled),
            ["sql-injection", "injection"]),
        new(
            "WEB.PATH_TRAVERSAL",
            "File path uses request data without an evident containment check",
            "high",
            "CWE-22",
            "A01:2021-Broken-Access-Control",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"(?:\.\./|Path\.Combine|readFile|read_text|open\s*\(|include\s*\(|require\s*\()[^\r\n]*(?:req\.|request\.|query\.|params\.|filename|fileName|input|path)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["path-traversal", "file-access"]),
        new(
            "WEB.SSRF",
            "Outbound request target appears to include user-controlled input",
            "high",
            "CWE-918",
            "A10:2021-SSRF",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"(?:axios\.(?:get|post|request)|requests?\.(?:get|post|request)|httpx\.(?:get|post|request)|HttpClient.*(?:GetAsync|PostAsync|SendAsync)|urllib\.request)[^\r\n]*(?:req\.|request\.|query\.|params\.|url|uri|input)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["ssrf", "outbound-request"]),
        new(
            "WEB.UNSAFE_DESERIALIZATION",
            "Unsafe object deserialization API",
            "high",
            "CWE-502",
            "A08:2021-Software-Integrity",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"(?:pickle\.(?:load|loads)|yaml\.load\s*\(|unserialize\s*\(|BinaryFormatter|ObjectInputStream|TypeNameHandling|JsonConvert\.DeserializeObject)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["deserialization"]),
        new(
            "WEB.DYNAMIC_CODE_EXECUTION",
            "Dynamic code evaluation API",
            "high",
            "CWE-95",
            "A03:2021-Injection",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"\b(?:eval\s*\(|new\s+Function\s*\(|create_function\s*\(|exec\s*\()", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["dynamic-code", "rce"]),
        new(
            "WEB.XSS_SINK",
            "Potential user-controlled data reaches an HTML output sink",
            "medium",
            "CWE-79",
            "A03:2021-Injection",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby"],
            new Regex(@"(?:innerHTML\s*=|dangerouslySetInnerHTML|Html\.Raw\s*\(|MarkupString|res\.send\s*\([^\r\n]*(?:req\.|request\.|query\.|params\.))", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["xss", "output-encoding"]),
        new(
            "CONFIG.DEBUG_ENABLED",
            "Debug/development mode appears enabled in deployable configuration",
            "medium",
            "CWE-489",
            "A05:2021-Security-Misconfiguration",
            ["config"],
            new Regex(@"(?:\bdebug\b\s*[:=]\s*true|ASPNETCORE_ENVIRONMENT\s*[=:""']+Development|APP_ENV\s*[=:""']+dev)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["misconfiguration", "debug"]),
        new(
            "CRYPTO.WEAK_ALGORITHM",
            "Weak or obsolete cryptographic algorithm",
            "medium",
            "CWE-327",
            "A02:2021-Cryptographic-Failures",
            ["javascript", "typescript", "php", "python", "csharp", "java", "ruby", "config"],
            new Regex(@"\b(?:MD5|SHA-?1|DES|3DES|RC4|ECB)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["weak-crypto"])
    ];

    private readonly CodeScanOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<CodeScanService> _logger;
    private readonly HttpClient _http;

    public CodeScanService(
        IOptions<CodeScanOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<CodeScanService> logger,
        HttpClient http)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
        _http = http;
        _http.Timeout = TimeSpan.FromSeconds(90);
    }

    public async Task<IReadOnlyList<CodeScanRunResult>> RunAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return [];
        }

        var roots = DiscoverRoots()
            .Take(Math.Clamp(_options.MaxProjectsPerRun, 1, 100))
            .ToList();
        if (roots.Count == 0)
        {
            _logger.LogInformation("Code scan found no configured or auto-discovered web roots");
            return [];
        }

        var results = new List<CodeScanRunResult>();
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await ScanProjectAsync(root, cancellationToken));
        }

        return results;
    }

    private async Task<CodeScanRunResult> ScanProjectAsync(string root, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var project = ProjectName(root);
        var findings = new List<CodeScanFinding>();
        var languages = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var severityCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var filesScanned = 0;
        var filesSkipped = 0;
        var maxFiles = Math.Clamp(_options.MaxFilesPerProject, 1, 1_000_000);
        var maxFindings = Math.Clamp(_options.MaxFindingsPerProject, 1, 10_000);

        foreach (var path in EnumerateSourceFiles(root, maxFiles))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (filesScanned >= maxFiles)
            {
                filesSkipped++;
                continue;
            }

            try
            {
                var info = new FileInfo(path);
                if (info.Length > Math.Clamp(_options.MaxFileBytes, 4_096, 20_000_000))
                {
                    filesSkipped++;
                    continue;
                }

                var text = await File.ReadAllTextAsync(path, cancellationToken);
                var language = DetectLanguage(path);
                languages[language] = languages.GetValueOrDefault(language) + 1;
                filesScanned++;

                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                var fileFindings = ScanText(relative, language, text, maxFindings - findings.Count);
                foreach (var finding in fileFindings)
                {
                    findings.Add(finding);
                    severityCounts[finding.Severity] = severityCounts.GetValueOrDefault(finding.Severity) + 1;
                }
            }
            catch (UnauthorizedAccessException)
            {
                filesSkipped++;
            }
            catch (IOException)
            {
                filesSkipped++;
            }

            if (findings.Count >= maxFindings)
            {
                break;
            }
        }

        var finished = DateTimeOffset.UtcNow;
        var report = new CodeScanReport
        {
            SchemaVersion = "1.0",
            ScanId = $"cas-{Guid.NewGuid():N}",
            Scanner = new CodeScannerIdentity
            {
                Name = "NTShield Agent Code Scanner",
                Version = "1.0.0",
                Host = _agentOptions.ComputerName,
                Platform = "windows"
            },
            StartedAtUtc = started,
            FinishedAtUtc = finished,
            PrivacyMode = _options.IncludeSnippets ? "snippets" : "metadata",
            Project = new CodeScanProject
            {
                Name = project,
                Repository = string.Empty,
                Branch = string.Empty,
                Commit = string.Empty
            },
            Summary = new CodeScanSummary
            {
                FilesScanned = filesScanned,
                FilesSkipped = filesSkipped,
                FindingCount = findings.Count,
                SeverityCounts = severityCounts,
                Languages = languages
            },
            Findings = findings
        };

        var submit = await SubmitAsync(report, cancellationToken);
        _logger.LogInformation(
            "Code scan completed project={Project} files={Files} skipped={Skipped} findings={Findings} sent={Sent} verdict={Verdict} model={Model} llm={Llm}",
            project, filesScanned, filesSkipped, findings.Count, submit.Sent, submit.Verdict, submit.Model, submit.LlmUsed);

        return new CodeScanRunResult(
            project,
            root,
            filesScanned,
            filesSkipped,
            findings.Count,
            submit.Sent,
            submit.LlmUsed,
            submit.Verdict,
            submit.Model,
            submit.Error);
    }

    private async Task<SubmitResult> SubmitAsync(CodeScanReport report, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BrainUrl) ||
            string.IsNullOrWhiteSpace(_options.TenantId) ||
            string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            return new SubmitResult(false, false, "not_configured", "none", "code_scan_brain_not_configured");
        }

        if (!Uri.TryCreate(_options.BrainUrl.TrimEnd('/'), UriKind.Absolute, out var brainUri))
        {
            return new SubmitResult(false, false, "error", "none", "code_scan_brain_url_invalid");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(brainUri, "v1/code-scans/analyze"));
        request.Headers.TryAddWithoutValidation("X-NTShield-Tenant", _options.TenantId);
        request.Headers.TryAddWithoutValidation("X-NTShield-Api-Key", _options.ApiKey);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(report, JsonOptions),
            Encoding.UTF8,
            "application/json");

        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new SubmitResult(false, false, "error", "none", $"brain_http_{(int)response.StatusCode}: {body[..Math.Min(240, body.Length)]}");
            }

            var analysis = JsonSerializer.Deserialize<BrainAnalysisResponse>(body, JsonOptions);
            return new SubmitResult(
                true,
                analysis?.LlmUsed == true,
                analysis?.Verdict ?? "unknown",
                analysis?.Model ?? "unknown",
                null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new SubmitResult(false, false, "error", "none", ex.Message[..Math.Min(240, ex.Message.Length)]);
        }
    }

    private IReadOnlyList<string> DiscoverRoots()
    {
        var roots = new List<string>();
        foreach (var configured in _options.Paths ?? [])
        {
            AddRoot(roots, configured);
        }

        if (_options.AutoDiscoverWebRoots)
        {
            foreach (var basePath in _options.DiscoveryBasePaths ?? [])
            {
                var full = ExpandPath(basePath);
                if (!Directory.Exists(full)) continue;
                if (IsProjectRoot(full)) AddRoot(roots, full);

                foreach (var candidate in WalkDirectories(full, Math.Clamp(_options.MaxDiscoveryDepth, 1, 8)))
                {
                    if (IsProjectRoot(candidate)) AddRoot(roots, candidate);
                    if (roots.Count >= Math.Clamp(_options.MaxAutoDiscoveredRoots, 1, 100)) break;
                }

                if (roots.Count >= Math.Clamp(_options.MaxAutoDiscoveredRoots, 1, 100)) break;
            }
        }

        var normalizedRoots = roots
            .Select(ExpandPath)
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path.Length)
            .ToList();

        return normalizedRoots
            .Where(path => !normalizedRoots.Any(parent => parent != path && IsUnder(path, parent)))
            .Take(Math.Clamp(_options.MaxProjectsPerRun, 1, 100))
            .ToList();
    }

    private void AddRoot(List<string> roots, string path)
    {
        var full = ExpandPath(path);
        if (File.Exists(full)) full = Path.GetDirectoryName(full) ?? full;
        if (Directory.Exists(full) && !roots.Contains(full, StringComparer.OrdinalIgnoreCase)) roots.Add(full);
    }

    private IEnumerable<string> WalkDirectories(string root, int maxDepth)
    {
        var pending = new Stack<(string Path, int Depth)>();
        pending.Push((root, 0));
        while (pending.Count > 0)
        {
            var (path, depth) = pending.Pop();
            if (depth >= maxDepth) continue;
            IEnumerable<string> children;
            try { children = Directory.EnumerateDirectories(path, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var child in children)
            {
                if (IsExcludedDirectory(child)) continue;
                yield return child;
                try
                {
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0)
                        pending.Push((child, depth + 1));
                }
                catch { }
            }
        }
    }

    private IEnumerable<string> EnumerateSourceFiles(string root, int maxFiles)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        var count = 0;
        while (pending.Count > 0 && count < maxFiles)
        {
            var directory = pending.Pop();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var file in files)
            {
                if (IsScannableFile(file))
                {
                    yield return file;
                    if (++count >= maxFiles) yield break;
                }
            }

            IEnumerable<string> children;
            try { children = Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }
            foreach (var child in children)
            {
                if (IsExcludedDirectory(child)) continue;
                try
                {
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0)
                        pending.Push(child);
                }
                catch { }
            }
        }
    }

    private IReadOnlyList<CodeScanFinding> ScanText(string relativePath, string language, string text, int budget)
    {
        var findings = new List<CodeScanFinding>();
        var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        for (var index = 0; index < lines.Length && findings.Count < budget; index++)
        {
            var line = lines[index];
            if (string.IsNullOrWhiteSpace(line)) continue;
            foreach (var rule in Rules)
            {
                if (!rule.AppliesTo(language) || !rule.Pattern.IsMatch(line)) continue;
                var sanitized = Redact(line.Trim(), 1800);
                var confidence = rule.Id.StartsWith("SECRET.", StringComparison.OrdinalIgnoreCase)
                    ? 0.90
                    : ContainsUserInput(line) ? 0.84 : 0.66;
                findings.Add(new CodeScanFinding
                {
                    FindingId = $"caf-{Guid.NewGuid():N}",
                    RuleId = rule.Id,
                    Title = rule.Title,
                    Severity = rule.Severity,
                    Confidence = confidence,
                    Cwe = rule.Cwe,
                    Owasp = rule.Owasp,
                    Language = language,
                    Path = relativePath,
                    Line = index + 1,
                    Snippet = _options.IncludeSnippets ? sanitized : string.Empty,
                    Evidence = $"Static rule matched at {relativePath}:{index + 1}; confirm data flow and reachable authentication boundary.",
                    Tags = rule.Tags.ToList(),
                    Fingerprint = Fingerprint(rule.Id, relativePath, index + 1, line)
                });
                if (findings.Count >= budget) break;
            }
        }

        return findings;
    }

    private bool IsProjectRoot(string path)
    {
        string[] markers = ["web.config", "package.json", "composer.json", "requirements.txt", "pom.xml", "index.php", "server.js", "app.py"];
        if (markers.Any(marker => File.Exists(Path.Combine(path, marker)))) return true;
        try { return Directory.EnumerateFiles(path, "*.csproj", SearchOption.TopDirectoryOnly).Any(); }
        catch { return false; }
    }

    private bool IsScannableFile(string path)
    {
        var name = Path.GetFileName(path);
        if (SpecialFileNames.Contains(name)) return true;
        var extension = Path.GetExtension(path);
        return !string.IsNullOrWhiteSpace(extension) &&
               (_options.Extensions ?? []).Any(item => string.Equals(item, extension, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsExcludedDirectory(string path)
    {
        var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return (_options.ExcludeDirectories ?? []).Any(item =>
            string.Equals(item, name, StringComparison.OrdinalIgnoreCase) ||
            path.Replace('\\', '/').Contains(item.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase));
    }

    private static string DetectLanguage(string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        if (name is ".env" or ".env.local" or "web.config" || name.StartsWith("appsettings")) return "config";
        return Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".cs" or ".cshtml" => "csharp",
            ".js" or ".jsx" => "javascript",
            ".ts" or ".tsx" => "typescript",
            ".php" => "php",
            ".py" => "python",
            ".java" => "java",
            ".rb" => "ruby",
            ".go" => "go",
            ".sql" => "sql",
            _ => "config"
        };
    }

    private static string ExpandPath(string value) =>
        Path.GetFullPath(Environment.ExpandEnvironmentVariables(value.Trim()));

    private static bool IsUnder(string path, string parent)
    {
        var normalizedPath = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedParent = parent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return normalizedPath.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase);
    }

    private static string ProjectName(string root) =>
        Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        ?? root;

    private static bool ContainsUserInput(string line) =>
        Regex.IsMatch(line, @"(?i)(req\.|request\.|query\.|params\.|body\.|input|argv|filename|url|uri)");

    private static string Redact(string value, int maxLength)
    {
        var text = value;
        text = Regex.Replace(text, @"(?i)(bearer\s+)[A-Za-z0-9._-]+", "$1[REDACTED]");
        text = Regex.Replace(text, @"(?i)(password|passwd|secret|token|api[_-]?key|client[_-]?secret)\s*([:=])\s*([^,;\s]+)", "$1$2[REDACTED]");
        text = Regex.Replace(text, @"-----BEGIN\s+[^\r\n]+-----.*", "[REDACTED_PRIVATE_KEY_MATERIAL]");
        return text.Length <= maxLength ? text : text[..maxLength];
    }

    private static string Fingerprint(string ruleId, string path, int line, string content)
    {
        var raw = Encoding.UTF8.GetBytes($"{ruleId}|{path}|{line}|{content.Trim()}");
        return Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
    }

    private sealed record ScanRule(
        string Id,
        string Title,
        string Severity,
        string Cwe,
        string Owasp,
        string[] Languages,
        Regex Pattern,
        string[] Tags)
    {
        public bool AppliesTo(string language) => Languages.Contains("*", StringComparer.OrdinalIgnoreCase) || Languages.Contains(language, StringComparer.OrdinalIgnoreCase);
    }

    private sealed class CodeScanReport
    {
        public string SchemaVersion { get; set; } = "1.0";
        public string ScanId { get; set; } = string.Empty;
        public CodeScannerIdentity Scanner { get; set; } = new();
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset FinishedAtUtc { get; set; }
        public string PrivacyMode { get; set; } = "snippets";
        public CodeScanProject Project { get; set; } = new();
        public CodeScanSummary Summary { get; set; } = new();
        public List<CodeScanFinding> Findings { get; set; } = [];
        public List<string> Errors { get; set; } = [];
    }

    private sealed class CodeScannerIdentity
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string Platform { get; set; } = "windows";
    }

    private sealed class CodeScanProject
    {
        public string Name { get; set; } = string.Empty;
        public string Repository { get; set; } = string.Empty;
        public string Branch { get; set; } = string.Empty;
        public string Commit { get; set; } = string.Empty;
    }

    private sealed class CodeScanSummary
    {
        public int FilesScanned { get; set; }
        public int FilesSkipped { get; set; }
        public int FindingCount { get; set; }
        public Dictionary<string, int> SeverityCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Languages { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class CodeScanFinding
    {
        public string FindingId { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = "info";
        public double Confidence { get; set; }
        public string Cwe { get; set; } = string.Empty;
        public string Owasp { get; set; } = string.Empty;
        public string Language { get; set; } = "unknown";
        public string Path { get; set; } = string.Empty;
        public int Line { get; set; }
        public int Column { get; set; }
        public string Snippet { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = [];
        public string Fingerprint { get; set; } = string.Empty;
    }

    private sealed class BrainAnalysisResponse
    {
        public string Verdict { get; set; } = "unknown";
        public string Model { get; set; } = "unknown";
        public bool LlmUsed { get; set; }
    }

    private sealed record SubmitResult(bool Sent, bool LlmUsed, string Verdict, string Model, string? Error);
}
