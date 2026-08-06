using System.Text.RegularExpressions;
using NTShield.Agent.Linux.Collectors;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Agent.Linux.Detection;

/// <summary>
/// Pattern-based analysis for nginx / PHP / Docker / Node / auth / generic Linux logs.
/// Produces SecurityEventRecord + optional DetectionAlert for Central ingest.
/// </summary>
internal static partial class LinuxLogAnalyzer
{
    private static readonly (Regex Rx, string RuleId, string Title, Severity Sev, int EventId, bool SuggestRemediate)[] Rules =
    [
        // nginx / reverse proxy
        (NginxCritical(), "LNX_NGINX_CRIT", "Nginx critical/error", Severity.High, 9001, true),
        (NginxUpstream(), "LNX_NGINX_UPSTREAM", "Nginx upstream failure", Severity.High, 9002, true),
        (Http5xx(), "LNX_HTTP_5XX", "HTTP 5xx in access log", Severity.Medium, 9003, false),
        (WebShellProbe(), "LNX_WEB_SHELL_PROBE", "Web shell / RCE probe in URL", Severity.Critical, 9004, true),
        (SqlInjection(), "LNX_SQLi", "SQL injection pattern in request", Severity.High, 9005, false),
        (PathTraversal(), "LNX_PATH_TRAV", "Path traversal probe", Severity.High, 9006, false),

        // PHP
        (PhpFatal(), "LNX_PHP_FATAL", "PHP fatal / parse error", Severity.High, 9101, true),
        (PhpWarn(), "LNX_PHP_WARN", "PHP warning / notice flood signal", Severity.Low, 9102, false),

        // Docker
        (DockerOom(), "LNX_DOCKER_OOM", "Docker container OOM killed", Severity.Critical, 9201, true),
        (DockerExit(), "LNX_DOCKER_EXIT", "Docker container exited unexpectedly", Severity.High, 9202, true),
        (DockerError(), "LNX_DOCKER_ERR", "Docker daemon/container error", Severity.Medium, 9203, false),

        // Node.js
        (NodeCrash(), "LNX_NODE_CRASH", "Node.js crash / uncaught exception", Severity.High, 9301, true),
        (NodeOom(), "LNX_NODE_OOM", "Node.js out of memory", Severity.Critical, 9302, true),

        // Auth / SSH
        (SshFail(), "LNX_SSH_FAIL", "SSH authentication failure", Severity.Medium, 9401, false),
        (SshInvalidUser(), "LNX_SSH_INVALID", "SSH invalid user", Severity.Medium, 9402, false),
        (SudoFail(), "LNX_SUDO_FAIL", "sudo authentication failure", Severity.High, 9403, false),
        (RootLogin(), "LNX_ROOT_LOGIN", "Root login activity", Severity.High, 9404, false),

        // Disk / system
        (DiskFull(), "LNX_DISK_FULL", "No space left on device", Severity.Critical, 9501, true),
        (Segfault(), "LNX_SEGFAULT", "Process segfault", Severity.High, 9502, false),
        (KernelOom(), "LNX_KERNEL_OOM", "Kernel OOM killer", Severity.Critical, 9503, true),
    ];

    public sealed record AnalysisResult(
        SecurityEventRecord Event,
        DetectionAlert? Alert,
        string? SuggestedActionType,
        string? SuggestedService);

    public static AnalysisResult? Analyze(LogLine line, string agentId, string computerName)
    {
        foreach (var (rx, ruleId, title, sev, eventId, remediate) in Rules)
        {
            if (!rx.IsMatch(line.Line)) continue;

            var ev = new SecurityEventRecord
            {
                TimestampUtc = line.TimestampUtc,
                CollectedAtUtc = DateTimeOffset.UtcNow,
                ComputerName = computerName,
                AgentId = agentId,
                EventId = eventId,
                Channel = line.Channel,
                ProviderName = "NTShield.Linux.Log",
                Status = ruleId,
                SubStatus = title,
                ProcessPath = line.Path,
                RawXml = line.Line,
                SourceIp = TryExtractIp(line.Line)
            };

            DetectionAlert? alert = null;
            if (sev >= Severity.Medium)
            {
                alert = new DetectionAlert
                {
                    TimestampUtc = line.TimestampUtc,
                    ComputerName = computerName,
                    AgentId = agentId,
                    RuleId = ruleId,
                    RuleName = title,
                    Severity = sev,
                    Title = $"[{line.Channel}] {title}",
                    Description = Truncate(line.Line, 500),
                    SourceIp = ev.SourceIp,
                    EventCount = 1,
                    EvidenceJson = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        path = line.Path,
                        channel = line.Channel,
                        line = Truncate(line.Line, 1000)
                    })
                };
            }

            string? action = null;
            string? service = null;
            if (remediate)
            {
                (action, service) = SuggestRemediation(line.Channel, ruleId, line.Line);
            }

            return new AnalysisResult(ev, alert, action, service);
        }

        // Low-noise interesting lines: still ship as event without alert
        if (IsInterestingGeneric(line.Line))
        {
            return new AnalysisResult(
                new SecurityEventRecord
                {
                    TimestampUtc = line.TimestampUtc,
                    CollectedAtUtc = DateTimeOffset.UtcNow,
                    ComputerName = computerName,
                    AgentId = agentId,
                    EventId = 9999,
                    Channel = line.Channel,
                    ProviderName = "NTShield.Linux.Log",
                    Status = "LNX_LOG_INTEREST",
                    SubStatus = "Interesting log line",
                    ProcessPath = line.Path,
                    RawXml = Truncate(line.Line, 2000),
                    SourceIp = TryExtractIp(line.Line)
                },
                null,
                null,
                null);
        }

        return null;
    }

    private static (string? Action, string? Service) SuggestRemediation(string channel, string ruleId, string line)
    {
        return (channel, ruleId) switch
        {
            ("nginx", _) => ("RestartService", "nginx"),
            ("apache", _) => ("RestartService", "apache2"),
            ("php", _) => ("RestartService", DetectPhpFpmService()),
            ("docker", "LNX_DOCKER_OOM") => ("RestartDockerContainer", TryDockerName(line)),
            ("docker", "LNX_DOCKER_EXIT") => ("RestartDockerContainer", TryDockerName(line)),
            ("nodejs", _) => ("RestartService", "pm2"),
            (_, "LNX_DISK_FULL") => ("VacuumJournal", null),
            (_, "LNX_KERNEL_OOM") => ("LogOnly", null),
            _ => (null, null)
        };
    }

    private static string DetectPhpFpmService()
    {
        // Common package names; response executor tries candidates
        return "php-fpm";
    }

    private static string? TryDockerName(string line)
    {
        var m = DockerName().Match(line);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string? TryExtractIp(string line)
    {
        var m = Ipv4().Match(line);
        if (!m.Success) return null;
        var ip = m.Value;
        if (ip.StartsWith("127.") || ip == "0.0.0.0") return null;
        return ip;
    }

    private static bool IsInterestingGeneric(string line)
    {
        if (line.Length < 12) return false;
        return line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
               line.Contains("critical", StringComparison.OrdinalIgnoreCase) ||
               line.Contains("fatal", StringComparison.OrdinalIgnoreCase) ||
               line.Contains("panic", StringComparison.OrdinalIgnoreCase) ||
               line.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
               line.Contains("refused", StringComparison.OrdinalIgnoreCase);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    [GeneratedRegex(@"(?i)\b(emerg|alert|crit|\[error\]|\[crit\]|\[emerg\])\b", RegexOptions.Compiled)]
    private static partial Regex NginxCritical();

    [GeneratedRegex(@"(?i)(upstream timed out|no live upstreams|connect\(\) failed|Connection refused)", RegexOptions.Compiled)]
    private static partial Regex NginxUpstream();

    [GeneratedRegex(@"\s""(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s[^\""]*""\s5\d{2}\s", RegexOptions.Compiled)]
    private static partial Regex Http5xx();

    [GeneratedRegex(@"(?i)(\.php\?|\.asp|/wp-admin|/shell|/cmd=|/eval\(|base64_decode|passthru|system\()", RegexOptions.Compiled)]
    private static partial Regex WebShellProbe();

    [GeneratedRegex(@"(?i)(union\s+select|or\s+1=1|'?\s*or\s*'1'='1|sleep\(\d+\)|benchmark\()", RegexOptions.Compiled)]
    private static partial Regex SqlInjection();

    [GeneratedRegex(@"(?i)(\.\./\.\./|/etc/passwd|/proc/self)", RegexOptions.Compiled)]
    private static partial Regex PathTraversal();

    [GeneratedRegex(@"(?i)(PHP Fatal error|Parse error|Uncaught Error|Allowed memory size)", RegexOptions.Compiled)]
    private static partial Regex PhpFatal();

    [GeneratedRegex(@"(?i)(PHP Warning|PHP Notice)", RegexOptions.Compiled)]
    private static partial Regex PhpWarn();

    [GeneratedRegex(@"(?i)(oom-kill|Out of memory|killed process)", RegexOptions.Compiled)]
    private static partial Regex DockerOom();

    [GeneratedRegex(@"(?i)(exited with code [1-9]|container .+ died|restarting)", RegexOptions.Compiled)]
    private static partial Regex DockerExit();

    [GeneratedRegex(@"(?i)(level=error|error msg=)", RegexOptions.Compiled)]
    private static partial Regex DockerError();

    [GeneratedRegex(@"(?i)(uncaughtException|UnhandledPromiseRejection|FATAL ERROR)", RegexOptions.Compiled)]
    private static partial Regex NodeCrash();

    [GeneratedRegex(@"(?i)(JavaScript heap out of memory|allocation failed - JavaScript heap)", RegexOptions.Compiled)]
    private static partial Regex NodeOom();

    [GeneratedRegex(@"(?i)(Failed password|authentication failure|Invalid user)", RegexOptions.Compiled)]
    private static partial Regex SshFail();

    [GeneratedRegex(@"(?i)Invalid user\s+\S+", RegexOptions.Compiled)]
    private static partial Regex SshInvalidUser();

    [GeneratedRegex(@"(?i)sudo:.*(authentication failure|3 incorrect password)", RegexOptions.Compiled)]
    private static partial Regex SudoFail();

    [GeneratedRegex(@"(?i)(session opened for user root|Accepted .+ for root)", RegexOptions.Compiled)]
    private static partial Regex RootLogin();

    [GeneratedRegex(@"(?i)(No space left on device|ENOSPC)", RegexOptions.Compiled)]
    private static partial Regex DiskFull();

    [GeneratedRegex(@"(?i)segfault at", RegexOptions.Compiled)]
    private static partial Regex Segfault();

    [GeneratedRegex(@"(?i)Out of memory: Killed process", RegexOptions.Compiled)]
    private static partial Regex KernelOom();

    [GeneratedRegex(@"(?i)(?:container[= ]|/|name=)([a-zA-Z0-9][a-zA-Z0-9_.-]{1,64})", RegexOptions.Compiled)]
    private static partial Regex DockerName();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4();
}
