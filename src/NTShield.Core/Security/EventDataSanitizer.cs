using System.Text;
using System.Text.RegularExpressions;

namespace NTShield.Core.Security;

/// <summary>
/// Sanitizes event/log payloads so password/credential material is never written or transmitted.
/// </summary>
public static partial class EventDataSanitizer
{
    private static readonly Regex SensitiveKeyValue = SensitiveKeyValueRegex();
    private static readonly Regex PasswordInXml = PasswordInXmlRegex();

    public static string SanitizeForLog(string? input, int maxLength = 4096)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var s = SensitiveKeyValue.Replace(input, "$1=***REDACTED***");
        s = PasswordInXml.Replace(s, "<$1>***REDACTED***</$1>");
        s = s.Replace('\0', ' ');

        if (s.Length > maxLength)
        {
            s = s[..maxLength] + "…[truncated]";
        }

        return s;
    }

    public static string SanitizeXml(string? rawXml, int maxLength = 256_000)
    {
        if (string.IsNullOrEmpty(rawXml))
        {
            return string.Empty;
        }

        // Never ship cleartext credential fields if present in custom providers.
        var s = PasswordInXml.Replace(rawXml, "<$1>***REDACTED***</$1>");
        s = SensitiveKeyValue.Replace(s, "$1=***REDACTED***");
        if (s.Length > maxLength)
        {
            s = s[..maxLength];
        }

        return s;
    }

    public static string SafePath(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative))
        {
            throw new ArgumentException("Path is empty.", nameof(relative));
        }

        // Block path traversal.
        if (relative.Contains("..", StringComparison.Ordinal) ||
            relative.Contains(':', StringComparison.Ordinal) ||
            Path.IsPathRooted(relative))
        {
            throw new InvalidOperationException("Path traversal or absolute path rejected.");
        }

        var fullRoot = Path.GetFullPath(root);
        var combined = Path.GetFullPath(Path.Combine(fullRoot, relative));
        if (!combined.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Resolved path escapes root.");
        }

        return combined;
    }

    public static bool IsAllowlistedCommand(string actionType) =>
        AllowedResponseCommands.Contains(actionType);

    public static readonly HashSet<string> AllowedResponseCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "BlockDestinationIp",
        "BlockSourceIp",
        "BlockRemoteIp",
        "BlockPort",
        "OpenPort",
        "ClosePort",
        "RemoveFirewallBlock",
        "StopService",
        "StartService",
        "RestartService",
        "ReloadService",
        "ReloadNginx",
        "DisableService",
        "EnableService",
        "StopScheduledTask",
        "DisableScheduledTask",
        "TerminateProcess",
        "RestartDockerContainer",
        "StopDockerContainer",
        "StartDockerContainer",
        "DockerRestart",
        "VacuumJournal",
        "CollectDiagnostics",
        "ExportEvidence",
        "ScanFile",
        "ScanPath",
        "QuarantineFile",
        "RestoreQuarantinedFile",
        "QuarantineHost",
        "LogOnly"
    };

    [GeneratedRegex(@"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)\s*[:=]\s*([^\s;,""']+)", RegexOptions.Compiled)]
    private static partial Regex SensitiveKeyValueRegex();

    [GeneratedRegex(@"<(?<tag>Password|Passwd|Credentials?|Secret|Token)[^>]*>.*?</\k<tag>>", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline)]
    private static partial Regex PasswordInXmlRegex();
}
