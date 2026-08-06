using System.Text;
using Microsoft.Extensions.Logging;

namespace NTShield.Agent.Linux.Collectors;

/// <summary>
/// Tail multiple log files (nginx, PHP, Docker, Node, syslog, auth, …).
/// Tracks byte offsets; handles rotation (inode/size shrink).
/// </summary>
internal sealed class LogFileTailer
{
    private readonly ILogger _logger;
    private readonly Dictionary<string, TailState> _states = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public LogFileTailer(ILogger logger) => _logger = logger;

    public IReadOnlyList<LogLine> ReadNewLines(IEnumerable<string> paths, int maxLinesPerFile = 200)
    {
        var results = new List<LogLine>();
        foreach (var path in ExpandPaths(paths))
        {
            try
            {
                results.AddRange(ReadFile(path, maxLinesPerFile));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Log tail failed for {Path}", path);
            }
        }

        return results;
    }

    private IEnumerable<LogLine> ReadFile(string path, int maxLines)
    {
        if (!File.Exists(path))
            yield break;

        var info = new FileInfo(path);
        long length = info.Length;
        long offset;
        lock (_gate)
        {
            if (!_states.TryGetValue(path, out var st))
            {
                // First open: start near end to avoid replaying huge history
                offset = Math.Max(0, length - 256 * 1024);
                _states[path] = new TailState { Offset = offset, Length = length };
            }
            else
            {
                // Rotation: file smaller than last known length
                if (length < st.Length || length < st.Offset)
                    st.Offset = 0;
                offset = st.Offset;
                st.Length = length;
            }
        }

        if (offset >= length)
            yield break;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        fs.Seek(offset, SeekOrigin.Begin);
        using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 64 * 1024, leaveOpen: false);

        var channel = InferChannel(path);
        var count = 0;
        string? line;
        while (count < maxLines && (line = reader.ReadLine()) is not null)
        {
            count++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            yield return new LogLine
            {
                Path = path,
                Channel = channel,
                Line = line.Length > 8000 ? line[..8000] : line,
                TimestampUtc = DateTimeOffset.UtcNow
            };
        }

        lock (_gate)
        {
            _states[path] = new TailState { Offset = fs.Position, Length = length };
        }
    }

    private static IEnumerable<string> ExpandPaths(IEnumerable<string> patterns)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in patterns)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var pattern = raw.Trim().Replace('\\', '/');

            if (pattern.Contains('*') || pattern.Contains('?'))
            {
                foreach (var f in ExpandGlob(pattern))
                {
                    if (seen.Add(f)) yield return f;
                }

                continue;
            }

            if (seen.Add(pattern))
                yield return pattern;
        }
    }

    /// <summary>Expand simple globs including one intermediate dir segment (e.g. containers/*/*-json.log).</summary>
    private static IEnumerable<string> ExpandGlob(string pattern)
    {
        // Special-case docker json logs
        if (pattern.Contains("/var/lib/docker/containers/", StringComparison.Ordinal) &&
            pattern.Contains("*-json.log", StringComparison.Ordinal))
        {
            const string root = "/var/lib/docker/containers";
            if (!Directory.Exists(root)) yield break;
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*-json.log", SearchOption.AllDirectories);
            }
            catch
            {
                yield break;
            }

            foreach (var f in files.Take(80))
                yield return f;
            yield break;
        }

        // home/*/.pm2/logs/*.log
        if (pattern.Contains("/home/", StringComparison.Ordinal) && pattern.Contains(".pm2", StringComparison.Ordinal))
        {
            const string home = "/home";
            if (!Directory.Exists(home)) yield break;
            foreach (var userDir in Directory.EnumerateDirectories(home).Take(50))
            {
                var logDir = Path.Combine(userDir, ".pm2", "logs");
                if (!Directory.Exists(logDir)) continue;
                foreach (var f in Directory.EnumerateFiles(logDir, "*.log").Take(40))
                    yield return f;
            }

            yield break;
        }

        // Single-directory globs: /var/log/nginx/*.log or /var/log/php*-fpm.log
        var dir = Path.GetDirectoryName(pattern)?.Replace('\\', '/');
        var filePat = Path.GetFileName(pattern);
        if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(filePat))
            yield break;

        // Parent may also contain wildcards (php*)
        if (dir.Contains('*') || dir.Contains('?'))
        {
            var parent = Path.GetDirectoryName(dir);
            var dirPat = Path.GetFileName(dir);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) yield break;
            foreach (var sub in Directory.EnumerateDirectories(parent, dirPat))
            {
                if (!Directory.Exists(sub)) continue;
                foreach (var f in SafeEnumFiles(sub, filePat))
                    yield return f;
            }

            yield break;
        }

        if (!Directory.Exists(dir)) yield break;
        foreach (var f in SafeEnumFiles(dir, filePat))
            yield return f;
    }

    private static IEnumerable<string> SafeEnumFiles(string dir, string filePat)
    {
        try
        {
            return Directory.EnumerateFiles(dir, filePat).Take(100).ToList();
        }
        catch
        {
            return [];
        }
    }

    internal static string InferChannel(string path)
    {
        var p = path.Replace('\\', '/').ToLowerInvariant();
        if (p.Contains("/nginx")) return "nginx";
        if (p.Contains("/apache") || p.Contains("httpd")) return "apache";
        if (p.Contains("php") || p.Contains("fpm")) return "php";
        if (p.Contains("docker") || p.Contains("containerd")) return "docker";
        if (p.Contains("node") || p.Contains("pm2") || p.EndsWith(".out.log") || p.EndsWith(".error.log"))
            return "nodejs";
        if (p.Contains("mysql") || p.Contains("mariadb")) return "mysql";
        if (p.Contains("postgres")) return "postgres";
        if (p.Contains("redis")) return "redis";
        if (p.Contains("auth.log") || p.Contains("secure")) return "auth";
        if (p.Contains("syslog") || p.Contains("messages")) return "syslog";
        if (p.Contains("fail2ban")) return "fail2ban";
        if (p.Contains("caddy")) return "caddy";
        if (p.Contains("traefik")) return "traefik";
        return "logfile";
    }

    private sealed class TailState
    {
        public long Offset;
        public long Length;
    }
}

internal sealed class LogLine
{
    public string Path { get; set; } = "";
    public string Channel { get; set; } = "";
    public string Line { get; set; } = "";
    public DateTimeOffset TimestampUtc { get; set; }
}
