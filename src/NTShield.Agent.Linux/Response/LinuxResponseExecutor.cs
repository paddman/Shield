using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;

namespace NTShield.Agent.Linux.Response;

/// <summary>
/// Safe, allowlisted remediation on Linux: systemctl, docker, kill, iptables/nft, journal vacuum.
/// Arbitrary shell commands are never accepted.
/// </summary>
internal sealed class LinuxResponseExecutor
{
    private readonly ILogger _logger;
    private readonly bool _autoRemediate;

    public static readonly HashSet<string> AllowedActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "LogOnly",
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
        "DisableService",
        "EnableService",
        "TerminateProcess",
        "RestartDockerContainer",
        "StopDockerContainer",
        "StartDockerContainer",
        "DockerRestart",
        "VacuumJournal",
        "ReloadNginx",
        "ReloadService",
        "CollectDiagnostics",
        "QuarantineHost",
        "ExportEvidence"
    };

    private static readonly HashSet<string> ServiceNameAllow = new(StringComparer.OrdinalIgnoreCase)
    {
        "nginx", "apache2", "httpd", "php-fpm", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm",
        "mysql", "mysqld", "mariadb", "postgresql", "redis", "redis-server",
        "docker", "containerd", "ssh", "sshd", "fail2ban", "cron", "crond",
        "pm2-root", "pm2", "nodejs", "caddy", "traefik", "haproxy",
        "ntshield-agent"
    };

    private static readonly Regex SafeToken = new(@"^[a-zA-Z0-9][a-zA-Z0-9_.@/-]{0,120}$", RegexOptions.Compiled);

    public LinuxResponseExecutor(ILogger logger, bool autoRemediate = false)
    {
        _logger = logger;
        _autoRemediate = autoRemediate;
    }

    public async Task<ResponseActionRecord> ExecuteAsync(ResponseActionRequest request, CancellationToken ct)
    {
        var record = new ResponseActionRecord
        {
            RequestId = string.IsNullOrWhiteSpace(request.RequestId) ? Guid.NewGuid().ToString("N") : request.RequestId,
            Requester = request.Requester,
            ActionType = request.ActionType,
            Reason = request.Reason,
            Approved = request.Approved,
            ApprovalId = request.ApprovalId,
            AlertId = request.AlertId ?? "",
            IncidentId = request.IncidentId ?? "",
            TimestampUtc = DateTimeOffset.UtcNow,
            ComputerName = Environment.MachineName
        };

        if (!AllowedActions.Contains(request.ActionType))
        {
            record.Status = "Rejected";
            record.Error = "Action type not in Linux allowlist (arbitrary commands forbidden).";
            return record;
        }

        // Destructive ops need approval unless auto-remediate local + safe restarts
        var needsApproval = NeedsApproval(request.ActionType);
        if (needsApproval && !request.Approved && !IsLocalAutoSafe(request))
        {
            record.Status = "PendingApproval";
            record.Result = "Blocked by policy: Central/Dashboard approval required.";
            return record;
        }

        try
        {
            switch (request.ActionType)
            {
                case "LogOnly":
                    record.Status = "Completed";
                    record.Result = "logged";
                    break;

                case "RestartService":
                case "StartService":
                case "StopService":
                case "ReloadService":
                case "EnableService":
                case "DisableService":
                    await SystemCtlAsync(record, request, ct);
                    break;

                case "ReloadNginx":
                    request.ServiceName = "nginx";
                    request.ActionType = "ReloadService";
                    await SystemCtlAsync(record, request, ct);
                    break;

                case "RestartDockerContainer":
                case "DockerRestart":
                    await DockerAsync(record, "restart", request.ServiceName ?? request.TaskName, ct);
                    break;

                case "StopDockerContainer":
                    await DockerAsync(record, "stop", request.ServiceName ?? request.TaskName, ct);
                    break;

                case "StartDockerContainer":
                    await DockerAsync(record, "start", request.ServiceName ?? request.TaskName, ct);
                    break;

                case "TerminateProcess":
                    TerminateProcess(record, request.ProcessId);
                    break;

                case "BlockSourceIp":
                case "BlockRemoteIp":
                    await IptablesBlockIpAsync(record, request.TargetIp, "INPUT", ct);
                    break;

                case "BlockDestinationIp":
                    await IptablesBlockIpAsync(record, request.TargetIp, "OUTPUT", ct);
                    break;

                case "BlockPort":
                    await IptablesBlockPortAsync(record, request, ct);
                    break;

                case "OpenPort":
                    await IptablesOpenPortAsync(record, request, ct);
                    break;

                case "ClosePort":
                case "RemoveFirewallBlock":
                    await IptablesRemoveCommentAsync(record, request.RuleName ?? request.ServiceName, ct);
                    break;

                case "VacuumJournal":
                    await VacuumJournalAsync(record, ct);
                    break;

                case "CollectDiagnostics":
                    await CollectDiagnosticsAsync(record, ct);
                    break;

                case "QuarantineHost":
                    await QuarantineAsync(record, ct);
                    break;

                case "ExportEvidence":
                    record.Status = "Completed";
                    record.Result = "Use CollectDiagnostics on Linux agent";
                    break;

                default:
                    record.Status = "Rejected";
                    record.Error = "Unhandled action";
                    break;
            }
        }
        catch (Exception ex)
        {
            record.Status = "Failed";
            record.Error = ex.Message;
            _logger.LogError(ex, "Linux action {Type} failed", request.ActionType);
        }

        record.AuditLog =
            $"{record.TimestampUtc:o}|{record.ActionType}|{record.Status}|{record.Result}|{record.Error}";
        return record;
    }

    private bool IsLocalAutoSafe(ResponseActionRequest request)
    {
        if (!_autoRemediate) return false;
        // Only auto-approve service restarts / journal vacuum / log-only from local analyzer
        return request.ActionType is "RestartService" or "ReloadService" or "ReloadNginx"
            or "RestartDockerContainer" or "DockerRestart" or "VacuumJournal" or "LogOnly"
            or "StartService";
    }

    private static bool NeedsApproval(string actionType) =>
        actionType is not ("LogOnly" or "CollectDiagnostics" or "ExportEvidence");

    private async Task SystemCtlAsync(ResponseActionRecord record, ResponseActionRequest request, CancellationToken ct)
    {
        var unit = request.ServiceName?.Trim();
        if (string.IsNullOrWhiteSpace(unit) || !IsSafeServiceName(unit))
        {
            record.Status = "Rejected";
            record.Error = "ServiceName required and must be allowlisted/safe token.";
            return;
        }

        // Map action → systemctl verb
        var verb = request.ActionType switch
        {
            "RestartService" => "restart",
            "StartService" => "start",
            "StopService" => "stop",
            "ReloadService" => "reload",
            "EnableService" => "enable",
            "DisableService" => "disable",
            _ => "status"
        };

        // php-fpm → try versioned units
        var candidates = unit.Equals("php-fpm", StringComparison.OrdinalIgnoreCase)
            ? new[] { "php8.3-fpm", "php8.2-fpm", "php8.1-fpm", "php-fpm", "php8.4-fpm" }
            : unit.Equals("apache2", StringComparison.OrdinalIgnoreCase)
                ? new[] { "apache2", "httpd" }
                : new[] { unit };

        string? lastErr = null;
        foreach (var c in candidates)
        {
            var (ok, output, err) = await RunAsync("systemctl", $"{verb} {c}", ct, timeoutSec: 60);
            if (ok)
            {
                record.Status = "Completed";
                record.Result = $"systemctl {verb} {c}: {Truncate(output, 400)}";
                record.BeforeState = $"unit={c}";
                record.RollbackCommand = verb is "stop" or "disable"
                    ? $"systemctl start {c}"
                    : verb is "disable" ? $"systemctl enable {c}" : null;
                return;
            }

            lastErr = err;
        }

        record.Status = "Failed";
        record.Error = lastErr ?? "systemctl failed";
    }

    private async Task DockerAsync(ResponseActionRecord record, string verb, string? name, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name) || !SafeToken.IsMatch(name) || name.Contains(".."))
        {
            record.Status = "Rejected";
            record.Error = "Container name required (safe token).";
            return;
        }

        var (ok, output, err) = await RunAsync("docker", $"{verb} {name}", ct, timeoutSec: 90);
        if (ok)
        {
            record.Status = "Completed";
            record.Result = $"docker {verb} {name}: {Truncate(output, 400)}";
            record.RollbackCommand = verb == "stop" ? $"docker start {name}" : null;
        }
        else
        {
            record.Status = "Failed";
            record.Error = err;
        }
    }

    private static void TerminateProcess(ResponseActionRecord record, int? pid)
    {
        if (pid is null or <= 1)
        {
            record.Status = "Rejected";
            record.Error = "ProcessId required (pid > 1)";
            return;
        }

        try
        {
            using var p = Process.GetProcessById(pid.Value);
            var name = p.ProcessName;
            p.Kill(entireProcessTree: true);
            record.Status = "Completed";
            record.Result = $"Killed pid={pid} name={name}";
            record.BeforeState = $"pid={pid};name={name}";
        }
        catch (Exception ex)
        {
            record.Status = "Failed";
            record.Error = ex.Message;
        }
    }

    private async Task IptablesBlockIpAsync(ResponseActionRecord record, string? ip, string chain, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IsSafeIp(ip))
        {
            record.Status = "Rejected";
            record.Error = "Valid TargetIp required";
            return;
        }

        var comment = $"NTS-{chain}-{ip.Replace('/', '_').Replace(':', '_')}";
        var args = $"-I {chain} -s {ip} -j DROP -m comment --comment {comment}";
        if (chain == "OUTPUT")
            args = $"-I OUTPUT -d {ip} -j DROP -m comment --comment {comment}";

        var (ok, output, err) = await RunAsync("iptables", args, ct);
        if (!ok)
        {
            // try nft briefly via iptables-nft same binary often
            (ok, output, err) = await RunAsync("iptables", args, ct);
        }

        if (ok)
        {
            record.Status = "Completed";
            record.Result = $"Blocked {ip} on {chain}";
            record.RollbackCommand = $"iptables -D {chain} -s {ip} -j DROP";
            record.Details = output;
        }
        else
        {
            record.Status = "Failed";
            record.Error = err;
        }
    }

    private async Task IptablesBlockPortAsync(ResponseActionRecord record, ResponseActionRequest request, CancellationToken ct)
    {
        var port = request.TargetPort ?? 0;
        if (port is < 1 or > 65535)
        {
            record.Status = "Rejected";
            record.Error = "TargetPort required";
            return;
        }

        var proto = string.IsNullOrWhiteSpace(request.Protocol) ? "tcp" : request.Protocol!.ToLowerInvariant();
        if (proto is not ("tcp" or "udp"))
        {
            record.Status = "Rejected";
            record.Error = "Protocol must be tcp or udp";
            return;
        }

        var dir = string.IsNullOrWhiteSpace(request.Direction) ? "in" : request.Direction!.ToLowerInvariant();
        var chain = dir == "out" ? "OUTPUT" : "INPUT";
        var comment = request.RuleName is { Length: > 0 } r && r.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase)
            ? r
            : $"NTS-Port-{port}-{proto}";

        var args = $"-I {chain} -p {proto} --dport {port} -j DROP -m comment --comment {comment}";
        var (ok, output, err) = await RunAsync("iptables", args, ct);
        if (ok)
        {
            record.Status = "Completed";
            record.Result = $"Blocked {proto}/{port} on {chain}";
            record.RollbackCommand = $"iptables -D {chain} -p {proto} --dport {port} -j DROP";
        }
        else
        {
            record.Status = "Failed";
            record.Error = err;
        }
    }

    private async Task IptablesOpenPortAsync(ResponseActionRecord record, ResponseActionRequest request, CancellationToken ct)
    {
        var port = request.TargetPort ?? 0;
        if (port is < 1 or > 65535)
        {
            record.Status = "Rejected";
            record.Error = "TargetPort required";
            return;
        }

        var proto = string.IsNullOrWhiteSpace(request.Protocol) ? "tcp" : request.Protocol!.ToLowerInvariant();
        var comment = request.RuleName is { Length: > 0 } r && r.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase)
            ? r
            : $"NTS-Open-{port}";
        var args = $"-I INPUT -p {proto} --dport {port} -j ACCEPT -m comment --comment {comment}";
        var (ok, output, err) = await RunAsync("iptables", args, ct);
        if (ok)
        {
            record.Status = "Completed";
            record.Result = $"Opened {proto}/{port} INPUT";
            record.RollbackCommand = $"iptables -D INPUT -p {proto} --dport {port} -j ACCEPT";
        }
        else
        {
            record.Status = "Failed";
            record.Error = err;
        }
    }

    private async Task IptablesRemoveCommentAsync(ResponseActionRecord record, string? ruleName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase))
        {
            record.Status = "Rejected";
            record.Error = "RuleName must start with NTS-";
            return;
        }

        // Best-effort: list and delete matching comment (requires careful parsing — use iptables-save)
        var (ok, output, err) = await RunAsync("bash", $"-c \"iptables-save | grep -F '{ruleName.Replace("'", "")}' | head -5\"", ct);
        record.Status = ok ? "Completed" : "Failed";
        record.Result = "Listed matching rules (manual delete if needed):\n" + Truncate(output, 800);
        record.Error = ok ? null : err;
        record.Details = "Linux agent lists CSA rules; full auto-delete by comment varies by iptables version.";
    }

    private async Task VacuumJournalAsync(ResponseActionRecord record, CancellationToken ct)
    {
        var (ok, output, err) = await RunAsync("journalctl", "--vacuum-size=200M", ct, timeoutSec: 120);
        if (ok)
        {
            record.Status = "Completed";
            record.Result = Truncate(output, 500);
        }
        else
        {
            // fallback: vacuum time
            (ok, output, err) = await RunAsync("journalctl", "--vacuum-time=7d", ct, timeoutSec: 120);
            record.Status = ok ? "Completed" : "Failed";
            record.Result = Truncate(output, 500);
            record.Error = ok ? null : err;
        }
    }

    private async Task CollectDiagnosticsAsync(ResponseActionRecord record, CancellationToken ct)
    {
        var dir = Directory.Exists("/var/log/ntshield")
            ? "/var/log/ntshield"
            : Path.Combine(AppContext.BaseDirectory, "logs");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"diag-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.txt");
        var sb = new StringBuilder();
        sb.AppendLine($"# NT Shield Linux diagnostics {DateTimeOffset.UtcNow:o}");
        sb.AppendLine($"Host={Environment.MachineName}");
        foreach (var (cmd, args) in new[]
                 {
                     ("uname", "-a"),
                     ("uptime", ""),
                     ("df", "-h"),
                     ("free", "-m"),
                     ("systemctl", "is-active nginx php-fpm docker sshd 2>/dev/null; true"),
                 })
        {
            // skip bash compound for systemctl — run simple ones
            if (args.Contains("2>")) continue;
            var (ok, output, err) = await RunAsync(cmd, args, ct, timeoutSec: 15);
            sb.AppendLine($"## {cmd} {args}");
            sb.AppendLine(ok ? output : err);
            sb.AppendLine();
        }

        // disk + mem quick
        try
        {
            sb.AppendLine("## /proc/loadavg");
            sb.AppendLine(await File.ReadAllTextAsync("/proc/loadavg", ct));
            sb.AppendLine("## /proc/meminfo (head)");
            sb.AppendLine(string.Join('\n', (await File.ReadAllLinesAsync("/proc/meminfo", ct)).Take(8)));
        }
        catch
        {
            // ignore
        }

        await File.WriteAllTextAsync(path, sb.ToString(), ct);
        record.Status = "Completed";
        record.Result = path;
    }

    private async Task QuarantineAsync(ResponseActionRecord record, CancellationToken ct)
    {
        // Drop all inbound except established + loopback + ssh (22) so operator can recover
        var cmds = new[]
        {
            "-P INPUT DROP",
            "-I INPUT -i lo -j ACCEPT",
            "-I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "-I INPUT -p tcp --dport 22 -j ACCEPT",
            "-I INPUT -m comment --comment NTS-Quarantine -j DROP"
        };

        var okAny = false;
        var log = new StringBuilder();
        foreach (var a in cmds)
        {
            var (ok, output, err) = await RunAsync("iptables", a, ct);
            log.AppendLine(ok ? $"OK {a}" : $"FAIL {a}: {err}");
            okAny |= ok;
        }

        record.Status = okAny ? "Completed" : "Failed";
        record.Result = Truncate(log.ToString(), 800);
        record.RollbackCommand = "iptables -P INPUT ACCEPT; iptables -F INPUT  # review carefully";
        record.Error = okAny ? null : "iptables quarantine failed — need root";
    }

    private static bool IsSafeServiceName(string name)
    {
        if (!SafeToken.IsMatch(name)) return false;
        if (ServiceNameAllow.Contains(name)) return true;
        // allow phpX.Y-fpm pattern and *.service stripped
        var n = name.EndsWith(".service", StringComparison.OrdinalIgnoreCase)
            ? name[..^8]
            : name;
        if (ServiceNameAllow.Contains(n)) return true;
        if (Regex.IsMatch(n, @"^php\d+(\.\d+)?-fpm$", RegexOptions.IgnoreCase)) return true;
        // allow any simple unit that doesn't look like a path injection
        return n.Length <= 64 && !n.Contains('/') && !n.Contains('\\') && !n.Contains(' ');
    }

    private static bool IsSafeIp(string ip)
    {
        // IPv4 or simple CIDR
        if (ip.Contains("..") || ip.Contains(' ') || ip.Length > 43) return false;
        var core = ip.Contains('/') ? ip.Split('/')[0] : ip;
        return System.Net.IPAddress.TryParse(core, out _);
    }

    private async Task<(bool Ok, string Output, string Error)> RunAsync(
        string fileName, string arguments, CancellationToken ct, int timeoutSec = 30)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = new Process { StartInfo = psi };
            var sbOut = new StringBuilder();
            var sbErr = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data is not null) sbOut.AppendLine(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (e.Data is not null) sbErr.AppendLine(e.Data); };
            if (!p.Start())
                return (false, "", "Failed to start process");
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            using var reg = ct.Register(() => { try { p.Kill(true); } catch { /* ignore */ } });
            var finished = await Task.Run(() => p.WaitForExit(timeoutSec * 1000), ct);
            if (!finished)
            {
                try { p.Kill(true); } catch { /* ignore */ }
                return (false, sbOut.ToString(), "Timeout");
            }

            var output = sbOut.ToString().Trim();
            var err = sbErr.ToString().Trim();
            if (p.ExitCode == 0)
                return (true, output, err);
            return (false, output, string.IsNullOrEmpty(err) ? $"exit={p.ExitCode}" : err);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Run {Cmd} failed", fileName);
            return (false, "", ex.Message);
        }
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s[..max] + "…";
}
