using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;

namespace NTShield.Response.Firewall;

/// <summary>
/// Windows Firewall blocking compatible with Server 2012 via netsh advfirewall fallback.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallBlocker
{
    private readonly ILogger<FirewallBlocker> _logger;

    public FirewallBlocker(ILogger<FirewallBlocker> logger)
    {
        _logger = logger;
    }

    public FirewallChangeResult BlockIp(string ip, string direction, string ruleName, string reason)
    {
        ValidateIp(ip);
        ValidateDirection(direction);
        ValidateRuleName(ruleName);

        var dir = direction.Equals("out", StringComparison.OrdinalIgnoreCase) ? "out" : "in";
        var args =
            $"advfirewall firewall add rule name=\"{ruleName}\" dir={dir} action=block remoteip={ip} enable=yes protocol=any";

        var before = GetRule(ruleName);
        var (code, output) = RunNetsh(args);

        return new FirewallChangeResult
        {
            Success = code == 0,
            BeforeState = before ?? "absent",
            Result = code == 0 ? $"blocked IP {ip} dir={dir} ({reason})" : output,
            RollbackCommand = $"netsh advfirewall firewall delete rule name=\"{ruleName}\"",
            Error = code == 0 ? null : output,
            RuleName = ruleName
        };
    }

    /// <summary>
    /// Block traffic by port. localPort = this host's port; remotePort = peer port.
    /// action block + dir in/out.
    /// </summary>
    public FirewallChangeResult BlockPort(
        string direction,
        string protocol,
        int? localPort,
        int? remotePort,
        string? remoteIp,
        string ruleName,
        string reason)
    {
        ValidateDirection(direction);
        ValidateRuleName(ruleName);
        var proto = NormalizeProtocol(protocol);
        var dir = direction.Equals("out", StringComparison.OrdinalIgnoreCase) ? "out" : "in";

        if (localPort is null && remotePort is null)
        {
            throw new ArgumentException("localPort or remotePort required for port block.");
        }

        if (localPort is < 1 or > 65535 || remotePort is < 1 or > 65535)
        {
            throw new ArgumentException("Port must be 1-65535.");
        }

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            ValidateIp(remoteIp);
        }

        var parts = new StringBuilder();
        parts.Append($"advfirewall firewall add rule name=\"{ruleName}\" dir={dir} action=block protocol={proto} enable=yes");
        if (localPort is not null)
        {
            parts.Append($" localport={localPort.Value}");
        }

        if (remotePort is not null)
        {
            parts.Append($" remoteport={remotePort.Value}");
        }

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            parts.Append($" remoteip={remoteIp}");
        }

        var before = GetRule(ruleName);
        var (code, output) = RunNetsh(parts.ToString());
        return new FirewallChangeResult
        {
            Success = code == 0,
            BeforeState = before ?? "absent",
            Result = code == 0
                ? $"blocked port local={localPort} remote={remotePort} proto={proto} dir={dir} ip={remoteIp ?? "*"} ({reason})"
                : output,
            RollbackCommand = $"netsh advfirewall firewall delete rule name=\"{ruleName}\"",
            Error = code == 0 ? null : output,
            RuleName = ruleName
        };
    }

    /// <summary>Open (allow) a local port — typically inbound for a service.</summary>
    public FirewallChangeResult OpenPort(string direction, string protocol, int localPort, string ruleName, string reason)
    {
        ValidateDirection(direction);
        ValidateRuleName(ruleName);
        if (localPort is < 1 or > 65535)
        {
            throw new ArgumentException("Port must be 1-65535.");
        }

        var proto = NormalizeProtocol(protocol);
        var dir = direction.Equals("out", StringComparison.OrdinalIgnoreCase) ? "out" : "in";
        var args =
            $"advfirewall firewall add rule name=\"{ruleName}\" dir={dir} action=allow protocol={proto} localport={localPort} enable=yes";

        var before = GetRule(ruleName);
        var (code, output) = RunNetsh(args);
        return new FirewallChangeResult
        {
            Success = code == 0,
            BeforeState = before ?? "absent",
            Result = code == 0 ? $"opened port {localPort}/{proto} dir={dir} ({reason})" : output,
            RollbackCommand = $"netsh advfirewall firewall delete rule name=\"{ruleName}\"",
            Error = code == 0 ? null : output,
            RuleName = ruleName
        };
    }

    /// <summary>Close = delete matching CSA rule (allow or block).</summary>
    public FirewallChangeResult RemoveRule(string ruleName)
    {
        ValidateRuleName(ruleName);
        var before = GetRule(ruleName) ?? "absent";
        var (code, output) = RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
        return new FirewallChangeResult
        {
            Success = code == 0 || output.Contains("No rules match", StringComparison.OrdinalIgnoreCase),
            BeforeState = before,
            Result = code == 0 ? "rule removed (port closed / unblock)" : output,
            RollbackCommand = before != "absent"
                ? $"# re-add previous rule manually: {before}"
                : string.Empty,
            Error = code == 0 ? null : output,
            RuleName = ruleName
        };
    }

    private static string NormalizeProtocol(string? protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol) || protocol.Equals("any", StringComparison.OrdinalIgnoreCase))
        {
            return "any";
        }

        if (protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase))
        {
            return "TCP";
        }

        if (protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
        {
            return "UDP";
        }

        throw new ArgumentException("Protocol must be tcp, udp, or any.");
    }

    public string CaptureFirewallStatus()
    {
        var (code, output) = RunNetsh("advfirewall show allprofiles");
        return code == 0 ? output : $"netsh failed: {output}";
    }

    private string? GetRule(string ruleName)
    {
        var (code, output) = RunNetsh($"advfirewall firewall show rule name=\"{ruleName}\"");
        if (code != 0 || output.Contains("No rules match", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return output.Length > 2000 ? output[..2000] : output;
    }

    private (int ExitCode, string Output) RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start netsh");
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(30_000);
            var combined = (stdout + Environment.NewLine + stderr).Trim();
            _logger.LogDebug("netsh {Args} => {Code}", args, p.ExitCode);
            return (p.ExitCode, combined);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "netsh failed");
            return (-1, ex.Message);
        }
    }

    private static void ValidateIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || ip.Contains(' ') || ip.Contains('"') || ip.Contains(';') || ip.Contains('&'))
        {
            throw new ArgumentException("Invalid IP for firewall rule.", nameof(ip));
        }

        if (!System.Net.IPAddress.TryParse(ip, out _))
        {
            throw new ArgumentException("IP parse failed.", nameof(ip));
        }
    }

    private static void ValidateDirection(string direction)
    {
        if (!direction.Equals("in", StringComparison.OrdinalIgnoreCase) &&
            !direction.Equals("out", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Direction must be in or out.");
        }
    }

    private static void ValidateRuleName(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName) || ruleName.Length > 128 ||
            ruleName.IndexOfAny(['"', ';', '&', '|', '\n', '\r']) >= 0)
        {
            throw new ArgumentException("Invalid rule name.");
        }

        if (!ruleName.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Rule name must start with NTS- prefix.");
        }
    }
}

public sealed class FirewallChangeResult
{
    public bool Success { get; init; }
    public string BeforeState { get; init; } = string.Empty;
    public string Result { get; init; } = string.Empty;
    public string RollbackCommand { get; init; } = string.Empty;
    public string? Error { get; init; }
    public string? RuleName { get; init; }
}
