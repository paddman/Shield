using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using NTShield.Collectors.Windows.Native;
using Microsoft.Extensions.Logging;

namespace NTShield.Collectors.Windows.Process;

[SupportedOSPlatform("windows")]
public sealed class ProcessEnricher
{
    private readonly ILogger<ProcessEnricher> _logger;
    private readonly Dictionary<int, ProcessDetails> _cache = new();
    private readonly object _sync = new();

    public ProcessEnricher(ILogger<ProcessEnricher> logger)
    {
        _logger = logger;
    }

    public ProcessDetails GetDetails(int pid, bool hashExecutable)
    {
        lock (_sync)
        {
            if (_cache.TryGetValue(pid, out var cached))
            {
                return cached;
            }
        }

        var details = Resolve(pid, hashExecutable);
        lock (_sync)
        {
            _cache[pid] = details;
            if (_cache.Count > 5000)
            {
                _cache.Clear();
            }
        }

        return details;
    }

    private ProcessDetails Resolve(int pid, bool hashExecutable)
    {
        var details = new ProcessDetails { ProcessId = pid };

        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            details.ProcessName = proc.ProcessName;
            try { details.StartTimeUtc = proc.StartTime.ToUniversalTime(); } catch { /* access denied */ }
            try { details.ParentProcessId = GetParentPidWmi(pid); } catch { /* ignore */ }
        }
        catch (ArgumentException)
        {
            details.ProcessName = $"pid-{pid}";
            return details;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Process.GetProcessById failed for {Pid}", pid);
            details.ProcessName = $"pid-{pid}";
        }

        details.ProcessPath = ProcessNative.GetProcessPath(pid);
        if (string.IsNullOrEmpty(details.ProcessPath))
        {
            details.ProcessPath = TryWmiExecutablePath(pid);
        }

        if (!string.IsNullOrEmpty(details.ProcessPath))
        {
            details.ProcessName = Path.GetFileName(details.ProcessPath);
            var (status, signer) = ProcessNative.GetSignatureInfo(details.ProcessPath);
            details.DigitalSignatureStatus = status;
            details.SignerName = signer;
            if (hashExecutable)
            {
                details.ExecutableSha256 = ProcessNative.ComputeSha256(details.ProcessPath);
            }
        }

        details.CommandLine = TryWmiCommandLine(pid);
        details.Owner = TryWmiOwner(pid);
        details.IntegrityLevel = "Unknown";
        return details;
    }

    private static string? TryWmiExecutablePath(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["ExecutablePath"]?.ToString();
            }
        }
        catch
        {
            // AccessDenied / process exited
        }

        return null;
    }

    private static string? TryWmiCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString();
            }
        }
        catch
        {
            // AccessDenied / process exited
        }

        return null;
    }

    private static string? TryWmiOwner(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var args = new string[] { string.Empty, string.Empty };
                var returnCode = Convert.ToInt32(obj.InvokeMethod("GetOwner", args));
                if (returnCode == 0)
                {
                    var user = args[0];
                    var domain = args[1];
                    return string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                }
            }
        }
        catch
        {
            // AccessDenied
        }

        return null;
    }

    private static int? GetParentPidWmi(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }
}

public sealed class ProcessDetails
{
    public int ProcessId { get; set; }
    public int? ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string? ProcessPath { get; set; }
    public string? CommandLine { get; set; }
    public string? Owner { get; set; }
    public DateTime? StartTimeUtc { get; set; }
    public string? ExecutableSha256 { get; set; }
    public string? DigitalSignatureStatus { get; set; }
    public string? SignerName { get; set; }
    public string? IntegrityLevel { get; set; }
}
