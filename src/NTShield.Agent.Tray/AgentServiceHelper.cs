using System.Diagnostics;
using System.ServiceProcess;

namespace NTShield.Agent.Tray;

/// <summary>
/// Local NTShieldAgent Windows service: detect / install / start / stop / restart.
/// Handles broken installs where the service path points at a missing exe
/// (common after dual Full-stack + Agent-only upgrades).
/// </summary>
internal static class AgentServiceHelper
{
    public const string ServiceName = "NTShieldAgent";
    public const string DisplayName = "NT Shield Agent";

    public static bool IsInstalled()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            _ = sc.Status;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Image path registered with SCM, or null.</summary>
    public static string? GetServiceBinaryPath()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"qc {ServiceName}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10_000);
            // BINARY_PATH_NAME   : "C:\...\NTShield.Agent.exe"
            foreach (var line in output.Split('\n'))
            {
                var t = line.Trim();
                if (!t.StartsWith("BINARY_PATH_NAME", StringComparison.OrdinalIgnoreCase))
                    continue;
                var idx = t.IndexOf(':');
                if (idx < 0) continue;
                var path = t[(idx + 1)..].Trim().Trim('"');
                return string.IsNullOrWhiteSpace(path) ? null : path;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    public static string? FindAgentExe(string installDir)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(installDir))
            candidates.Add(Path.Combine(installDir, "NTShield.Agent.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "NTShield.Agent.exe"));
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "NT Shield Agent", "NTShield.Agent.exe"));
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "NT Shield", "Agent", "NTShield.Agent.exe"));

        // Prefer newest existing binary (dual-install machines)
        string? best = null;
        DateTime bestWrite = DateTime.MinValue;
        foreach (var c in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!File.Exists(c)) continue;
                var w = File.GetLastWriteTimeUtc(c);
                if (best is null || w > bestWrite)
                {
                    best = c;
                    bestWrite = w;
                }
            }
            catch
            {
                // skip
            }
        }

        return best;
    }

    public static bool TryGetStatus(out ServiceControllerStatus status, out string label)
    {
        status = ServiceControllerStatus.Stopped;
        try
        {
            using var sc = new ServiceController(ServiceName);
            sc.Refresh();
            status = sc.Status;
            label = status.ToString();

            // Detect broken registration: service exists but binary missing
            var bin = GetServiceBinaryPath();
            if (!string.IsNullOrEmpty(bin) && !File.Exists(bin) &&
                status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
            {
                label = "Broken (exe missing)";
            }

            return true;
        }
        catch
        {
            label = "Not installed";
            return false;
        }
    }

    /// <summary>
    /// If service points to a missing file, re-register to a found Agent.exe.
    /// </summary>
    public static bool TryRepairBrokenBinaryPath(string installDir, IWin32Window? owner, bool startAfter)
    {
        var bin = GetServiceBinaryPath();
        if (!string.IsNullOrEmpty(bin) && File.Exists(bin))
            return false; // not broken

        var exe = FindAgentExe(installDir);
        if (exe is null)
        {
            MessageBox.Show(owner,
                "Agent service is registered but the executable is missing, and no Agent.exe was found.\n\n" +
                "Reinstall:\n  NTShield-Agent-Setup-*.exe\n  or Full Setup.\n\n" +
                (string.IsNullOrEmpty(bin) ? "" : $"Missing path:\n{bin}"),
                "Agent broken install",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return false;
        }

        var r = MessageBox.Show(owner,
            "Agent service points to a missing file (upgrade left an empty folder).\n\n" +
            (string.IsNullOrEmpty(bin) ? "" : $"Broken path:\n{bin}\n\n") +
            $"Found working agent:\n{exe}\n\n" +
            "Repair service path and start now? (Administrator / UAC)",
            "Repair Agent service",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (r != DialogResult.Yes)
            return false;

        return RegisterService(exe, Path.GetDirectoryName(exe) ?? installDir, owner, startAfter);
    }

    /// <summary>
    /// Start/stop/restart. If not installed or broken path, offers to register/repair.
    /// </summary>
    public static void Control(string action, string installDir, IWin32Window? owner = null)
    {
        if (!IsInstalled())
        {
            var exe = FindAgentExe(installDir);
            if (exe is null)
            {
                MessageBox.Show(owner,
                    "Agent service is not installed and NTShield.Agent.exe was not found.\n\n" +
                    "Install with:\n" +
                    "  NTShield-Agent-Setup-*.exe\n" +
                    "or Full Setup (includes Agent).\n\n" +
                    $"Looked under:\n{installDir}",
                    "Agent service not installed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            var r = MessageBox.Show(owner,
                "Windows service \"NTShieldAgent\" is not registered on this PC.\n\n" +
                $"Found agent:\n{exe}\n\n" +
                "Register and start the service now?\n(Requires Administrator)",
                "Install Agent service",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (r != DialogResult.Yes) return;

            if (!RegisterService(exe, Path.GetDirectoryName(exe) ?? installDir, owner, startAfter: true))
                return;

            if (action is "start" or "restart")
                return;
        }
        else
        {
            // Service exists — check binary still on disk
            var bin = GetServiceBinaryPath();
            if (!string.IsNullOrEmpty(bin) && !File.Exists(bin))
            {
                if (!TryRepairBrokenBinaryPath(installDir, owner, startAfter: action is "start" or "restart"))
                    return;
                if (action is "start" or "restart")
                    return;
            }
        }

        try
        {
            using var sc = new ServiceController(ServiceName);
            sc.Refresh();
            var timeout = TimeSpan.FromSeconds(60);
            switch (action)
            {
                case "start":
                    if (sc.Status is not ServiceControllerStatus.Running and not ServiceControllerStatus.StartPending)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    }

                    break;
                case "stop":
                    if (sc.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    break;
                case "restart":
                    if (sc.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    sc.Refresh();
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    break;
            }
        }
        catch (Exception ex)
        {
            // Auto-retry repair on classic "file not found" / cannot start
            var msg = ex.Message ?? "";
            if (msg.Contains("cannot be started", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("cannot find the file", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                if (TryRepairBrokenBinaryPath(installDir, owner, startAfter: action is "start" or "restart"))
                    return;
            }

            MessageBox.Show(owner,
                ex.Message + "\n\n" +
                "• Exe missing: reinstall Agent Setup, or click Start again to repair path.\n" +
                "• Access denied: right-click tray → Run as Administrator.\n" +
                "• Dual install: use one of:\n" +
                "    C:\\Program Files\\NT Shield Agent\n" +
                "    C:\\Program Files\\NT Shield\\Agent",
                "Agent service",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    public static bool RegisterService(string agentExe, string installDir, IWin32Window? owner, bool startAfter)
    {
        try
        {
            if (!File.Exists(agentExe))
            {
                MessageBox.Show(owner, "Agent exe not found:\n" + agentExe, "Agent service",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            var dataDir = @"C:\ProgramData\NTShield\Agent";
            Directory.CreateDirectory(dataDir);
            Directory.CreateDirectory(Path.Combine(dataDir, "logs"));
            Directory.CreateDirectory(Path.Combine(dataDir, "evidence"));

            var agentDir = Path.GetDirectoryName(agentExe) ?? installDir;

            // Prefer official helper if present
            var ps1 = Path.Combine(installDir, "Installer", "register-agent-service.ps1");
            if (!File.Exists(ps1))
                ps1 = Path.Combine(agentDir, "Installer", "register-agent-service.ps1");

            string centralUrl = "https://localhost:7443";
            try
            {
                var settings = Path.Combine(agentDir, "appsettings.json");
                if (!File.Exists(settings))
                    settings = Path.Combine(installDir, "appsettings.json");
                if (File.Exists(settings))
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(settings));
                    if (doc.RootElement.TryGetProperty("Server", out var s) &&
                        s.TryGetProperty("Url", out var u) &&
                        u.GetString() is { Length: > 0 } url)
                        centralUrl = url;
                }

                var conn = @"C:\ProgramData\NTShield\connection.json";
                if (File.Exists(conn) && (centralUrl.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
                                          centralUrl.Contains("127.0.0.1")))
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(conn));
                    if (doc.RootElement.TryGetProperty("RemoteUrl", out var ru) &&
                        ru.GetString() is { Length: > 0 } remote)
                        centralUrl = remote;
                }
            }
            catch
            {
                // keep default
            }

            if (File.Exists(ps1))
            {
                var args =
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{ps1}\" " +
                    $"-InstallDir \"{agentDir}\" " +
                    $"-DataDir \"{dataDir}\" " +
                    $"-ServiceName \"{ServiceName}\" " +
                    $"-StartService \"{(startAfter ? "1" : "0")}\" " +
                    $"-CentralUrl \"{centralUrl}\"";
                var code = RunElevated("powershell.exe", args);
                if (code != 0)
                {
                    MessageBox.Show(owner,
                        $"register-agent-service.ps1 exited with code {code}.\nTrying sc.exe fallback…",
                        "Agent service", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return RegisterWithSc(agentExe, startAfter, owner);
                }

                return IsInstalled() && File.Exists(GetServiceBinaryPath() ?? agentExe);
            }

            return RegisterWithSc(agentExe, startAfter, owner);
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, "Register failed:\n" + ex.Message, "Agent service",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private static bool RegisterWithSc(string agentExe, bool startAfter, IWin32Window? owner)
    {
        RunElevated("sc.exe", $"stop {ServiceName}");
        Thread.Sleep(500);
        RunElevated("sc.exe", $"delete {ServiceName}");
        Thread.Sleep(1000);

        var bin = agentExe.Replace("\"", "");
        var create = $"create {ServiceName} binPath= \"{bin}\" start= auto DisplayName= \"{DisplayName}\"";
        var code = RunElevated("sc.exe", create);
        if (code != 0 && !IsInstalled())
        {
            MessageBox.Show(owner,
                $"sc create failed (exit {code}).\nRun tray as Administrator, or install NTShield-Agent-Setup.",
                "Agent service", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }

        RunElevated("sc.exe", $"description {ServiceName} \"NT Shield Endpoint Security Monitoring Agent\"");
        RunElevated("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/10000/restart/30000/restart/60000");
        RunElevated("sc.exe", $"config {ServiceName} start= auto");

        if (startAfter)
        {
            try
            {
                using var sc = new ServiceController(ServiceName);
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
            }
            catch (Exception ex)
            {
                MessageBox.Show(owner, "Service registered but start failed:\n" + ex.Message,
                    "Agent service", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        MessageBox.Show(owner,
            "Agent service registered.\n\n" +
            $"Path:\n{bin}\n\n" +
            "Next: Edit Central IP / Port if needed, then wait for heartbeat.",
            "Agent service", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return IsInstalled();
    }

    private static int RunElevated(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi);
            if (p is null) return -1;
            p.WaitForExit(120_000);
            return p.ExitCode;
        }
        catch
        {
            // User cancelled UAC
            return -1;
        }
    }
}
