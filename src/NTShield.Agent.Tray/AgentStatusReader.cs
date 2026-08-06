using System.ServiceProcess;
using System.Text.Json;

namespace NTShield.Agent.Tray;

internal sealed class AgentLiveStatus
{
    public string ServiceStatus { get; set; } = "Unknown";
    public bool ServiceRunning { get; set; }
    public string State { get; set; } = "Unknown";
    public string Message { get; set; } = "Waiting for agent status…";
    public string Host { get; set; } = Environment.MachineName;
    public string AgentId { get; set; } = "—";
    public string Version { get; set; } = "—";
    public string CentralUrl { get; set; } = "(not set)";
    public bool CentralReachable { get; set; }
    public bool DetectOnly { get; set; } = true;
    public string Mode { get; set; } = "Ids";
    public long EventsCollected { get; set; }
    public long ConnectionsCollected { get; set; }
    public long ProcessSnapshots { get; set; }
    public long AlertsRaised { get; set; }
    public long QueueDepth { get; set; }
    public long DatabaseSizeBytes { get; set; }
    public long WorkingSetBytes { get; set; }
    public string? LastAlertTitle { get; set; }
    public DateTimeOffset? UpdatedAtUtc { get; set; }
    public DateTimeOffset? StartedAtUtc { get; set; }
    public DateTimeOffset? LastActivityUtc { get; set; }
    public bool SecurityEvents { get; set; } = true;
    public bool NetworkConnections { get; set; } = true;
    public bool Processes { get; set; } = true;
    public bool Services { get; set; } = true;
    public bool ScheduledTasks { get; set; } = true;
    public bool Detection { get; set; } = true;
    public bool HasStatusFile { get; set; }
    public string StatusFilePath { get; set; } = "";
    public string DataDir { get; set; } = @"C:\ProgramData\NTShield\Agent";
}

internal static class AgentStatusReader
{
    private const string ServiceName = "NTShieldAgent";

    public static AgentLiveStatus Read(string installDir)
    {
        var s = new AgentLiveStatus();
        try
        {
            using var sc = new ServiceController(ServiceName);
            s.ServiceStatus = sc.Status.ToString();
            s.ServiceRunning = sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            s.ServiceStatus = "Not installed";
            s.ServiceRunning = false;
        }

        // Defaults from appsettings
        try
        {
            var settings = Path.Combine(installDir, "appsettings.json");
            if (File.Exists(settings))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(settings));
                if (doc.RootElement.TryGetProperty("Server", out var server) &&
                    server.TryGetProperty("Url", out var u))
                {
                    s.CentralUrl = u.GetString() ?? s.CentralUrl;
                }

                if (doc.RootElement.TryGetProperty("Agent", out var agent))
                {
                    if (agent.TryGetProperty("ComputerName", out var cn) &&
                        !string.IsNullOrWhiteSpace(cn.GetString()))
                    {
                        s.Host = cn.GetString()!;
                    }

                    if (agent.TryGetProperty("AgentId", out var id) &&
                        !string.IsNullOrWhiteSpace(id.GetString()))
                    {
                        s.AgentId = id.GetString()!;
                    }

                    if (agent.TryGetProperty("Version", out var ver) &&
                        !string.IsNullOrWhiteSpace(ver.GetString()))
                    {
                        s.Version = ver.GetString()!;
                    }

                    if (agent.TryGetProperty("DetectOnly", out var det))
                    {
                        s.DetectOnly = det.GetBoolean();
                    }

                    if (agent.TryGetProperty("DataDirectory", out var dd) &&
                        !string.IsNullOrWhiteSpace(dd.GetString()))
                    {
                        s.DataDir = dd.GetString()!;
                    }
                }

                if (doc.RootElement.TryGetProperty("Collectors", out var col))
                {
                    s.SecurityEvents = GetBool(col, "SecurityEvents", true);
                    s.NetworkConnections = GetBool(col, "NetworkConnections", true);
                    s.Processes = GetBool(col, "Processes", true);
                    s.Services = GetBool(col, "Services", true);
                    s.ScheduledTasks = GetBool(col, "ScheduledTasks", true);
                }

                if (doc.RootElement.TryGetProperty("Detection", out var detSec))
                {
                    s.Detection = GetBool(detSec, "Enabled", true);
                }
            }
        }
        catch
        {
            // keep defaults
        }

        s.StatusFilePath = Path.Combine(s.DataDir, "status.json");
        if (File.Exists(s.StatusFilePath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(s.StatusFilePath));
                var r = doc.RootElement;
                s.HasStatusFile = true;
                s.State = GetStr(r, "State") ?? s.State;
                s.Message = GetStr(r, "Message") ?? s.Message;
                s.Host = GetStr(r, "ComputerName") ?? s.Host;
                s.AgentId = GetStr(r, "AgentId") ?? s.AgentId;
                s.Version = GetStr(r, "Version") ?? s.Version;
                s.CentralUrl = GetStr(r, "CentralUrl") ?? s.CentralUrl;
                s.DetectOnly = GetBoolEl(r, "DetectOnly", s.DetectOnly);
                s.Mode = GetStr(r, "Mode") ?? GetStr(r, "ResponseMode") ?? s.Mode;
                s.CentralReachable = GetBoolEl(r, "CentralReachable", false);
                s.EventsCollected = GetLong(r, "EventsCollected");
                s.ConnectionsCollected = GetLong(r, "ConnectionsCollected");
                s.ProcessSnapshots = GetLong(r, "ProcessSnapshots");
                s.AlertsRaised = GetLong(r, "AlertsRaised");
                s.QueueDepth = GetLong(r, "QueueDepth");
                s.DatabaseSizeBytes = GetLong(r, "DatabaseSizeBytes");
                s.WorkingSetBytes = GetLong(r, "WorkingSetBytes");
                s.LastAlertTitle = GetStr(r, "LastAlertTitle");
                s.UpdatedAtUtc = GetTime(r, "UpdatedAtUtc");
                s.StartedAtUtc = GetTime(r, "StartedAtUtc");
                s.LastActivityUtc = GetTime(r, "LastActivityUtc");
                if (r.TryGetProperty("Collectors", out var c))
                {
                    s.SecurityEvents = GetBoolEl(c, "SecurityEvents", s.SecurityEvents);
                    s.NetworkConnections = GetBoolEl(c, "NetworkConnections", s.NetworkConnections);
                    s.Processes = GetBoolEl(c, "Processes", s.Processes);
                    s.Services = GetBoolEl(c, "Services", s.Services);
                    s.ScheduledTasks = GetBoolEl(c, "ScheduledTasks", s.ScheduledTasks);
                    s.Detection = GetBoolEl(c, "Detection", s.Detection);
                }
            }
            catch
            {
                s.HasStatusFile = false;
            }
        }

        if (s.ServiceRunning)
        {
            if (!s.HasStatusFile)
            {
                s.State = "Monitoring";
                s.Message = "Agent service is running — collecting security telemetry";
            }
        }
        else
        {
            s.State = "Stopped";
            s.Message = s.ServiceStatus is "Not installed"
                ? "Service not installed — use Install / Register Agent service (tray menu) or Agent Setup"
                : "Agent service is not running — click Start Agent";
        }

        // Stale status file (> 2 min) while service running
        if (s.ServiceRunning && s.UpdatedAtUtc is { } t &&
            DateTimeOffset.UtcNow - t > TimeSpan.FromMinutes(2))
        {
            s.Message = "Service running, but status heartbeat is stale — check agent logs";
        }

        return s;
    }

    private static bool GetBool(JsonElement parent, string name, bool fallback)
    {
        if (parent.TryGetProperty(name, out var p) &&
            (p.ValueKind is JsonValueKind.True or JsonValueKind.False))
        {
            return p.GetBoolean();
        }

        return fallback;
    }

    private static bool GetBoolEl(JsonElement parent, string name, bool fallback) =>
        GetBool(parent, name, fallback);

    private static string? GetStr(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    private static long GetLong(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var p))
        {
            return 0;
        }

        return p.ValueKind switch
        {
            JsonValueKind.Number => p.TryGetInt64(out var n) ? n : 0,
            JsonValueKind.String when long.TryParse(p.GetString(), out var n) => n,
            _ => 0
        };
    }

    private static DateTimeOffset? GetTime(JsonElement parent, string name)
    {
        var s = GetStr(parent, name);
        if (s is null)
        {
            return null;
        }

        return DateTimeOffset.TryParse(s, out var t) ? t : null;
    }
}
