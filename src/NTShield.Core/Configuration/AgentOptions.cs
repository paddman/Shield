namespace NTShield.Core.Configuration;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string Name { get; set; } = "NT Shield Agent";
    public string AgentId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = Environment.MachineName;
    public string DataDirectory { get; set; } = @"C:\ProgramData\NTShield\Agent";
    public string ConfigPath { get; set; } = string.Empty;
    public string Version { get; set; } = "1.0.0";
    public int HeartbeatSeconds { get; set; } = 60;
    public int CollectionIntervalSeconds { get; set; } = 5;
    /// <summary>When true (default), no destructive response actions execute without explicit central approval.</summary>
    public bool DetectOnly { get; set; } = true;

    /// <summary>
    /// Security operating mode:
    /// Ids = detect + alert only (classic IDS);
    /// Ips = detect + automatic prevention (firewall block) for high/critical (classic IPS).
    /// DetectOnly is treated as Ids when Mode is empty.
    /// </summary>
    public string Mode { get; set; } = "Ids";
}

public sealed class CentralServerOptions
{
    public const string SectionName = "Server";

    public string Url { get; set; } = "https://sentinel.example.local";
    // Back-compat
    public string BaseUrl
    {
        get => Url;
        set => Url = value;
    }

    public bool EnableMtls { get; set; }
    public string? ClientCertificatePath { get; set; }
    public string? ClientCertificatePassword { get; set; }
    public string? CaCertificatePath { get; set; }
    public bool AllowUntrustedServerCertificate { get; set; }
    public int TimeoutSeconds { get; set; } = 30;
    public int HeartbeatIntervalSeconds { get; set; } = 60;
    public int FlushIntervalSeconds { get; set; } = 15;
    public int BatchSize { get; set; } = 200;
    public int OfflineQueueLimit { get; set; } = 100_000;

    /// <summary>Central enrollment token (register once). From Central secrets.json EnrollmentToken.</summary>
    public string EnrollmentToken { get; set; } = "";

    /// <summary>Per-agent API key issued on register. Sent as X-NTShield-Api-Key.</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Optional syslog forward of alerts to Central (or any syslog receiver).</summary>
    public bool SyslogEnabled { get; set; }
    public string SyslogHost { get; set; } = "127.0.0.1";
    public int SyslogPort { get; set; } = 5514;
    public string SyslogProtocol { get; set; } = "Udp";
    public string SyslogAppName { get; set; } = "NTShield";
}

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    public string DatabaseFileName { get; set; } = "agent.db";
    public int RetentionDays { get; set; } = 14;
    public long MaxDatabaseSizeMb { get; set; } = 1024;
    public int MaintenanceIntervalMinutes { get; set; } = 60;
    public int OfflineQueueLimit { get; set; } = 100_000;
    public int MaxLogFileBytes { get; set; } = 50 * 1024 * 1024;
}

public sealed class EventLogCollectorOptions
{
    public const string SectionName = "Collectors";

    public bool SecurityEvents { get; set; } = true;
    public bool Enabled
    {
        get => SecurityEvents;
        set => SecurityEvents = value;
    }

    public List<EventChannelWatch> Channels { get; set; } =
    [
        new()
        {
            LogName = "Security",
            EventIds = [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 5156, 5157]
        },
        new()
        {
            LogName = "System",
            // 7045=new service; 7031/7034=service crash/terminated (IIS W3SVC/WAS noise is useful)
            EventIds = [7045, 7031, 7034]
        },
        new()
        {
            // ASP.NET / IIS errors (Application log)
            LogName = "Application",
            EventIds =
            [
                1000, 1001, 1002,           // app crash / hang
                1309, 1310, 1325,           // ASP.NET unhandled / health
                2276, 2280, 2303, 2304,     // IIS module / WP issues (when logged to Application)
                5002, 5009, 5010, 5011, 5012, 5013 // WAS worker process failures
            ]
        },
        new()
        {
            // IIS configuration changes (if channel exists on host)
            LogName = "Microsoft-Windows-IIS-Configuration/Operational",
            EventIds = [29, 30, 40, 41, 50, 51, 52]
        },
        new()
        {
            // PowerShell ScriptBlock/Module logging (when policy is enabled)
            LogName = "Microsoft-Windows-PowerShell/Operational",
            EventIds = [4103, 4104, 4105, 4106]
        },
        new()
        {
            LogName = "Microsoft-Windows-WAS/Operational",
            EventIds = [5002, 5009, 5010, 5011, 5012, 5013, 5186]
        }
    ];
}

public sealed class EventChannelWatch
{
    public string LogName { get; set; } = "Security";
    public List<int> EventIds { get; set; } = [];
}

public sealed class NetworkCollectorOptions
{
    public const string SectionName = "Collectors";

    public bool NetworkConnections { get; set; } = true;
    public bool Enabled
    {
        get => NetworkConnections;
        set => NetworkConnections = value;
    }

    public int PollIntervalSeconds { get; set; } = 5;
    public bool CaptureUdp { get; set; } = true;
    public bool ResolveProcessDetails { get; set; } = true;
    public bool HashNewExecutables { get; set; } = true;
    public bool ResolveServices { get; set; } = true;
}

public sealed class IpLogFileInspectorOptions
{
    public const string SectionName = "Collectors";

    /// <summary>Read explicitly configured text logs and extract IP evidence.</summary>
    public bool IpLogFiles { get; set; } = true;

    public bool Enabled
    {
        get => IpLogFiles;
        set => IpLogFiles = value;
    }

    public int PollIntervalSeconds { get; set; } = 30;
    public int MaxFiles { get; set; } = 32;
    public int MaxBytesPerFile { get; set; } = 2 * 1024 * 1024;
    public int MaxEventsPerCycle { get; set; } = 200;
    public int AlertWindowMinutes { get; set; } = 5;
    public int AuthFailureBurstMin { get; set; } = 10;
    public int WebProbeBurstMin { get; set; } = 5;

    /// <summary>
    /// Keep the initial scope explicit. Missing paths are ignored; no drive-wide scan occurs.
    /// </summary>
    public List<string> Paths { get; set; } =
    [
        @"C:\ProgramData\NTShield\Agent\logs\*.log",
        @"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
        @"C:\inetpub\logs\LogFiles\W3SVC*\*.log",
        @"C:\ProgramData\ssh\logs\*.log"
    ];
}

public sealed class ProcessCollectorOptions
{
    public const string SectionName = "Collectors";

    public bool Processes { get; set; } = true;
    public bool Services { get; set; } = true;
    public bool Enabled
    {
        get => Processes;
        set => Processes = value;
    }

    public int PollIntervalSeconds { get; set; } = 30;
    public bool HashExecutables { get; set; } = true;
    public bool UseWmiFallback { get; set; } = true;
}

public sealed class ScheduledTaskCollectorOptions
{
    public const string SectionName = "Collectors";

    public bool ScheduledTasks { get; set; } = true;
    public bool Enabled
    {
        get => ScheduledTasks;
        set => ScheduledTasks = value;
    }

    public int PollIntervalSeconds { get; set; } = 60;
}

public sealed class DetectionOptions
{
    public const string SectionName = "Detection";

    public bool Enabled { get; set; } = true;
    public string RulesPath { get; set; } = "config/rules.json";
    public string AllowlistPath { get; set; } = "config/allowlist.json";
    public int EvaluationIntervalSeconds { get; set; } = 10;
    public List<string> AllowlistUsernames { get; set; } = [];
    public List<string> AllowlistSourceIps { get; set; } = [];

    /// <summary>Watch file activity for ransomware-style mass changes.</summary>
    public bool FileActivityMonitoring { get; set; } = true;
    public List<string> FileActivityPaths { get; set; } = [@"C:\Users"];
    public List<string> FileActivityExcludedPaths { get; set; } =
    [
        @"\AppData\Local\Temp\",
        @"\AppData\Local\Microsoft\",
        @"\AppData\Local\Packages\",
        @"\NTShield\Agent\logs\",
        @"\NTShield\Agent\evidence\"
    ];
    public bool CanaryFiles { get; set; } = true;
    public string CanaryDirectory { get; set; } = string.Empty;
    public int FileActivityWindowSeconds { get; set; } = 60;
    public int FileActivityMinEvents { get; set; } = 80;
    public int FileActivityMinRenames { get; set; } = 20;
    public int FileActivityMinDeletes { get; set; } = 20;
    public int FileActivityEntropySamples { get; set; } = 32;
    public double FileActivityHighEntropyThreshold { get; set; } = 7.2;
    public double FileActivityHighEntropyRatio { get; set; } = 0.65;
    public int FileActivityCooldownMinutes { get; set; } = 10;

    /// <summary>Enable PowerShell ScriptBlock/Operational telemetry when supported.</summary>
    public bool EnablePowerShellTelemetry { get; set; } = true;
}

public sealed class AntivirusOptions
{
    public const string SectionName = "Antivirus";

    public bool Enabled { get; set; } = true;
    public bool RealTimeMonitoring { get; set; } = true;
    public bool ScheduledScanEnabled { get; set; } = true;
    public int ScheduledScanIntervalHours { get; set; } = 24;
    public List<string> ScanPaths { get; set; } = [@"C:\Users", @"C:\ProgramData"];
    public List<string> ExcludedPaths { get; set; } =
    [
        @"\AppData\Local\Temp\",
        @"\NTShield\Agent\",
        @"\Windows\WinSxS\"
    ];
    public string YaraExecutablePath { get; set; } = "tools\\yara64.exe";
    public string LocalProtectionPackPath { get; set; } = "config\\protection-pack.json";
    public string ProtectionDataDirectory { get; set; } = "protection";
    public string QuarantineDirectoryName { get; set; } = "quarantine";
    public string ProtectionPublicKeyPem { get; set; } = string.Empty;
    public int MaxFileSizeMb { get; set; } = 256;
    public int MaxRealtimeQueue { get; set; } = 1024;
    public int ScanTimeoutSeconds { get; set; } = 60;
    public int ScheduledScanMaxFiles { get; set; } = 5000;
    public bool EnableDefender { get; set; } = true;
    public bool EnableYara { get; set; } = true;
}

public sealed class ResponseOptions
{
    public const string SectionName = "Response";

    /// <summary>Default true: detect-only, no block/kill without central approval (IDS). Set false for IPS auto-block.</summary>
    public bool DetectOnly { get; set; } = true;
    public bool Enabled { get; set; } = true;
    public bool AllowNetworkIsolation { get; set; }
    public bool AllowProcessTerminate { get; set; }
    public bool LogOnlyMode { get; set; } = true;
    public string EvidenceDirectory { get; set; } = @"C:\ProgramData\NTShield\Agent\evidence";

    /// <summary>Ids | Ips — when Ips, local detections may auto-block (see AutoBlock*).</summary>
    public string Mode { get; set; } = "Ids";

    /// <summary>Minimum severity that triggers auto-block in IPS mode: Medium | High | Critical.</summary>
    public string AutoBlockMinSeverity { get; set; } = "High";

    /// <summary>In IPS mode, auto block inbound from alert.SourceIp.</summary>
    public bool AutoBlockSourceIp { get; set; } = true;

    /// <summary>In IPS mode, auto block outbound to alert.DestinationIp.</summary>
    public bool AutoBlockDestinationIp { get; set; } = true;

    /// <summary>In IPS mode, also block destination port if present on related connection evidence (optional).</summary>
    public bool AutoBlockDestinationPort { get; set; }

    /// <summary>Never auto-quarantine whole host unless true (dangerous).</summary>
    public bool AutoQuarantineHost { get; set; }
}

public sealed class LoggingPathsOptions
{
    public const string SectionName = "LoggingPaths";

    public string Directory { get; set; } = @"C:\ProgramData\NTShield\Agent\logs";
    public string FileName { get; set; } = "agent-.log";
    public int RetainedFileCountLimit { get; set; } = 31;
    public long FileSizeLimitBytes { get; set; } = 50 * 1024 * 1024;
}
