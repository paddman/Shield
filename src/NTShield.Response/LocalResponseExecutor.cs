using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text.Json;
using NTShield.Core.Abstractions;
using NTShield.Core.Compatibility;
using NTShield.Core.Configuration;
using NTShield.Core.Security;
using NTShield.Response.Firewall;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Response;

/// <summary>
/// Response engine supporting IDS (detect-only) and IPS (auto prevention) modes.
/// Default = IDS. IPS auto-blocks only when Mode=Ips and severity threshold is met.
/// Central-approved actions always run when Approved=true.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LocalResponseExecutor : IResponseExecutor
{
    private readonly ResponseOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly RuntimePolicyState _runtimePolicy;
    private readonly FirewallBlocker _firewall;
    private readonly IEvidenceCollector? _evidence;
    private readonly ILogger<LocalResponseExecutor> _logger;

    public LocalResponseExecutor(
        IOptions<ResponseOptions> options,
        IOptions<AgentOptions> agentOptions,
        RuntimePolicyState runtimePolicy,
        FirewallBlocker firewall,
        ILogger<LocalResponseExecutor> logger,
        IEvidenceCollector? evidence = null)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _runtimePolicy = runtimePolicy;
        _firewall = firewall;
        _logger = logger;
        _evidence = evidence;
    }

    public bool IsIpsMode
    {
        get
        {
            var mode = _runtimePolicy.PolicyVersion > 0 ? _runtimePolicy.Mode : _options.Mode;
            var detectOnly = _runtimePolicy.PolicyVersion > 0 ? _runtimePolicy.DetectOnly : (_options.DetectOnly || _agentOptions.DetectOnly);
            return string.Equals(mode, "Ips", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(mode, "IPS", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(_agentOptions.Mode, "Ips", StringComparison.OrdinalIgnoreCase) ||
                   (!detectOnly && !_options.LogOnlyMode);
        }
    }

    public bool IsIdsMode => !IsIpsMode;

    public async Task<ResponseActionRecord> ExecuteAsync(DetectionAlert alert, CancellationToken cancellationToken)
    {
        // --- IDS path: always log ---
        if (IsIdsMode || !MeetsAutoBlockSeverity(alert.Severity))
        {
            var record = BaseRecord("LogOnly", alert.AlertId, string.Empty);
            record.Requester = "local-ids";
            record.Reason = $"IDS {alert.RuleId}: {alert.Title}";
            record.Status = "Completed";
            record.BeforeState = "n/a";
            record.Result = IsIdsMode
                ? "IDS detect-only: alert logged, no containment"
                : $"IDS: severity {alert.Severity} below auto-block threshold {_options.AutoBlockMinSeverity}";
            record.RollbackCommand = string.Empty;
            record.AuditLog = Audit(record, "ids-log");
            _logger.LogWarning("IDS alert {Rule} sev={Sev} AlertId={AlertId}", alert.RuleId, alert.Severity, alert.AlertId);
            return record;
        }

        // --- IPS path: log + automatic prevention ---
        var combined = BaseRecord("IpsAutoBlock", alert.AlertId, string.Empty);
        combined.Requester = "local-ips";
        combined.Reason = $"IPS auto-prevent {alert.RuleId}: {alert.Title}";
        combined.Approved = true;
        combined.ApprovalId = "local-ips-policy";
        var results = new List<string>();
        var rollbacks = new List<string>();
        var before = _firewall.CaptureFirewallStatus();
        combined.BeforeState = before.Length > 1500 ? before[..1500] : before;

        try
        {
            if (_options.AutoBlockSourceIp &&
                !string.IsNullOrWhiteSpace(alert.SourceIp) &&
                IsPublicishIp(alert.SourceIp))
            {
                var rule = $"NTS-IPS-Src-{SanitizeToken(alert.SourceIp)}-{alert.AlertId[..8]}";
                var r = _firewall.BlockIp(alert.SourceIp, "in", rule, combined.Reason);
                results.Add(r.Success ? $"block-src {alert.SourceIp} OK" : $"block-src FAIL {r.Error}");
                if (!string.IsNullOrEmpty(r.RollbackCommand))
                {
                    rollbacks.Add(r.RollbackCommand);
                }

                _logger.LogWarning("IPS auto-block SOURCE {Ip} rule={Rule} ok={Ok}", alert.SourceIp, rule, r.Success);
            }

            if (_options.AutoBlockDestinationIp &&
                !string.IsNullOrWhiteSpace(alert.DestinationIp) &&
                IsPublicishIp(alert.DestinationIp))
            {
                var rule = $"NTS-IPS-Dst-{SanitizeToken(alert.DestinationIp)}-{alert.AlertId[..8]}";
                var r = _firewall.BlockIp(alert.DestinationIp, "out", rule, combined.Reason);
                results.Add(r.Success ? $"block-dst {alert.DestinationIp} OK" : $"block-dst FAIL {r.Error}");
                if (!string.IsNullOrEmpty(r.RollbackCommand))
                {
                    rollbacks.Add(r.RollbackCommand);
                }

                _logger.LogWarning("IPS auto-block DEST {Ip} rule={Rule} ok={Ok}", alert.DestinationIp, rule, r.Success);
            }

            if (_options.AutoBlockDestinationPort &&
                TryExtractPort(alert, out var port) &&
                port is > 0 and <= 65535)
            {
                var rule = $"NTS-IPS-Port-{port}-{alert.AlertId[..8]}";
                var r = _firewall.BlockPort("out", "tcp", null, port, alert.DestinationIp, rule, combined.Reason);
                results.Add(r.Success ? $"block-port {port} OK" : $"block-port FAIL {r.Error}");
                if (!string.IsNullOrEmpty(r.RollbackCommand))
                {
                    rollbacks.Add(r.RollbackCommand);
                }
            }

            if (results.Count == 0)
            {
                combined.Status = "Completed";
                combined.Result = "IPS: no blockable IP/port on alert (logged only)";
            }
            else
            {
                var anyFail = results.Exists(x => x.Contains("FAIL", StringComparison.Ordinal));
                combined.Status = anyFail ? "Partial" : "Completed";
                combined.Result = "IPS: " + string.Join("; ", results);
                combined.RollbackCommand = string.Join(" && ", rollbacks);
            }
        }
        catch (Exception ex)
        {
            combined.Status = "Failed";
            combined.Error = ex.Message;
            _logger.LogError(ex, "IPS auto-block failed for {Rule}", alert.RuleId);
        }

        combined.AuditLog = Audit(combined, "ips-auto");
        await Task.CompletedTask;
        return combined;
    }

    public async Task<ResponseActionRecord> ExecuteRequestAsync(ResponseActionRequest request, CancellationToken cancellationToken)
    {
        var record = BaseRecord(request.ActionType, request.AlertId ?? string.Empty, request.IncidentId ?? string.Empty);
        record.RequestId = string.IsNullOrWhiteSpace(request.RequestId) ? record.RequestId : request.RequestId;
        record.Requester = request.Requester;
        record.Reason = request.Reason;
        record.Approved = request.Approved;
        record.ApprovalId = request.ApprovalId;
        record.RequiresApproval = RequiresApproval(request.ActionType);

        if (!EventDataSanitizer.IsAllowlistedCommand(request.ActionType))
        {
            record.Status = "Rejected";
            record.Error = "Action type not in allowlist (arbitrary commands forbidden).";
            record.AuditLog = Audit(record, "rejected allowlist");
            return record;
        }

        // Hard rule: destructive actions need explicit Central approval (unless local IPS already set Approved).
        if (record.RequiresApproval && !request.Approved)
        {
            record.Status = "PendingApproval";
            record.Result = "Blocked by policy: explicit Central Server approval required.";
            record.AuditLog = Audit(record, "missing approval");
            return record;
        }

        if (IsIdsMode &&
            record.RequiresApproval &&
            !request.Approved)
        {
            record.Status = "Skipped";
            record.Result = "IDS/DetectOnly=true";
            record.AuditLog = Audit(record, "ids-mode");
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

                case "BlockDestinationIp":
                    {
                        var ip = request.TargetIp ?? throw new ArgumentException("TargetIp required");
                        var rule = request.RuleName ?? $"NTS-Block-Dst-{SanitizeToken(ip)}-{record.RequestId[..8]}";
                        var dir = string.IsNullOrWhiteSpace(request.Direction) ? "out" : request.Direction!;
                        var result = _firewall.BlockIp(ip, dir, EnsureCsa(rule), request.Reason);
                        ApplyFirewall(record, result);
                        break;
                    }

                case "BlockSourceIp":
                case "BlockRemoteIp":
                    {
                        var ip = request.TargetIp ?? throw new ArgumentException("TargetIp required");
                        var rule = request.RuleName ?? $"NTS-Block-Src-{SanitizeToken(ip)}-{record.RequestId[..8]}";
                        var dir = string.IsNullOrWhiteSpace(request.Direction) ? "in" : request.Direction!;
                        var result = _firewall.BlockIp(ip, dir, EnsureCsa(rule), request.Reason);
                        ApplyFirewall(record, result);
                        break;
                    }

                case "BlockPort":
                    {
                        var rule = request.RuleName ??
                                   $"NTS-Block-Port-{request.TargetPort ?? 0}-{record.RequestId[..8]}";
                        var dir = string.IsNullOrWhiteSpace(request.Direction) ? "in" : request.Direction!;
                        var proto = string.IsNullOrWhiteSpace(request.Protocol) ? "tcp" : request.Protocol!;
                        int? localPort = request.TargetPort;
                        int? remotePort = null;
                        if (string.Equals(request.ServiceName, "remote", StringComparison.OrdinalIgnoreCase))
                        {
                            remotePort = request.TargetPort;
                            localPort = null;
                        }

                        var result = _firewall.BlockPort(dir, proto, localPort, remotePort, request.TargetIp,
                            EnsureCsa(rule), request.Reason);
                        ApplyFirewall(record, result);
                        break;
                    }

                case "OpenPort":
                    {
                        var port = request.TargetPort ?? throw new ArgumentException("TargetPort required for OpenPort");
                        var rule = request.RuleName ?? $"NTS-Open-Port-{port}-{record.RequestId[..8]}";
                        var dir = string.IsNullOrWhiteSpace(request.Direction) ? "in" : request.Direction!;
                        var proto = string.IsNullOrWhiteSpace(request.Protocol) ? "tcp" : request.Protocol!;
                        var result = _firewall.OpenPort(dir, proto, port, EnsureCsa(rule), request.Reason);
                        ApplyFirewall(record, result);
                        break;
                    }

                case "ClosePort":
                case "RemoveFirewallBlock":
                    {
                        var ruleName = request.RuleName ?? request.ServiceName ?? request.TargetIp;
                        if (string.IsNullOrWhiteSpace(ruleName) ||
                            !ruleName.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new ArgumentException(
                                "Provide NTS- rule name in RuleName (or ServiceName) to close/remove firewall rule.");
                        }

                        var result = _firewall.RemoveRule(ruleName);
                        ApplyFirewall(record, result);
                        break;
                    }

                case "StopService":
                    await ControlServiceAsync(record, request.ServiceName, "stop", cancellationToken);
                    break;

                case "StartService":
                    await ControlServiceAsync(record, request.ServiceName, "start", cancellationToken);
                    break;

                case "RestartService":
                    await ControlServiceAsync(record, request.ServiceName, "restart", cancellationToken);
                    break;

                case "DisableService":
                    await ControlServiceAsync(record, request.ServiceName, "disable", cancellationToken);
                    break;

                case "EnableService":
                    await ControlServiceAsync(record, request.ServiceName, "enable", cancellationToken);
                    break;

                case "StopScheduledTask":
                    ControlTask(record, request, disable: false);
                    break;

                case "DisableScheduledTask":
                    ControlTask(record, request, disable: true);
                    break;

                case "TerminateProcess":
                    if (!_options.AllowProcessTerminate &&
                        !string.Equals(request.Requester, "dashboard-operator", StringComparison.OrdinalIgnoreCase))
                    {
                        record.Status = "Rejected";
                        record.Error = "AllowProcessTerminate=false";
                        break;
                    }

                    TerminateProcess(record, request.ProcessId);
                    break;

                case "ExportEvidence":
                    {
                        if (_evidence is null)
                        {
                            record.Status = "Failed";
                            record.Error = "Evidence collector not registered";
                            break;
                        }

                        var incident = new Incident
                        {
                            IncidentId = request.IncidentId ?? record.RequestId,
                            Title = "Evidence export",
                            SourceIp = request.TargetIp
                        };
                        var path = await _evidence.CollectAndExportZipAsync(incident, cancellationToken);
                        record.Status = "Completed";
                        record.Result = path;
                        record.BeforeState = "n/a";
                        record.RollbackCommand = $"Remove-Item -LiteralPath '{path}'";
                        break;
                    }

                case "QuarantineHost":
                    {
                        if (!_options.AutoQuarantineHost &&
                            !request.Approved)
                        {
                            record.Status = "Rejected";
                            record.Error = "Quarantine requires approved Central/Dashboard action";
                            break;
                        }

                        record.BeforeState = _firewall.CaptureFirewallStatus();
                        var r1 = _firewall.BlockIp("0.0.0.0/0", "in", $"NTS-Quarantine-In-{record.RequestId[..8]}", request.Reason);
                        // 0.0.0.0/0 may fail validation — use alternative
                        if (!r1.Success)
                        {
                            record.Result = $"Quarantine limited: {r1.Error}. Prefer per-IP IPS blocks or NAC.";
                            record.Status = "Failed";
                            record.Error = r1.Error;
                        }
                        else
                        {
                            record.Result = "Quarantine inbound rule applied";
                            record.RollbackCommand = r1.RollbackCommand;
                            record.Status = "Completed";
                        }

                        break;
                    }

                default:
                    record.Status = "Rejected";
                    record.Error = "Unhandled action type";
                    break;
            }
        }
        catch (Exception ex)
        {
            record.Status = "Failed";
            record.Error = ex.Message;
            _logger.LogError(ex, "Response action {Type} failed", request.ActionType);
        }

        record.AuditLog = Audit(record, "executed");
        return record;
    }

    private bool MeetsAutoBlockSeverity(Severity severity)
    {
        var min = ParseSeverity(_options.AutoBlockMinSeverity);
        return severity >= min;
    }

    private static Severity ParseSeverity(string? s)
    {
        if (Enum.TryParse<Severity>(s, true, out var v))
        {
            return v;
        }

        return Severity.High;
    }

    private static bool IsPublicishIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr))
        {
            return false;
        }

        // Still allow private RFC1918 — lateral movement is internal. Block loopback only.
        if (System.Net.IPAddress.IsLoopback(addr))
        {
            return false;
        }

        return true;
    }

    private static bool TryExtractPort(DetectionAlert alert, out int port)
    {
        port = 0;
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(alert.EvidenceJson) ? "[]" : alert.EvidenceJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.TryGetProperty("RemotePort", out var p) && p.TryGetInt32(out port) && port > 0)
                {
                    return true;
                }

                if (el.TryGetProperty("remotePort", out p) && p.TryGetInt32(out port) && port > 0)
                {
                    return true;
                }

                if (el.TryGetProperty("DestinationPort", out p) && p.TryGetInt32(out port) && port > 0)
                {
                    return true;
                }
            }
        }
        catch
        {
            // ignore
        }

        return false;
    }

    private static bool RequiresApproval(string actionType) =>
        actionType is not ("LogOnly" or "ExportEvidence");

    private void ApplyFirewall(ResponseActionRecord record, FirewallChangeResult result)
    {
        record.BeforeState = result.BeforeState;
        record.Result = result.Result + (result.RuleName is null ? "" : $" rule={result.RuleName}");
        record.RollbackCommand = result.RollbackCommand;
        record.Status = result.Success ? "Completed" : "Failed";
        record.Error = result.Error;
    }

    /// <param name="action">start | stop | restart | disable | enable</param>
    private Task ControlServiceAsync(ResponseActionRecord record, string? serviceName, string action, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.IndexOfAny(['"', ';', '&', '|', '\n', '\r']) >= 0)
        {
            throw new ArgumentException("Invalid service name");
        }

        serviceName = serviceName.Trim();
        // Protect critical OS services from stop/disable via agent
        if (action is "stop" or "restart" or "disable" &&
            IsProtectedService(serviceName))
        {
            record.Status = "Rejected";
            record.Error = $"Service '{serviceName}' is protected (cannot {action} via agent).";
            return Task.CompletedTask;
        }

        try
        {
            using var sc = new ServiceController(serviceName);
            var before = $"{sc.Status}; StartType={sc.StartType}";
            record.BeforeState = before;
            var timeout = TimeSpan.FromSeconds(45);

            switch (action.ToLowerInvariant())
            {
                case "start":
                    if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
                    {
                        record.Result = $"already {sc.Status}";
                        record.Status = "Completed";
                        break;
                    }

                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    record.Result = "service started";
                    record.Status = "Completed";
                    record.RollbackCommand = $"sc.exe stop \"{serviceName}\"";
                    break;

                case "stop":
                    if (sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
                    {
                        record.Result = $"already {sc.Status}";
                        record.Status = "Completed";
                        break;
                    }

                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    record.Result = "service stopped";
                    record.Status = "Completed";
                    record.RollbackCommand = $"sc.exe start \"{serviceName}\"";
                    break;

                case "restart":
                    if (sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    sc.Refresh();
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    record.Result = "service restarted";
                    record.Status = "Completed";
                    record.RollbackCommand = null;
                    break;

                case "disable":
                    // Prefer WMI ChangeStartMode + Stop
                    SetStartModeWmi(serviceName, "Disabled");
                    sc.Refresh();
                    if (sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    record.Result = "service stopped and disabled";
                    record.Status = "Completed";
                    record.RollbackCommand = $"sc.exe config \"{serviceName}\" start= demand & sc.exe start \"{serviceName}\"";
                    break;

                case "enable":
                    SetStartModeWmi(serviceName, "Automatic");
                    record.Result = "service set to Automatic (not started)";
                    record.Status = "Completed";
                    record.RollbackCommand = $"sc.exe config \"{serviceName}\" start= disabled";
                    break;

                default:
                    record.Status = "Rejected";
                    record.Error = "Unknown service action: " + action;
                    break;
            }
        }
        catch (InvalidOperationException ex)
        {
            record.Status = "Failed";
            record.Error = "Service not found or access denied: " + ex.Message;
        }
        catch (System.ServiceProcess.TimeoutException ex)
        {
            record.Status = "Failed";
            record.Error = "Timeout waiting for service state: " + ex.Message;
        }
        catch (System.TimeoutException ex)
        {
            record.Status = "Failed";
            record.Error = "Timeout waiting for service state: " + ex.Message;
        }
        catch (Exception ex)
        {
            record.Status = "Failed";
            record.Error = ex.Message;
            _logger.LogError(ex, "Service control {Action} failed for {Name}", action, serviceName);
        }

        return Task.CompletedTask;
    }

    private static bool IsProtectedService(string name)
    {
        // Service short names (not display names)
        var n = name.Trim();
        return n.Equals("RpcSs", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("DcomLaunch", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("LSM", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("SamSs", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("WinDefend", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("EventLog", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("PlugPlay", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("Power", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("Schedule", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("ProfSvc", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("UserManager", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("NTShieldAgent", StringComparison.OrdinalIgnoreCase) ||
               n.Equals("NTShieldCentral", StringComparison.OrdinalIgnoreCase);
    }

    private static void SetStartModeWmi(string serviceName, string mode)
    {
        using var searcher = new ManagementObjectSearcher(
            $"SELECT Name FROM Win32_Service WHERE Name = '{EscapeWmi(serviceName)}'");
        foreach (ManagementObject obj in searcher.Get())
        {
            using (obj)
            {
                obj.InvokeMethod("ChangeStartMode", new object[] { mode });
            }

            return;
        }

        throw new InvalidOperationException("Service not found for start-mode change: " + serviceName);
    }

    private void ControlTask(ResponseActionRecord record, ResponseActionRequest request, bool disable)
    {
        var path = request.TaskPath ?? "\\";
        var name = request.TaskName ?? throw new ArgumentException("TaskName required");
        if (name.Contains("..") || path.Contains(".."))
        {
            throw new InvalidOperationException("Path traversal rejected");
        }

        var taskServiceType = Type.GetTypeFromProgID("Schedule.Service")
                              ?? throw new InvalidOperationException("Schedule.Service unavailable");
        dynamic service = Activator.CreateInstance(taskServiceType)!;
        service.Connect();
        dynamic folder = service.GetFolder(path);
        dynamic task = folder.GetTask(name);
        record.BeforeState = $"Enabled={task.Enabled}";
        if (disable)
        {
            task.Enabled = false;
            record.Result = "task disabled";
            record.RollbackCommand = $"# re-enable task {path}{name}";
        }
        else
        {
            task.Stop(0);
            record.Result = "task stopped";
            record.RollbackCommand = $"# task stop is transient for {path}{name}";
        }

        record.Status = "Completed";
    }

    private void TerminateProcess(ResponseActionRecord record, int? pid)
    {
        if (pid is null or <= 0)
        {
            throw new ArgumentException("ProcessId required");
        }

        using var proc = Process.GetProcessById(pid.Value);
        record.BeforeState = $"PID={pid};Name={proc.ProcessName}";
        proc.Kill();
        record.Result = "process terminated";
        record.RollbackCommand = "# process termination is not reversible";
        record.Status = "Completed";
    }

    private ResponseActionRecord BaseRecord(string actionType, string alertId, string incidentId) => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        ComputerName = _agentOptions.ComputerName,
        AgentId = _agentOptions.AgentId,
        AlertId = alertId,
        IncidentId = incidentId,
        ActionType = actionType,
        Status = "Pending"
    };

    private static string Audit(ResponseActionRecord r, string note) =>
        JsonSerializer.Serialize(new
        {
            r.RequestId,
            r.Requester,
            r.TimestampUtc,
            r.ActionType,
            r.Reason,
            r.BeforeState,
            r.Result,
            r.RollbackCommand,
            r.Status,
            r.Approved,
            r.ApprovalId,
            note
        });

    private static string EscapeWmi(string value) => value.Replace("'", "\\'");

    private static string SanitizeToken(string ip) =>
        new string(ip.Where(c => char.IsLetterOrDigit(c) || c is '.' or ':' or '-').ToArray());

    private static string EnsureCsa(string ruleName) =>
        ruleName.StartsWith("NTS-", StringComparison.OrdinalIgnoreCase)
            ? ruleName
            : "NTS-" + ruleName;
}
