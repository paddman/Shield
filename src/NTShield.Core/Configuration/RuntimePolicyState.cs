namespace NTShield.Core.Configuration;

/// <summary>
/// Mutable policy applied at runtime from Central heartbeat (avoids frozen IOptions snapshots).
/// Response/detection code should prefer this when set.
/// </summary>
public sealed class RuntimePolicyState
{
    private readonly object _gate = new();
    private int _policyVersion;
    private string _mode = "Ids";
    private bool _detectOnly = true;
    private bool _autoRemediate;
    private bool _allowProcessTerminate;
    private bool _allowNetworkIsolation = true;
    private bool _autoBlockSourceIp = true;
    private bool _autoBlockDestinationIp = true;
    private string _autoBlockMinSeverity = "High";
    private double _cpuAlertPercent = 90;
    private double _memAlertPercent = 90;
    private double _diskAlertPercent = 90;
    private int? _heartbeatSeconds;

    public int PolicyVersion
    {
        get { lock (_gate) return _policyVersion; }
    }

    public string Mode
    {
        get { lock (_gate) return _mode; }
    }

    public bool DetectOnly
    {
        get { lock (_gate) return _detectOnly; }
    }

    public bool AutoRemediate
    {
        get { lock (_gate) return _autoRemediate; }
    }

    public bool AllowProcessTerminate
    {
        get { lock (_gate) return _allowProcessTerminate; }
    }

    public bool AllowNetworkIsolation
    {
        get { lock (_gate) return _allowNetworkIsolation; }
    }

    public bool AutoBlockSourceIp
    {
        get { lock (_gate) return _autoBlockSourceIp; }
    }

    public bool AutoBlockDestinationIp
    {
        get { lock (_gate) return _autoBlockDestinationIp; }
    }

    public string AutoBlockMinSeverity
    {
        get { lock (_gate) return _autoBlockMinSeverity; }
    }

    public double CpuAlertPercent
    {
        get { lock (_gate) return _cpuAlertPercent; }
    }

    public double MemAlertPercent
    {
        get { lock (_gate) return _memAlertPercent; }
    }

    public double DiskAlertPercent
    {
        get { lock (_gate) return _diskAlertPercent; }
    }

    public int? HeartbeatSeconds
    {
        get { lock (_gate) return _heartbeatSeconds; }
    }

    public void SeedFromLocal(AgentOptions agent, ResponseOptions response)
    {
        lock (_gate)
        {
            _mode = string.IsNullOrWhiteSpace(agent.Mode) ? response.Mode : agent.Mode;
            _detectOnly = agent.DetectOnly || response.DetectOnly;
            _allowProcessTerminate = response.AllowProcessTerminate;
            _allowNetworkIsolation = response.AllowNetworkIsolation;
            _autoBlockSourceIp = response.AutoBlockSourceIp;
            _autoBlockDestinationIp = response.AutoBlockDestinationIp;
            _autoBlockMinSeverity = response.AutoBlockMinSeverity;
        }
    }

    /// <summary>Apply Central policy if version is newer. Returns true when applied.</summary>
    public bool TryApply(Shared.Models.AgentPolicy policy)
    {
        if (policy.PolicyVersion <= 0) return false;
        lock (_gate)
        {
            if (policy.PolicyVersion <= _policyVersion) return false;
            _policyVersion = policy.PolicyVersion;
            if (!string.IsNullOrWhiteSpace(policy.Mode))
                _mode = policy.Mode;
            _detectOnly = policy.DetectOnly;
            _autoRemediate = policy.AutoRemediate;
            _allowProcessTerminate = policy.AllowProcessTerminate;
            _allowNetworkIsolation = policy.AllowNetworkIsolation;
            _autoBlockSourceIp = policy.AutoBlockSourceIp;
            _autoBlockDestinationIp = policy.AutoBlockDestinationIp;
            if (!string.IsNullOrWhiteSpace(policy.AutoBlockMinSeverity))
                _autoBlockMinSeverity = policy.AutoBlockMinSeverity;
            if (policy.CpuAlertPercent is double c) _cpuAlertPercent = c;
            if (policy.MemAlertPercent is double m) _memAlertPercent = m;
            if (policy.DiskAlertPercent is double d) _diskAlertPercent = d;
            if (policy.HeartbeatSeconds is int hb && hb >= 15) _heartbeatSeconds = hb;
            return true;
        }
    }
}
