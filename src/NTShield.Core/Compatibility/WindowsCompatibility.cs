using System.Runtime.InteropServices;

namespace NTShield.Core.Compatibility;

/// <summary>
/// Runtime checks for Windows Server 2012 / 2012 R2 compatibility.
/// Prefer APIs available since Windows Server 2012 (NT 6.2). Do not call newer-only APIs
/// without guarding with these checks.
/// </summary>
public static class WindowsCompatibility
{
    // Windows Server 2012 = 6.2, 2012 R2 = 6.3, 2016 = 10.0 build 14393, etc.
    public static readonly Version MinimumSupported = new(6, 2);

    public static bool IsWindows =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public static Version OsVersion
    {
        get
        {
            if (!IsWindows)
            {
                return new Version(0, 0);
            }

            // Environment.OSVersion is reliable enough for major/minor gate on older Windows
            // when combined with application manifest supportingWin7/8 compatibility.
            var v = Environment.OSVersion.Version;
            return new Version(v.Major, v.Minor, v.Build);
        }
    }

    public static bool IsAtLeastWindowsServer2012 =>
        IsWindows && OsVersion >= MinimumSupported;

    public static bool IsWindows8OrServer2012 =>
        IsWindows && OsVersion.Major == 6 && OsVersion.Minor == 2;

    public static bool IsWindows81OrServer2012R2 =>
        IsWindows && OsVersion.Major == 6 && OsVersion.Minor == 3;

    public static bool IsWindows10OrServer2016OrLater =>
        IsWindows && OsVersion.Major >= 10;

    /// <summary>
    /// EventLogWatcher (System.Diagnostics.Eventing.Reader) is available on Server 2012+.
    /// </summary>
    public static bool SupportsEventLogWatcher => IsAtLeastWindowsServer2012;

    /// <summary>
    /// GetExtendedTcpTable / GetExtendedUdpTable available long before Server 2012.
    /// </summary>
    public static bool SupportsIpHelperExtendedTables => IsAtLeastWindowsServer2012;

    /// <summary>
    /// Task Scheduler 2.0 COM (ITaskService) available on Server 2008+.
    /// </summary>
    public static bool SupportsTaskSchedulerCom => IsAtLeastWindowsServer2012;

    /// <summary>
    /// QueryFullProcessImageName available since Vista / Server 2008.
    /// </summary>
    public static bool SupportsQueryFullProcessImageName => IsAtLeastWindowsServer2012;

    /// <summary>
    /// Windows Filtering Platform advanced isolation helpers vary by build.
    /// Keep disabled unless OS is Server 2016+ and policy enables it.
    /// </summary>
    public static bool SupportsAdvancedNetworkIsolation => IsWindows10OrServer2016OrLater;

    public static CompatibilityReport BuildReport()
    {
        return new CompatibilityReport
        {
            IsWindows = IsWindows,
            OsVersion = OsVersion.ToString(),
            MeetsMinimum = IsAtLeastWindowsServer2012,
            SupportsEventLogWatcher = SupportsEventLogWatcher,
            SupportsIpHelperExtendedTables = SupportsIpHelperExtendedTables,
            SupportsTaskSchedulerCom = SupportsTaskSchedulerCom,
            SupportsQueryFullProcessImageName = SupportsQueryFullProcessImageName,
            SupportsAdvancedNetworkIsolation = SupportsAdvancedNetworkIsolation,
            Notes = IsAtLeastWindowsServer2012
                ? "Host meets NT Shield minimum OS gate (Windows Server 2012+)."
                : "Host is below Windows Server 2012. Agent must not start collectors."
        };
    }
}

public sealed class CompatibilityReport
{
    public bool IsWindows { get; init; }
    public string OsVersion { get; init; } = string.Empty;
    public bool MeetsMinimum { get; init; }
    public bool SupportsEventLogWatcher { get; init; }
    public bool SupportsIpHelperExtendedTables { get; init; }
    public bool SupportsTaskSchedulerCom { get; init; }
    public bool SupportsQueryFullProcessImageName { get; init; }
    public bool SupportsAdvancedNetworkIsolation { get; init; }
    public string Notes { get; init; } = string.Empty;
}
