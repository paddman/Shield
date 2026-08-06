using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NTShield.Agent;

/// <summary>
/// Host CPU / memory / disk / disk I/O / network RX·TX via Win32 + counters + NIC stats.
/// Rates need two samples (warmup or successive heartbeats).
/// </summary>
internal static class WindowsHostMetrics
{
    private static long _prevIdle;
    private static long _prevKernel;
    private static long _prevUser;
    private static bool _cpuSeeded;

    private static PerformanceCounter? _diskRead;
    private static PerformanceCounter? _diskWrite;
    private static bool _diskCountersInit;
    private static bool _diskCountersFailed;

    private static long _prevNetRx;
    private static long _prevNetTx;
    private static DateTimeOffset _prevNetAt = DateTimeOffset.MinValue;
    private static bool _netSeeded;

    public sealed record Snapshot(
        double? CpuPercent,
        double? MemUsedPercent,
        long? HostMemUsedBytes,
        long? HostMemTotalBytes,
        double? DiskUsedPercent,
        double? DiskReadBytesPerSec,
        double? DiskWriteBytesPerSec,
        double? NetworkRxBytesPerSec,
        double? NetworkTxBytesPerSec);

    public static Snapshot Sample()
    {
        var cpu = SampleCpuPercent();
        var (memPct, used, total) = SampleMemory();
        var disk = SampleSystemDiskPercent();
        var (ioR, ioW) = SampleDiskIo();
        var (netRx, netTx) = SampleNetwork();
        return new Snapshot(cpu, memPct, used, total, disk, ioR, ioW, netRx, netTx);
    }

    /// <summary>Seed CPU + disk I/O + network so the next Sample has real rates.</summary>
    public static void Warmup(int waitMs = 350)
    {
        SampleCpuPercent();
        EnsureDiskCounters();
        try
        {
            _ = _diskRead?.NextValue();
            _ = _diskWrite?.NextValue();
        }
        catch
        {
            // ignore
        }

        // Seed network totals (first sample has no rate)
        _ = SampleNetwork();

        if (waitMs > 0)
            Thread.Sleep(waitMs);

        SampleCpuPercent();
        try
        {
            _ = _diskRead?.NextValue();
            _ = _diskWrite?.NextValue();
        }
        catch
        {
            // ignore
        }

        _ = SampleNetwork();
    }

    public static void WarmupCpu(int waitMs = 250) => Warmup(waitMs);

    public static double? SampleCpuPercent()
    {
        if (!GetSystemTimes(out var idleFt, out var kernelFt, out var userFt))
            return null;

        var idle = FileTimeToLong(idleFt);
        var kernel = FileTimeToLong(kernelFt);
        var user = FileTimeToLong(userFt);

        if (!_cpuSeeded)
        {
            _prevIdle = idle;
            _prevKernel = kernel;
            _prevUser = user;
            _cpuSeeded = true;
            return null;
        }

        var dIdle = idle - _prevIdle;
        var dKernel = kernel - _prevKernel;
        var dUser = user - _prevUser;
        _prevIdle = idle;
        _prevKernel = kernel;
        _prevUser = user;

        var total = dKernel + dUser;
        if (total <= 0) return 0;
        var busy = total - dIdle;
        if (busy < 0) busy = 0;
        return Math.Clamp(100.0 * busy / total, 0, 100);
    }

    /// <summary>
    /// Sum BytesReceived/Sent across active non-loopback NICs; rate = delta / elapsed.
    /// More reliable than PerformanceCounter instance names (locale / rename issues).
    /// </summary>
    private static (double? RxBps, double? TxBps) SampleNetwork()
    {
        try
        {
            long rx = 0, tx = 0;
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                        continue;

                    var name = ni.Name ?? "";
                    var desc = ni.Description ?? "";
                    // Skip common virtual/noise adapters that double-count or stay idle
                    if (IsVirtualNic(name, desc)) continue;

                    var stats = ni.GetIPStatistics();
                    rx += stats.BytesReceived;
                    tx += stats.BytesSent;
                }
                catch
                {
                    // skip this NIC
                }
            }

            var now = DateTimeOffset.UtcNow;
            if (!_netSeeded || _prevNetAt == DateTimeOffset.MinValue)
            {
                _prevNetRx = rx;
                _prevNetTx = tx;
                _prevNetAt = now;
                _netSeeded = true;
                return (null, null);
            }

            var elapsed = Math.Max(0.5, (now - _prevNetAt).TotalSeconds);
            double rxBps = 0, txBps = 0;
            if (rx >= _prevNetRx)
                rxBps = (rx - _prevNetRx) / elapsed;
            if (tx >= _prevNetTx)
                txBps = (tx - _prevNetTx) / elapsed;

            _prevNetRx = rx;
            _prevNetTx = tx;
            _prevNetAt = now;
            return (Math.Max(0, rxBps), Math.Max(0, txBps));
        }
        catch
        {
            return (null, null);
        }
    }

    private static bool IsVirtualNic(string name, string desc)
    {
        static bool Hit(string s) =>
            s.Contains("Loopback", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("isatap", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Teredo", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Pseudo", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("VMware", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Hyper-V Virtual Ethernet", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase);

        return Hit(name) || Hit(desc);
    }

    private static (double? ReadBps, double? WriteBps) SampleDiskIo()
    {
        EnsureDiskCounters();
        if (_diskCountersFailed || _diskRead is null || _diskWrite is null)
            return (null, null);

        try
        {
            var r = (double)_diskRead.NextValue();
            var w = (double)_diskWrite.NextValue();
            if (r < 0) r = 0;
            if (w < 0) w = 0;
            return (r, w);
        }
        catch
        {
            return (null, null);
        }
    }

    private static void EnsureDiskCounters()
    {
        if (_diskCountersInit) return;
        _diskCountersInit = true;
        try
        {
            _diskRead = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total", readOnly: true);
            _diskWrite = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total", readOnly: true);
            _ = _diskRead.NextValue();
            _ = _diskWrite.NextValue();
        }
        catch
        {
            _diskCountersFailed = true;
            try { _diskRead?.Dispose(); } catch { /* ignore */ }
            try { _diskWrite?.Dispose(); } catch { /* ignore */ }
            _diskRead = null;
            _diskWrite = null;
        }
    }

    private static (double? Pct, long? Used, long? Total) SampleMemory()
    {
        try
        {
            var st = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (!GlobalMemoryStatusEx(ref st) || st.ullTotalPhys == 0)
                return (null, null, null);

            var total = (long)st.ullTotalPhys;
            var avail = (long)st.ullAvailPhys;
            var used = total - avail;
            var pct = Math.Clamp(100.0 * used / total, 0, 100);
            return (pct, used, total);
        }
        catch
        {
            return (null, null, null);
        }
    }

    private static double? SampleSystemDiskPercent()
    {
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            var sys = DriveInfo.GetDrives().FirstOrDefault(d =>
                d.IsReady && d.Name.StartsWith(root, StringComparison.OrdinalIgnoreCase));
            if (sys is { TotalSize: > 0 })
                return Math.Clamp(100.0 * (1.0 - (double)sys.AvailableFreeSpace / sys.TotalSize), 0, 100);
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static long FileTimeToLong(FILETIME ft) =>
        ((long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FILETIME idleTime, out FILETIME kernelTime, out FILETIME userTime);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
}
