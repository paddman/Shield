using System.Globalization;

namespace NTShield.Agent.Linux.Collectors;

/// <summary>
/// Host metrics from /proc and DriveInfo — CPU, RAM, disk, network rates, disk I/O rates.
/// </summary>
internal sealed class HostMetricsCollector
{
    private CpuSample? _prevCpu;
    private NetSample? _prevNet;
    private IoSample? _prevIo;
    private DateTimeOffset _prevSampleAt = DateTimeOffset.MinValue;

    public HostMetrics Snapshot()
    {
        var now = DateTimeOffset.UtcNow;
        var elapsed = _prevSampleAt == DateTimeOffset.MinValue
            ? 1.0
            : Math.Max(0.5, (now - _prevSampleAt).TotalSeconds);

        var cpu = ReadCpu();
        var mem = ReadMemory();
        var disk = ReadDisks();
        var net = ReadNetwork();
        var io = ReadDiskIo();

        double? cpuPct = null;
        if (_prevCpu is not null && cpu is not null)
        {
            var dIdle = cpu.IdleAll - _prevCpu.IdleAll;
            var dTotal = cpu.Total - _prevCpu.Total;
            if (dTotal > 0)
                cpuPct = Math.Clamp(100.0 * (1.0 - (dIdle / dTotal)), 0, 100);
        }

        double rxBps = 0, txBps = 0;
        if (_prevNet is not null && net is not null)
        {
            rxBps = Math.Max(0, (net.RxBytes - _prevNet.RxBytes) / elapsed);
            txBps = Math.Max(0, (net.TxBytes - _prevNet.TxBytes) / elapsed);
        }

        double readBps = 0, writeBps = 0;
        if (_prevIo is not null && io is not null)
        {
            readBps = Math.Max(0, (io.ReadBytes - _prevIo.ReadBytes) / elapsed);
            writeBps = Math.Max(0, (io.WriteBytes - _prevIo.WriteBytes) / elapsed);
        }

        if (cpu is not null) _prevCpu = cpu;
        if (net is not null) _prevNet = net;
        if (io is not null) _prevIo = io;
        _prevSampleAt = now;

        var root = disk.FirstOrDefault(d => d.Mount == "/") ?? disk.OrderByDescending(d => d.TotalBytes).FirstOrDefault();

        return new HostMetrics
        {
            TimestampUtc = now,
            CpuPercent = cpuPct,
            MemTotalBytes = mem.TotalBytes,
            MemAvailableBytes = mem.AvailableBytes,
            MemUsedPercent = mem.TotalBytes > 0
                ? Math.Clamp(100.0 * (1.0 - (double)mem.AvailableBytes / mem.TotalBytes), 0, 100)
                : null,
            Disks = disk,
            RootDiskUsedPercent = root?.UsedPercent,
            RootMount = root?.Mount,
            NetworkRxBytesPerSec = rxBps,
            NetworkTxBytesPerSec = txBps,
            DiskReadBytesPerSec = readBps,
            DiskWriteBytesPerSec = writeBps,
            LoadAverage1 = ReadLoad1(),
            ProcessCount = CountProcesses()
        };
    }

    public string FormatStatusLine(HostMetrics m)
    {
        var parts = new List<string>();
        if (m.CpuPercent is double c) parts.Add($"cpu={c:F1}%");
        if (m.MemUsedPercent is double mem) parts.Add($"mem={mem:F1}%");
        if (m.RootDiskUsedPercent is double d)
            parts.Add($"disk={m.RootMount ?? "/"} {d:F1}%");
        parts.Add($"net_rx={FormatRate(m.NetworkRxBytesPerSec)} net_tx={FormatRate(m.NetworkTxBytesPerSec)}");
        parts.Add($"io_r={FormatRate(m.DiskReadBytesPerSec)} io_w={FormatRate(m.DiskWriteBytesPerSec)}");
        if (m.LoadAverage1 is double load) parts.Add($"load1={load:F2}");
        return string.Join(" ", parts);
    }

    private static string FormatRate(double bytesPerSec)
    {
        if (bytesPerSec >= 1_048_576) return $"{bytesPerSec / 1_048_576:F2}MB/s";
        if (bytesPerSec >= 1024) return $"{bytesPerSec / 1024:F1}KB/s";
        return $"{bytesPerSec:F0}B/s";
    }

    private static CpuSample? ReadCpu()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/stat"))
            {
                if (!line.StartsWith("cpu ", StringComparison.Ordinal)) continue;
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                // cpu user nice system idle iowait irq softirq steal guest guest_nice
                if (parts.Length < 5) return null;
                ulong user = ParseU(parts[1]);
                ulong nice = ParseU(parts[2]);
                ulong system = ParseU(parts[3]);
                ulong idle = ParseU(parts[4]);
                ulong iowait = parts.Length > 5 ? ParseU(parts[5]) : 0;
                ulong irq = parts.Length > 6 ? ParseU(parts[6]) : 0;
                ulong softirq = parts.Length > 7 ? ParseU(parts[7]) : 0;
                ulong steal = parts.Length > 8 ? ParseU(parts[8]) : 0;
                var idleAll = idle + iowait;
                var total = user + nice + system + idle + iowait + irq + softirq + steal;
                return new CpuSample(idleAll, total);
            }
        }
        catch
        {
            // non-Linux or restricted
        }

        return null;
    }

    private static (long TotalBytes, long AvailableBytes) ReadMemory()
    {
        long total = 0, available = 0, free = 0, buffers = 0, cached = 0;
        try
        {
            foreach (var line in File.ReadLines("/proc/meminfo"))
            {
                if (line.StartsWith("MemTotal:", StringComparison.Ordinal))
                    total = ParseKbLine(line);
                else if (line.StartsWith("MemAvailable:", StringComparison.Ordinal))
                    available = ParseKbLine(line);
                else if (line.StartsWith("MemFree:", StringComparison.Ordinal))
                    free = ParseKbLine(line);
                else if (line.StartsWith("Buffers:", StringComparison.Ordinal))
                    buffers = ParseKbLine(line);
                else if (line.StartsWith("Cached:", StringComparison.Ordinal))
                    cached = ParseKbLine(line);
            }

            if (available <= 0)
                available = free + buffers + cached;
        }
        catch
        {
            try
            {
                var gc = GC.GetGCMemoryInfo();
                total = gc.TotalAvailableMemoryBytes;
                available = total - GC.GetTotalMemory(false);
            }
            catch
            {
                // ignore
            }
        }

        return (total, available);
    }

    private static List<DiskMountMetrics> ReadDisks()
    {
        var list = new List<DiskMountMetrics>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady) continue;
                    // Skip special virtual fs
                    var root = d.Name.TrimEnd('/');
                    if (root is "/proc" or "/sys" or "/dev" or "/run" or "/snap") continue;
                    if (d.DriveType is DriveType.Network or DriveType.Ram or DriveType.NoRootDirectory)
                        continue;

                    var total = d.TotalSize;
                    if (total <= 0) continue;
                    var free = d.AvailableFreeSpace;
                    var usedPct = Math.Clamp(100.0 * (1.0 - (double)free / total), 0, 100);
                    var mount = string.IsNullOrEmpty(d.Name) ? "/" : d.Name.TrimEnd('/');
                    if (string.IsNullOrEmpty(mount)) mount = "/";
                    // On Linux DriveInfo.Name is often "/"
                    if (d.Name == "/") mount = "/";

                    list.Add(new DiskMountMetrics
                    {
                        Mount = mount == "" ? "/" : mount,
                        TotalBytes = total,
                        FreeBytes = free,
                        UsedPercent = usedPct,
                        FileSystem = d.DriveFormat
                    });
                }
                catch
                {
                    // skip unreadable mount
                }
            }
        }
        catch
        {
            // ignore
        }

        return list;
    }

    private static NetSample? ReadNetwork()
    {
        try
        {
            ulong rx = 0, tx = 0;
            foreach (var line in File.ReadLines("/proc/net/dev"))
            {
                var idx = line.IndexOf(':');
                if (idx < 0) continue;
                var iface = line[..idx].Trim();
                if (iface is "lo" or "face") continue;
                var rest = line[(idx + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (rest.Length < 9) continue;
                rx += ParseU(rest[0]);
                tx += ParseU(rest[8]);
            }

            return new NetSample(rx, tx);
        }
        catch
        {
            return null;
        }
    }

    private static IoSample? ReadDiskIo()
    {
        try
        {
            // /proc/diskstats: major minor name reads ... sectors_read ... writes ... sectors_written
            // field indices (0-based after name): 0 reads completed, 2 sectors read, 4 writes, 6 sectors written
            ulong readSectors = 0, writeSectors = 0;
            foreach (var line in File.ReadLines("/proc/diskstats"))
            {
                var p = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (p.Length < 14) continue;
                var name = p[2];
                // Whole disks only (sda, nvme0n1, vda) — skip partitions sda1
                if (name.StartsWith("loop", StringComparison.Ordinal) ||
                    name.StartsWith("ram", StringComparison.Ordinal) ||
                    name.StartsWith("dm-", StringComparison.Ordinal))
                    continue;
                if (char.IsDigit(name[^1]) && !name.StartsWith("nvme", StringComparison.Ordinal))
                    continue;
                if (name.StartsWith("nvme", StringComparison.Ordinal) && name.Contains('p') &&
                    char.IsDigit(name[^1]))
                    continue;

                readSectors += ParseU(p[5]);
                writeSectors += ParseU(p[9]);
            }

            // sectors are typically 512 bytes
            return new IoSample(readSectors * 512UL, writeSectors * 512UL);
        }
        catch
        {
            return null;
        }
    }

    private static double? ReadLoad1()
    {
        try
        {
            var text = File.ReadAllText("/proc/loadavg").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (text.Length > 0 && double.TryParse(text[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var v))
                return v;
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static int? CountProcesses()
    {
        try
        {
            return Directory.EnumerateDirectories("/proc")
                .Count(p => int.TryParse(Path.GetFileName(p), out _));
        }
        catch
        {
            return null;
        }
    }

    private static long ParseKbLine(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return 0;
        return long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var kb)
            ? kb * 1024L
            : 0;
    }

    private static ulong ParseU(string s) =>
        ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private sealed record CpuSample(ulong IdleAll, ulong Total);
    private sealed record NetSample(ulong RxBytes, ulong TxBytes);
    private sealed record IoSample(ulong ReadBytes, ulong WriteBytes);
}

internal sealed class HostMetrics
{
    public DateTimeOffset TimestampUtc { get; set; }
    public double? CpuPercent { get; set; }
    public long MemTotalBytes { get; set; }
    public long MemAvailableBytes { get; set; }
    public double? MemUsedPercent { get; set; }
    public List<DiskMountMetrics> Disks { get; set; } = [];
    public double? RootDiskUsedPercent { get; set; }
    public string? RootMount { get; set; }
    public double NetworkRxBytesPerSec { get; set; }
    public double NetworkTxBytesPerSec { get; set; }
    public double DiskReadBytesPerSec { get; set; }
    public double DiskWriteBytesPerSec { get; set; }
    public double? LoadAverage1 { get; set; }
    public int? ProcessCount { get; set; }

    public bool IsDegraded(double cpuAlert, double memAlert, double diskAlert) =>
        (CpuPercent is double c && c >= cpuAlert) ||
        (MemUsedPercent is double m && m >= memAlert) ||
        (RootDiskUsedPercent is double d && d >= diskAlert);
}

internal sealed class DiskMountMetrics
{
    public string Mount { get; set; } = "/";
    public long TotalBytes { get; set; }
    public long FreeBytes { get; set; }
    public double UsedPercent { get; set; }
    public string? FileSystem { get; set; }
}
