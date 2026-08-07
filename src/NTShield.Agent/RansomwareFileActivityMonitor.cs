using System.Security.Cryptography;
using System.Text.Json;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Options;

namespace NTShield.Agent;

/// <summary>
/// Lightweight ransomware behavior sensor. It intentionally reports bounded
/// aggregates instead of uploading every file path or file contents.
/// </summary>
public sealed class RansomwareFileActivityMonitor : IDisposable
{
    private static readonly string[] SuspiciousExtensions =
    [
        ".encrypted", ".encrypt", ".locked", ".lockbit", ".akira", ".blackcat",
        ".crypt", ".crypto", ".enc", ".wncry", ".ryuk", ".conti", ".play",
        ".ransom", ".vault", ".crypted"
    ];

    private readonly DetectionOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<RansomwareFileActivityMonitor> _logger;
    private readonly object _sync = new();
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly List<string> _samplePaths = [];
    private DateTimeOffset _windowStartedUtc = DateTimeOffset.UtcNow;
    private DateTimeOffset _nextAlertUtc = DateTimeOffset.MinValue;
    private int _created;
    private int _changed;
    private int _deleted;
    private int _renamed;
    private int _suspiciousExtensions;
    private int _entropySamples;
    private int _highEntropySamples;
    private bool _canaryHit;
    private string? _canaryPath;
    private bool _started;

    public RansomwareFileActivityMonitor(
        IOptions<DetectionOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<RansomwareFileActivityMonitor> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public void Start()
    {
        if (!_options.FileActivityMonitoring || _started)
        {
            return;
        }

        _started = true;
        var canaryDirectory = ResolveCanaryDirectory();
        if (_options.CanaryFiles)
        {
            CreateCanaries(canaryDirectory);
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var configured in _options.FileActivityPaths.Append(canaryDirectory))
        {
            if (string.IsNullOrWhiteSpace(configured))
            {
                continue;
            }

            try
            {
                var path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(configured));
                if (Directory.Exists(path))
                {
                    paths.Add(path);
                }
                else
                {
                    _logger.LogWarning("File activity path does not exist: {Path}", path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Invalid file activity path: {Path}", configured);
            }
        }

        foreach (var path in paths)
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName |
                                   NotifyFilters.DirectoryName |
                                   NotifyFilters.LastWrite |
                                   NotifyFilters.Size |
                                   NotifyFilters.CreationTime,
                    Filter = "*",
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = true
                };
                watcher.Created += OnCreated;
                watcher.Changed += OnChanged;
                watcher.Deleted += OnDeleted;
                watcher.Renamed += OnRenamed;
                watcher.Error += OnWatcherError;
                _watchers.Add(watcher);
                _logger.LogInformation("Ransomware file monitor watching {Path}", path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to watch file activity path: {Path}", path);
            }
        }

        if (_watchers.Count == 0)
        {
            _logger.LogWarning("Ransomware file monitor started without usable watch paths");
        }
    }

    public IReadOnlyList<DetectionAlert> DrainAlerts()
    {
        if (!_started || !_options.FileActivityMonitoring)
        {
            return [];
        }

        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;
            RotateWindowIfNeeded(now);
            if (now < _nextAlertUtc)
            {
                return [];
            }

            var total = _created + _changed + _deleted + _renamed;
            var entropyRatio = _entropySamples == 0
                ? 0
                : (double)_highEntropySamples / _entropySamples;
            var behaviorTrigger = total >= Math.Max(10, _options.FileActivityMinEvents) &&
                                  (_renamed >= _options.FileActivityMinRenames ||
                                   _deleted >= _options.FileActivityMinDeletes ||
                                   (_highEntropySamples >= 3 && entropyRatio >= _options.FileActivityHighEntropyRatio) ||
                                   _suspiciousExtensions >= 3);

            if (!_canaryHit && !behaviorTrigger)
            {
                return [];
            }

            var evidence = new
            {
                windowSeconds = _options.FileActivityWindowSeconds,
                created = _created,
                changed = _changed,
                deleted = _deleted,
                renamed = _renamed,
                suspiciousExtensions = _suspiciousExtensions,
                entropySamples = _entropySamples,
                highEntropySamples = _highEntropySamples,
                highEntropyRatio = Math.Round(entropyRatio, 3),
                canaryHit = _canaryHit,
                canaryPath = _canaryPath,
                samplePaths = _samplePaths.Take(12).ToArray()
            };

            var alert = new DetectionAlert
            {
                TimestampUtc = now,
                ComputerName = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                RuleId = _canaryHit ? "RANSOMWARE_CANARY_TAMPER" : "RANSOMWARE_FILE_ACTIVITY",
                RuleName = _canaryHit ? "Ransomware Canary Tamper" : "Ransomware-Style File Activity",
                Severity = _canaryHit ? Shared.Enums.Severity.Critical : Shared.Enums.Severity.High,
                Title = _canaryHit
                    ? "Ransomware canary file was modified, renamed, or deleted"
                    : "Ransomware-style mass file activity detected",
                Description = _canaryHit
                    ? "A protected NT Shield canary was touched. Treat as a possible encryption or destructive activity event."
                    : $"File activity burst: total={total}, renamed={_renamed}, deleted={_deleted}, highEntropyRatio={entropyRatio:F2}.",
                EventCount = total,
                EvidenceJson = JsonSerializer.Serialize(evidence)
            };

            _nextAlertUtc = now.AddMinutes(Math.Max(1, _options.FileActivityCooldownMinutes));
            ResetMetrics(now);
            return [alert];
        }
    }

    public void Stop()
    {
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Created -= OnCreated;
                watcher.Changed -= OnChanged;
                watcher.Deleted -= OnDeleted;
                watcher.Renamed -= OnRenamed;
                watcher.Error -= OnWatcherError;
                watcher.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to dispose file activity watcher");
            }
        }

        _watchers.Clear();
        _started = false;
    }

    public void Dispose() => Stop();

    private void OnCreated(object sender, FileSystemEventArgs e) => Record(FileChangeKind.Created, e.FullPath);

    private void OnChanged(object sender, FileSystemEventArgs e) => Record(FileChangeKind.Changed, e.FullPath);

    private void OnDeleted(object sender, FileSystemEventArgs e) => Record(FileChangeKind.Deleted, e.FullPath);

    private void OnRenamed(object sender, RenamedEventArgs e)
    {
        Record(FileChangeKind.Renamed, e.OldFullPath);
        Record(FileChangeKind.Renamed, e.FullPath);
    }

    private void OnWatcherError(object sender, ErrorEventArgs e) =>
        _logger.LogWarning(e.GetException(), "File activity watcher buffer error");

    private void Record(FileChangeKind kind, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var normalized = Path.GetFullPath(path);
        var isCanary = IsCanary(normalized);
        if (!isCanary && IsExcludedPath(normalized))
        {
            return;
        }
        var shouldSample = false;
        lock (_sync)
        {
            RotateWindowIfNeeded(now);
            switch (kind)
            {
                case FileChangeKind.Created: _created++; break;
                case FileChangeKind.Changed: _changed++; break;
                case FileChangeKind.Deleted: _deleted++; break;
                case FileChangeKind.Renamed: _renamed++; break;
            }

            if (isCanary)
            {
                _canaryHit = true;
                _canaryPath = normalized;
            }

            var extension = Path.GetExtension(normalized);
            if (SuspiciousExtensions.Any(x => string.Equals(x, extension, StringComparison.OrdinalIgnoreCase)))
            {
                _suspiciousExtensions++;
            }

            if (_samplePaths.Count < 12 && !Directory.Exists(normalized))
            {
                _samplePaths.Add(normalized);
            }

            shouldSample = kind is FileChangeKind.Created or FileChangeKind.Changed or FileChangeKind.Renamed &&
                           _entropySamples < Math.Max(0, _options.FileActivityEntropySamples);
            if (shouldSample)
            {
                _entropySamples++;
            }
        }

        if (shouldSample)
        {
            var entropy = CalculateEntropy(normalized);
            if (entropy >= _options.FileActivityHighEntropyThreshold)
            {
                lock (_sync)
                {
                    _highEntropySamples++;
                }
            }
        }
    }

    private void RotateWindowIfNeeded(DateTimeOffset now)
    {
        if ((now - _windowStartedUtc).TotalSeconds < Math.Max(10, _options.FileActivityWindowSeconds))
        {
            return;
        }

        ResetMetrics(now);
    }

    private void ResetMetrics(DateTimeOffset now)
    {
        _windowStartedUtc = now;
        _created = 0;
        _changed = 0;
        _deleted = 0;
        _renamed = 0;
        _suspiciousExtensions = 0;
        _entropySamples = 0;
        _highEntropySamples = 0;
        _canaryHit = false;
        _canaryPath = null;
        _samplePaths.Clear();
    }

    private string ResolveCanaryDirectory()
    {
        var configured = _options.CanaryDirectory;
        return string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(_agentOptions.DataDirectory, "canaries")
            : Environment.ExpandEnvironmentVariables(configured);
    }

    private void CreateCanaries(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            foreach (var extension in new[] { ".docx", ".xlsx", ".pdf" })
            {
                var path = Path.Combine(directory, $"ntshield-canary{extension}");
                if (!File.Exists(path))
                {
                    File.WriteAllText(path, $"NT Shield canary {Guid.NewGuid():N} - do not open");
                }

                try
                {
                    File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.NotContentIndexed);
                }
                catch
                {
                    // Attribute changes are best effort only.
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not create ransomware canary files at {Path}", directory);
        }
    }

    private bool IsCanary(string path)
    {
        var directory = ResolveCanaryDirectory();
        return path.StartsWith(directory, StringComparison.OrdinalIgnoreCase) &&
               Path.GetFileName(path).StartsWith("ntshield-canary", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsExcludedPath(string path) =>
        _options.FileActivityExcludedPaths.Any(excluded =>
            !string.IsNullOrWhiteSpace(excluded) &&
            path.Contains(excluded, StringComparison.OrdinalIgnoreCase));

    private static double CalculateEntropy(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return 0;
            }

            Span<byte> buffer = stackalloc byte[64 * 1024];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 16 * 1024, FileOptions.SequentialScan);
            var read = stream.Read(buffer);
            if (read < 256)
            {
                return 0;
            }

            Span<int> frequencies = stackalloc int[256];
            for (var i = 0; i < read; i++)
            {
                frequencies[buffer[i]]++;
            }

            var entropy = 0d;
            for (var i = 0; i < frequencies.Length; i++)
            {
                if (frequencies[i] == 0) continue;
                var probability = (double)frequencies[i] / read;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }
        catch (IOException)
        {
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return 0;
        }
        catch (CryptographicException)
        {
            return 0;
        }
    }

    private enum FileChangeKind
    {
        Created,
        Changed,
        Deleted,
        Renamed
    }
}
