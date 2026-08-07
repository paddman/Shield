using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NTShield.Core.Abstractions;
using NTShield.Core.Configuration;
using NTShield.Core.Security;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;

namespace NTShield.Agent;

/// <summary>
/// User-mode endpoint protection pipeline. It deliberately complements Microsoft Defender;
/// it is not a kernel minifilter or a replacement AV engine.
/// </summary>
public sealed class EndpointProtectionService : IFileProtectionService
{
    private readonly AntivirusOptions _options;
    private readonly AgentOptions _agentOptions;
    private readonly ILogger<EndpointProtectionService> _logger;
    private readonly ConcurrentQueue<string> _scanQueue = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly object _stateGate = new();
    private readonly List<DetectionAlert> _alerts = [];
    private CancellationTokenSource? _stop;
    private Task? _worker;
    // Version zero means a signed pack at version 1 can bootstrap even when the
    // optional local bootstrap file is absent or intentionally omitted.
    private ProtectionPack _pack = new() { Version = 0 };
    private ProtectionPackPayload _payload = new();
    private string _activeYaraPath = string.Empty;
    private DateTimeOffset? _lastScanUtc;
    private string? _lastPackError;

    public EndpointProtectionService(
        IOptions<AntivirusOptions> options,
        IOptions<AgentOptions> agentOptions,
        ILogger<EndpointProtectionService> logger)
    {
        _options = options.Value;
        _agentOptions = agentOptions.Value;
        _logger = logger;
    }

    public bool DefenderAvailable => _options.EnableDefender && FindDefenderExecutable() is not null;
    public bool YaraAvailable => _options.EnableYara && File.Exists(ResolvePath(_options.YaraExecutablePath)) &&
                                 !string.IsNullOrWhiteSpace(_payload.YaraRules);
    public string ProtectionStatus => !_options.Enabled
        ? "disabled"
        : _lastPackError is not null
            ? $"degraded: {_lastPackError}"
            : DefenderAvailable || YaraAvailable
                ? "protected"
                : "degraded: no scan engine available";
    public int RulePackVersion => _pack.Version;
    public DateTimeOffset? LastScanUtc => _lastScanUtc;

    public void Start()
    {
        if (!_options.Enabled || _stop is not null)
        {
            return;
        }

        LoadProtectionPack();
        Directory.CreateDirectory(QuarantineRoot());
        HardenDirectory(QuarantineRoot());
        _stop = new CancellationTokenSource();

        if (_options.RealTimeMonitoring)
        {
            foreach (var path in _options.ScanPaths.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (!Directory.Exists(path)) continue;
                    var watcher = new FileSystemWatcher(path)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                       NotifyFilters.Size | NotifyFilters.CreationTime,
                        Filter = "*.*",
                        EnableRaisingEvents = true
                    };
                    watcher.Created += OnFileChanged;
                    watcher.Changed += OnFileChanged;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnWatcherError;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Antivirus watcher unavailable for {Path}", path);
                }
            }
        }

        _worker = Task.Run(() => WorkerAsync(_stop.Token));
        _logger.LogInformation(
            "Endpoint protection started status={Status} defender={Defender} yara={Yara} pack={Pack}",
            ProtectionStatus, DefenderAvailable, YaraAvailable, RulePackVersion);
    }

    public void Stop()
    {
        _stop?.Cancel();
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        _watchers.Clear();
        try { _worker?.Wait(TimeSpan.FromSeconds(3)); } catch { /* shutdown */ }
        _worker = null;
        _stop?.Dispose();
        _stop = null;
    }

    public IReadOnlyList<DetectionAlert> DrainAlerts()
    {
        lock (_stateGate)
        {
            var result = _alerts.ToList();
            _alerts.Clear();
            return result;
        }
    }

    public async Task<FileScanResult> ScanFileAsync(string path, CancellationToken cancellationToken)
    {
        var result = new FileScanResult { Path = path };
        try
        {
            var fullPath = ValidateFilePath(path);
            var info = new FileInfo(fullPath);
            result.Path = fullPath;
            result.SizeBytes = info.Length;
            result.Features["file_size_mb"] = Math.Round(info.Length / 1024d / 1024d, 4);

            if (info.Length > Math.Max(1, _options.MaxFileSizeMb) * 1024L * 1024L)
            {
                result.Verdict = "skipped_size_limit";
                result.DefenderStatus = "not-run";
                result.YaraStatus = "not-run";
                return result;
            }

            result.Sha256 = await ComputeSha256Async(fullPath, cancellationToken);
            result.Features["is_executable"] = IsExecutable(fullPath) ? 1 : 0;
            result.Features["is_script"] = IsScript(fullPath) ? 1 : 0;
            result.Features["is_user_writable_path"] = IsUserWritablePath(fullPath) ? 1 : 0;
            result.Features["is_temp_path"] = IsTempPath(fullPath) ? 1 : 0;
            result.Features["entropy"] = await EstimateEntropyAsync(fullPath, cancellationToken);

            foreach (var signature in _payload.HashSignatures.Where(s =>
                         string.Equals(NormalizeHash(s.Sha256), result.Sha256, StringComparison.OrdinalIgnoreCase)))
            {
                result.Signals.Add(new ProtectionSignal
                {
                    Source = "signature",
                    RuleId = "HASH_" + result.Sha256[..12],
                    Name = signature.Name,
                    Severity = signature.Severity,
                    Score = 100,
                    Evidence = signature.Description
                });
            }

            if (YaraAvailable)
            {
                var yara = await RunYaraAsync(fullPath, cancellationToken);
                result.YaraStatus = yara.Status;
                result.Signals.AddRange(yara.Signals);
            }
            else
            {
                result.YaraStatus = _options.EnableYara ? "unavailable" : "disabled";
            }

            if (DefenderAvailable)
            {
                var defender = await RunDefenderAsync(fullPath, cancellationToken);
                result.DefenderStatus = defender.Status;
                result.Signals.AddRange(defender.Signals);
            }
            else
            {
                result.DefenderStatus = _options.EnableDefender ? "unavailable" : "disabled";
            }

            AddHeuristicSignals(fullPath, result);
            result.Score = Math.Min(100, result.Signals.Sum(s => s.Score));
            result.Severity = ScoreSeverity(result.Score);
            result.Verdict = result.Score >= 65 ? "malicious" : result.Score >= 35 ? "suspicious" : "clean";
            _lastScanUtc = result.TimestampUtc;

            if (result.Score >= 35)
            {
                EnqueueAlert(result);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            result.Verdict = "skipped_race";
        }
        catch (UnauthorizedAccessException)
        {
            result.Verdict = "skipped_policy";
        }
        catch (IOException ex)
        {
            result.Verdict = "skipped_locked";
            _logger.LogDebug(ex, "Endpoint protection skipped locked file {Path}", path);
        }
        catch (Exception ex)
        {
            result.Verdict = "scan_error";
            result.Signals.Add(new ProtectionSignal
            {
                Source = "pipeline",
                RuleId = "SCAN_ERROR",
                Name = "Scan failed",
                Severity = Severity.Medium,
                Score = 25,
                Evidence = ex.Message[..Math.Min(300, ex.Message.Length)]
            });
            _logger.LogWarning(ex, "Endpoint protection scan failed for {Path}", path);
        }

        return result;
    }

    public async Task<IReadOnlyList<FileScanResult>> ScanPathAsync(string path, CancellationToken cancellationToken)
    {
        var full = Path.GetFullPath(path);
        if (File.Exists(full)) return [await ScanFileAsync(full, cancellationToken)];
        if (!Directory.Exists(full)) throw new FileNotFoundException("Scan path not found", full);

        var results = new List<FileScanResult>();
        var max = Math.Max(1, _options.ScheduledScanMaxFiles);
        foreach (var file in EnumerateFilesSafe(full, max))
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await ScanFileAsync(file, cancellationToken));
        }

        return results;
    }

    public async Task<QuarantineResult> QuarantineFileAsync(
        string path,
        string reason,
        CancellationToken cancellationToken)
    {
        try
        {
            var source = ValidateFilePath(path);
            if (source.StartsWith(Path.GetFullPath(QuarantineRoot()) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Cannot quarantine a file already in the vault");
            var id = Guid.NewGuid().ToString("N");
            var dir = Path.Combine(QuarantineRoot(), id);
            Directory.CreateDirectory(dir);
            HardenDirectory(dir);
            var destination = Path.Combine(dir, Path.GetFileName(source));
            var hash = await ComputeSha256Async(source, cancellationToken);
            File.Move(source, destination);
            var movedHash = await ComputeSha256Async(destination, cancellationToken);
            if (!string.Equals(hash, movedHash, StringComparison.OrdinalIgnoreCase))
            {
                File.Move(destination, source);
                throw new IOException("File changed during quarantine");
            }
            var metadata = new
            {
                quarantineId = id,
                originalPath = source,
                vaultPath = destination,
                sha256 = hash,
                reason = EventDataSanitizer.SanitizeForLog(reason, 500),
                createdAtUtc = DateTimeOffset.UtcNow
            };
            await File.WriteAllTextAsync(
                Path.Combine(dir, "metadata.json"),
                JsonSerializer.Serialize(metadata),
                cancellationToken);
            return new QuarantineResult
            {
                Success = true,
                Status = "quarantined",
                QuarantineId = id,
                VaultPath = destination,
                OriginalPath = source,
                Sha256 = hash
            };
        }
        catch (Exception ex)
        {
            return new QuarantineResult { Status = "failed", Error = ex.Message };
        }
    }

    public async Task<QuarantineResult> RestoreQuarantinedFileAsync(
        string quarantineId,
        CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(quarantineId) ||
                quarantineId.Any(c => !Uri.IsHexDigit(c)))
            {
                throw new InvalidOperationException("Invalid quarantine id");
            }

            var dir = Path.Combine(QuarantineRoot(), quarantineId);
            var metadataPath = Path.Combine(dir, "metadata.json");
            var metadata = JsonSerializer.Deserialize<QuarantineMetadata>(
                await File.ReadAllTextAsync(metadataPath, cancellationToken),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidOperationException("Quarantine metadata is invalid");
            var original = Path.GetFullPath(metadata.OriginalPath);
            var vault = Path.GetFullPath(metadata.VaultPath);
            if (!vault.StartsWith(Path.GetFullPath(dir) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase) || File.Exists(original))
            {
                throw new InvalidOperationException("Restore destination is unsafe or already exists");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(original)!);
            File.Move(vault, original);
            Directory.Delete(dir, recursive: true);
            return new QuarantineResult
            {
                Success = true,
                Status = "restored",
                QuarantineId = quarantineId,
                OriginalPath = original,
                Sha256 = metadata.Sha256
            };
        }
        catch (Exception ex)
        {
            return new QuarantineResult { Status = "failed", QuarantineId = quarantineId, Error = ex.Message };
        }
    }

    public bool TryApplyProtectionPack(ProtectionPack pack, out string error)
    {
        error = string.Empty;
        try
        {
            if (pack.Version <= _pack.Version) { error = "pack_version_not_newer"; return false; }
            if (!ValidatePack(pack, requireSignature: true, out var payload, out error))
                return false;
            var dataDir = Path.Combine(_agentOptions.DataDirectory, _options.ProtectionDataDirectory);
            Directory.CreateDirectory(dataDir);
            var packPath = Path.Combine(dataDir, "active-pack.json");
            var temp = packPath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(pack));
            File.Move(temp, packPath, true);
            var yaraPath = Path.Combine(dataDir, "active-rules.yar");
            File.WriteAllText(yaraPath, payload.YaraRules ?? string.Empty);
            lock (_stateGate)
            {
                _pack = pack;
                _payload = payload;
                _activeYaraPath = yaraPath;
                _lastPackError = null;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _lastPackError = error;
            _logger.LogWarning("Protection pack rejected: {Error}", error);
            return false;
        }
    }

    private async Task WorkerAsync(CancellationToken cancellationToken)
    {
        var nextScheduled = DateTimeOffset.UtcNow.AddHours(Math.Max(1, _options.ScheduledScanIntervalHours));
        while (!cancellationToken.IsCancellationRequested)
        {
            while (_scanQueue.TryDequeue(out var path))
            {
                _queued.TryRemove(path, out _);
                try { await ScanFileAsync(path, cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
            }

            if (_options.ScheduledScanEnabled && DateTimeOffset.UtcNow >= nextScheduled)
            {
                foreach (var path in _options.ScanPaths)
                {
                    try { await ScanPathAsync(path, cancellationToken); }
                    catch (Exception ex) { _logger.LogDebug(ex, "Scheduled protection scan failed for {Path}", path); }
                }
                nextScheduled = DateTimeOffset.UtcNow.AddHours(Math.Max(1, _options.ScheduledScanIntervalHours));
            }

            try { await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken); }
            catch (OperationCanceledException) { return; }
        }
    }

    private void LoadProtectionPack()
    {
        try
        {
            var localPath = ResolvePath(_options.LocalProtectionPackPath);
            if (File.Exists(localPath))
            {
                var pack = JsonSerializer.Deserialize<ProtectionPack>(File.ReadAllText(localPath));
                if (pack is not null)
                {
                    var payload = JsonSerializer.Deserialize<ProtectionPackPayload>(pack.PayloadJson);
                    if (payload is not null)
                    {
                        _pack = pack;
                        _payload = payload;
                        var dataDir = Path.Combine(_agentOptions.DataDirectory, _options.ProtectionDataDirectory);
                        Directory.CreateDirectory(dataDir);
                        _activeYaraPath = Path.Combine(dataDir, "active-rules.yar");
                        File.WriteAllText(_activeYaraPath, payload.YaraRules ?? string.Empty);
                    }
                }
            }

            var activePath = Path.Combine(_agentOptions.DataDirectory, _options.ProtectionDataDirectory, "active-pack.json");
            if (File.Exists(activePath))
            {
                var active = JsonSerializer.Deserialize<ProtectionPack>(File.ReadAllText(activePath));
                var activeError = string.Empty;
                if (active is not null && active.Version > _pack.Version &&
                    ValidatePack(active, requireSignature: true, out var payload, out activeError))
                {
                    _pack = active;
                    _payload = payload;
                    _activeYaraPath = Path.Combine(_agentOptions.DataDirectory, _options.ProtectionDataDirectory, "active-rules.yar");
                    File.WriteAllText(_activeYaraPath, payload.YaraRules ?? string.Empty);
                }
                else if (active is not null && active.Version > _pack.Version)
                {
                    _lastPackError = activeError;
                }
            }
        }
        catch (Exception ex)
        {
            _lastPackError = "local_pack_invalid";
            _logger.LogWarning(ex, "Could not load local protection pack");
        }
    }

    private bool ValidatePack(ProtectionPack pack, bool requireSignature, out ProtectionPackPayload payload, out string error)
    {
        payload = new ProtectionPackPayload();
        error = string.Empty;
        if (pack.PayloadJson.Length is 0 or > 2_000_000) { error = "pack_payload_size_invalid"; return false; }
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pack.PayloadJson))).ToLowerInvariant();
        if (!string.Equals(hash, NormalizeHash(pack.Sha256), StringComparison.OrdinalIgnoreCase))
        {
            error = "pack_sha256_invalid";
            return false;
        }
        if (requireSignature && !UpdatePackageValidator.VerifySignedConfig(pack.PayloadJson, pack.Signature, _options.ProtectionPublicKeyPem))
        {
            error = "pack_signature_invalid";
            return false;
        }

        try
        {
            payload = JsonSerializer.Deserialize<ProtectionPackPayload>(pack.PayloadJson)
                      ?? throw new InvalidOperationException("pack_payload_invalid");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private void AddHeuristicSignals(string path, FileScanResult result)
    {
        if (result.Features.TryGetValue("entropy", out var entropy) && entropy >= 7.2 &&
            result.Features.GetValueOrDefault("is_executable") > 0)
        {
            result.Signals.Add(new ProtectionSignal
            {
                Source = "heuristic",
                RuleId = "HEUR_HIGH_ENTROPY_PE",
                Name = "High entropy executable",
                Severity = Severity.Medium,
                Score = 35,
                Evidence = $"entropy={entropy:F2}"
            });
        }

        if (IsTempPath(path) && (IsExecutable(path) || IsScript(path)))
        {
            result.Signals.Add(new ProtectionSignal
            {
                Source = "heuristic",
                RuleId = "HEUR_USER_WRITABLE_EXECUTION",
                Name = "Executable or script in a temporary path",
                Severity = Severity.Medium,
                Score = 30,
                Evidence = EventDataSanitizer.SanitizeForLog(path, 500)
            });
        }

        var name = Path.GetFileName(path);
        if (name.Count(c => c == '.') >= 2 &&
            (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
             name.EndsWith(".scr", StringComparison.OrdinalIgnoreCase) ||
             name.EndsWith(".js", StringComparison.OrdinalIgnoreCase)))
        {
            result.Signals.Add(new ProtectionSignal
            {
                Source = "heuristic",
                RuleId = "HEUR_DOUBLE_EXTENSION",
                Name = "Suspicious double extension",
                Severity = Severity.Medium,
                Score = 30,
                Evidence = name
            });
        }
    }

    private async Task<(string Status, List<ProtectionSignal> Signals)> RunYaraAsync(string path, CancellationToken cancellationToken)
    {
        var executable = ResolvePath(_options.YaraExecutablePath);
        if (!File.Exists(executable) || string.IsNullOrWhiteSpace(_activeYaraPath) || !File.Exists(_activeYaraPath))
            return ("unavailable", []);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, _options.ScanTimeoutSeconds)));
        var psi = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("--no-warnings");
        psi.ArgumentList.Add(_activeYaraPath);
        psi.ArgumentList.Add(path);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start YARA");
        var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
        await process.StandardError.ReadToEndAsync(timeout.Token);
        await process.WaitForExitAsync(timeout.Token);
        if (process.ExitCode == 1) return ("clean", []);
        if (process.ExitCode == 0)
        {
            var signals = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Take(20)
                .Select(line => new ProtectionSignal
                {
                    Source = "yara",
                    RuleId = "YARA_" + line.Split(' ', '\t')[0],
                    Name = line.Split(' ', '\t')[0],
                    Severity = Severity.High,
                    Score = 90,
                    Evidence = EventDataSanitizer.SanitizeForLog(line, 500)
                }).ToList();
            return (signals.Count > 0 ? "hit" : "error", signals);
        }

        return ($"error:{process.ExitCode}", []);
    }

    private async Task<(string Status, List<ProtectionSignal> Signals)> RunDefenderAsync(string path, CancellationToken cancellationToken)
    {
        var executable = FindDefenderExecutable();
        if (executable is null) return ("unavailable", []);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, _options.ScanTimeoutSeconds)));
        var psi = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-Scan");
        psi.ArgumentList.Add("-ScanType");
        psi.ArgumentList.Add("3");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(path);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start Defender");
        var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
        var error = await process.StandardError.ReadToEndAsync(timeout.Token);
        await process.WaitForExitAsync(timeout.Token);
        if (process.ExitCode == 0) return ("clean", []);
        if (process.ExitCode == 2 || output.Contains("threat", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("threat", StringComparison.OrdinalIgnoreCase))
        {
            return ("threat", [new ProtectionSignal
            {
                Source = "defender",
                RuleId = "DEFENDER_THREAT",
                Name = "Microsoft Defender reported a threat",
                Severity = Severity.Critical,
                Score = 100,
                Evidence = EventDataSanitizer.SanitizeForLog((output + " " + error).Trim(), 500)
            }]);
        }

        return ($"error:{process.ExitCode}", []);
    }

    private void EnqueueAlert(FileScanResult result)
    {
        var evidence = JsonSerializer.Serialize(new
        {
            result.ScanId,
            result.Path,
            result.Sha256,
            result.SizeBytes,
            result.Verdict,
            result.DefenderStatus,
            result.YaraStatus,
            result.RulePackVersion,
            signals = result.Signals.Take(20)
        });
        lock (_stateGate)
        {
            _alerts.Add(new DetectionAlert
            {
                AlertId = "av-" + result.ScanId,
                TimestampUtc = result.TimestampUtc,
                ComputerName = _agentOptions.ComputerName,
                AgentId = _agentOptions.AgentId,
                RuleId = result.Signals.FirstOrDefault()?.RuleId ?? "AV_SUSPICIOUS_FILE",
                RuleName = "NT Shield Antivirus",
                Severity = result.Severity,
                Title = result.Verdict == "malicious" ? "Antivirus threat detected" : "Suspicious file detected",
                Description = $"Layered protection score={result.Score} verdict={result.Verdict}",
                EventCount = result.Signals.Count,
                EvidenceJson = evidence,
                IncidentScore = result.Score,
                DetectionStage = string.Join(" → ", result.Signals.Select(s => s.Source).Distinct(StringComparer.OrdinalIgnoreCase)),
                FilePath = result.Path,
                FileSha256 = result.Sha256,
                AssetId = _agentOptions.ComputerName,
                Features = new Dictionary<string, double>(result.Features),
                ObserveBaseline = result.Score < 65
            });
        }
    }

    private string ValidateFilePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("File path is required", nameof(path));
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("File not found", full);
        if (IsExcluded(full)) throw new UnauthorizedAccessException("Path is excluded by antivirus policy");
        return full;
    }

    private bool IsExcluded(string path)
    {
        var full = NormalizePolicyPath(Path.GetFullPath(path));
        foreach (var configured in _options.ExcludedPaths)
        {
            if (string.IsNullOrWhiteSpace(configured)) continue;
            var value = configured.Trim();
            if (value.Contains('*'))
            {
                var wildcardRoot = NormalizePolicyPath(value);
                var pattern = "^" + Regex.Escape(wildcardRoot)
                    .Replace("\\*", "[^/]*") + "(?:/|$)";
                if (Regex.IsMatch(full, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) return true;
                continue;
            }

            if (Path.IsPathRooted(value))
            {
                var root = NormalizePolicyPath(Path.GetFullPath(value));
                if (string.Equals(full, root, StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(root + '/', StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            var relative = NormalizePolicyPath(value).Trim('/');
            if (!Path.IsPathRooted(value) && relative.Length > 0 &&
                full.Contains(relative, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string NormalizePolicyPath(string path) =>
        path.Replace('\\', '/').TrimEnd('/');

    private IEnumerable<string> EnumerateFilesSafe(string root, int max)
    {
        var count = 0;
        var pending = new Stack<string>([root]);
        while (pending.Count > 0 && count < max)
        {
            var dir = pending.Pop();
            if (IsExcluded(dir)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); } catch { continue; }
            foreach (var file in files)
            {
                if (count++ >= max) yield break;
                yield return file;
            }

            IEnumerable<string> children;
            try { children = Directory.EnumerateDirectories(dir); } catch { continue; }
            foreach (var child in children)
            {
                try
                {
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
                }
                catch { /* ignore inaccessible/reparse directory */ }
            }
        }
    }

    private string QuarantineRoot() => Path.Combine(_agentOptions.DataDirectory, _options.ProtectionDataDirectory, _options.QuarantineDirectoryName);
    private string ResolvePath(string path) => Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
    private static string NormalizeHash(string? hash) => (hash ?? string.Empty).Replace("-", string.Empty).Trim().ToLowerInvariant();
    private static Severity ScoreSeverity(int score) => score >= 85 ? Severity.Critical : score >= 65 ? Severity.High : score >= 35 ? Severity.Medium : Severity.Low;
    private static bool IsExecutable(string path) => Path.GetExtension(path).ToLowerInvariant() is ".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".msi";
    private static bool IsScript(string path) => Path.GetExtension(path).ToLowerInvariant() is ".ps1" or ".js" or ".vbs" or ".hta" or ".bat" or ".cmd";
    private static bool IsTempPath(string path) => path.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase);
    private static bool IsUserWritablePath(string path) => path.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase);
    private static string? FindDefenderExecutable()
    {
        var candidates = new List<string> { @"C:\Program Files\Windows Defender\MpCmdRun.exe" };
        var platform = @"C:\ProgramData\Microsoft\Windows Defender\Platform";
        try { candidates.AddRange(Directory.EnumerateDirectories(platform).OrderByDescending(x => x).Select(x => Path.Combine(x, "MpCmdRun.exe"))); } catch { }
        return candidates.FirstOrDefault(File.Exists);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<double> EstimateEntropyAsync(string path, CancellationToken cancellationToken)
    {
        var counts = new long[256];
        var total = 0L;
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
        var buffer = new byte[1024 * 1024];
        var read = await stream.ReadAsync(buffer, cancellationToken);
        while (read > 0 && total < 4 * 1024 * 1024)
        {
            for (var i = 0; i < read; i++) counts[buffer[i]]++;
            total += read;
            if (read < buffer.Length) break;
            read = await stream.ReadAsync(buffer, cancellationToken);
        }

        if (total == 0) return 0;
        var entropy = 0d;
        foreach (var count in counts.Where(c => c > 0))
        {
            var probability = count / (double)total;
            entropy -= probability * Math.Log(probability, 2);
        }
        return Math.Round(entropy, 4);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e) => QueueFile(e.FullPath);
    private void OnFileRenamed(object sender, RenamedEventArgs e) => QueueFile(e.FullPath);
    private void OnWatcherError(object sender, ErrorEventArgs e) => _logger.LogWarning(e.GetException(), "Antivirus watcher error");
    private void QueueFile(string path)
    {
        try
        {
            if (!File.Exists(path) || IsExcluded(path) || _scanQueue.Count >= Math.Max(10, _options.MaxRealtimeQueue)) return;
            var full = Path.GetFullPath(path);
            if (_queued.TryAdd(full, DateTimeOffset.UtcNow)) _scanQueue.Enqueue(full);
        }
        catch { /* file disappeared during the notification */ }
    }

    private static void HardenDirectory(string path)
    {
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        }
        catch { /* non-Windows test hosts or restricted service accounts */ }
    }

    private sealed class QuarantineMetadata
    {
        public string OriginalPath { get; set; } = string.Empty;
        public string VaultPath { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
    }
}
