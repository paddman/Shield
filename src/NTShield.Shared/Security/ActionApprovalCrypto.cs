using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using NTShield.Shared.Models;

namespace NTShield.Shared.Security;

/// <summary>
/// Cryptographic approval envelope for Central-issued response actions.
/// Central configures the private/public key pair; agents receive and trust only
/// the public key through versioned policy. The private key never leaves Central.
/// </summary>
public static class ActionApprovalCrypto
{
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions CanonicalJson = new(JsonSerializerDefaults.Web);
    private static readonly ConditionalWeakTable<ResponseActionRequest, object> ReservedRequests = new();
    private static readonly Dictionary<string, DateTimeOffset> ConsumedNonces = new(StringComparer.Ordinal);

    private static string? _signingPrivateKeyPem;
    private static string? _trustedPublicKeyPem;
    private static string? _trustedKeyId;
    private static string? _expectedAgentId;
    private static string? _replayLedgerPath;

    public static string? TrustedPublicKeyPem
    {
        get
        {
            lock (Gate) return _trustedPublicKeyPem;
        }
    }

    public static string? TrustedKeyId
    {
        get
        {
            lock (Gate) return _trustedKeyId;
        }
    }

    public static string? ExpectedAgentId
    {
        get
        {
            lock (Gate) return _expectedAgentId;
        }
    }

    public static bool HasSigningKey
    {
        get
        {
            lock (Gate) return !string.IsNullOrWhiteSpace(_signingPrivateKeyPem);
        }
    }

    /// <summary>
    /// Pin the identity of the local agent process. Once configured, a valid
    /// Central signature for another endpoint is still rejected locally.
    /// Passing null/blank clears the binding for Central-side signing/tests.
    /// </summary>
    public static void ConfigureExpectedAgentId(string? agentId)
    {
        lock (Gate)
        {
            _expectedAgentId = string.IsNullOrWhiteSpace(agentId)
                ? null
                : agentId.Trim();
        }
    }

    /// <summary>
    /// Configure the durable nonce ledger used by an agent. The ledger contains
    /// only random action nonces and expiry timestamps, never credentials or
    /// action payloads. Passing null clears in-memory replay state for tests or
    /// Central-side signing.
    /// </summary>
    public static void ConfigureReplayLedger(string? path)
    {
        lock (Gate)
        {
            _replayLedgerPath = string.IsNullOrWhiteSpace(path)
                ? null
                : Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            ConsumedNonces.Clear();

            if (_replayLedgerPath is null || !File.Exists(_replayLedgerPath))
                return;

            var now = DateTimeOffset.UtcNow;
            try
            {
                foreach (var line in File.ReadLines(_replayLedgerPath).TakeLast(20_000))
                {
                    var parts = line.Split('|', 2, StringSplitOptions.TrimEntries);
                    if (parts.Length != 2 ||
                        string.IsNullOrWhiteSpace(parts[0]) ||
                        !long.TryParse(parts[1], out var expiresUnix))
                    {
                        continue;
                    }

                    var expires = DateTimeOffset.FromUnixTimeSeconds(expiresUnix);
                    if (expires > now.AddMinutes(-5))
                        ConsumedNonces[parts[0]] = expires;
                }

                CompactReplayLedgerLocked(now);
            }
            catch
            {
                // A configured but unreadable ledger must fail closed later when
                // an action attempts reservation. Do not silently replace it here.
                ConsumedNonces.Clear();
            }
        }
    }

    /// <summary>Configure and verify the Central signing key pair.</summary>
    public static void ConfigureSigningKey(
        string privateKeyPem,
        string publicKeyPem,
        string? keyId = null)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem))
            throw new ArgumentException("Action signing private key is empty.", nameof(privateKeyPem));
        if (string.IsNullOrWhiteSpace(publicKeyPem))
            throw new ArgumentException("Action signing public key is empty.", nameof(publicKeyPem));

        using var privateKey = RSA.Create();
        privateKey.ImportFromPem(privateKeyPem);
        using var publicKey = RSA.Create();
        publicKey.ImportFromPem(publicKeyPem);

        var probe = RandomNumberGenerator.GetBytes(32);
        var probeSignature = privateKey.SignHash(
            probe,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        if (!publicKey.VerifyHash(
                probe,
                probeSignature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss))
        {
            throw new CryptographicException("Action signing public/private keys do not match.");
        }

        var resolvedKeyId = string.IsNullOrWhiteSpace(keyId)
            ? ComputeKeyId(publicKeyPem)
            : keyId.Trim().ToLowerInvariant();

        lock (Gate)
        {
            _signingPrivateKeyPem = privateKeyPem;
            _trustedPublicKeyPem = publicKeyPem;
            _trustedKeyId = resolvedKeyId;
        }
    }

    /// <summary>Configure the pinned Central public key on an agent.</summary>
    public static void ConfigureTrustedPublicKey(string publicKeyPem, string? keyId = null)
    {
        if (string.IsNullOrWhiteSpace(publicKeyPem))
            throw new ArgumentException("Action signing public key is empty.", nameof(publicKeyPem));

        using var publicKey = RSA.Create();
        publicKey.ImportFromPem(publicKeyPem);

        var resolvedKeyId = string.IsNullOrWhiteSpace(keyId)
            ? ComputeKeyId(publicKeyPem)
            : keyId.Trim().ToLowerInvariant();

        lock (Gate)
        {
            _trustedPublicKeyPem = publicKeyPem;
            _trustedKeyId = resolvedKeyId;
        }
    }

    public static string ComputeKeyId(string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return Convert.ToHexString(hash).ToLowerInvariant()[..16];
    }

    public static bool RequiresApproval(string? actionType) =>
        actionType is not ("LogOnly" or "ExportEvidence" or "ScanFile" or "ScanPath");

    /// <summary>
    /// Complete and sign an approval envelope. Call only after authenticating an
    /// operator and validating the action target and allowlist.
    /// </summary>
    public static void Sign(
        ResponseActionRequest request,
        string approvedBy,
        TimeSpan lifetime,
        DateTimeOffset? issuedAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(approvedBy))
            throw new ArgumentException("ApprovedBy is required.", nameof(approvedBy));

        string privateKeyPem;
        string keyId;
        lock (Gate)
        {
            privateKeyPem = _signingPrivateKeyPem
                ?? throw new InvalidOperationException("Central action signing key is not configured.");
            keyId = _trustedKeyId
                ?? throw new InvalidOperationException("Central action signing key id is not configured.");
        }

        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Action lifetime must be between 1 second and 1 hour.");

        var issued = issuedAtUtc ?? DateTimeOffset.UtcNow;
        request.Approved = true;
        request.ApprovedBy = approvedBy.Trim();
        request.ApprovedAtUtc = issued;
        request.ExpiresAtUtc = issued.Add(lifetime);
        request.ApprovalId = string.IsNullOrWhiteSpace(request.ApprovalId)
            ? Guid.NewGuid().ToString("N")
            : request.ApprovalId.Trim();
        request.Nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        request.ApprovalKeyId = keyId;
        request.PayloadSha256 = ComputePayloadSha256(request);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var payloadHash = Convert.FromHexString(request.PayloadSha256);
        request.ApprovalSignature = Convert.ToBase64String(rsa.SignHash(
            payloadHash,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));

        if (!IsApprovalValid(request, issued, enforceExpectedAgentId: false))
            throw new CryptographicException("Central generated an invalid action approval envelope.");
    }

    /// <summary>
    /// Pure signature validation. This method does not consume the nonce.
    /// Agent execution paths should use ValidateAndReserve.
    /// </summary>
    public static bool IsApprovalValid(
        ResponseActionRequest request,
        DateTimeOffset? nowUtc = null,
        bool enforceExpectedAgentId = true)
    {
        if (request is null || !request.ApprovalRequested)
            return false;

        var now = nowUtc ?? DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(request.RequestId) ||
            string.IsNullOrWhiteSpace(request.ActionType) ||
            string.IsNullOrWhiteSpace(request.TargetAgentId) ||
            string.Equals(request.TargetAgentId, "broadcast", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(request.ApprovalId) ||
            string.IsNullOrWhiteSpace(request.ApprovedBy) ||
            string.IsNullOrWhiteSpace(request.Nonce) || request.Nonce.Length < 32 ||
            string.IsNullOrWhiteSpace(request.PayloadSha256) || request.PayloadSha256.Length != 64 ||
            string.IsNullOrWhiteSpace(request.ApprovalSignature) ||
            string.IsNullOrWhiteSpace(request.ApprovalKeyId) ||
            request.ApprovedAtUtc is null ||
            request.ExpiresAtUtc is null)
        {
            return false;
        }

        var issued = request.ApprovedAtUtc.Value;
        var expires = request.ExpiresAtUtc.Value;
        if (issued > now.AddMinutes(5) ||
            expires <= now.AddSeconds(-30) ||
            expires <= issued ||
            expires - issued > TimeSpan.FromHours(1))
        {
            return false;
        }

        string? publicKeyPem;
        string? trustedKeyId;
        string? expectedAgentId;
        lock (Gate)
        {
            publicKeyPem = _trustedPublicKeyPem;
            trustedKeyId = _trustedKeyId;
            expectedAgentId = _expectedAgentId;
        }

        if (enforceExpectedAgentId &&
            !string.IsNullOrWhiteSpace(expectedAgentId) &&
            !string.Equals(expectedAgentId, request.TargetAgentId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(publicKeyPem) ||
            string.IsNullOrWhiteSpace(trustedKeyId) ||
            !string.Equals(
                trustedKeyId,
                request.ApprovalKeyId,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string expectedHash;
        try
        {
            expectedHash = ComputePayloadSha256(request);
        }
        catch
        {
            return false;
        }

        if (!FixedTimeHexEquals(expectedHash, request.PayloadSha256))
            return false;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            return rsa.VerifyHash(
                Convert.FromHexString(expectedHash),
                Convert.FromBase64String(request.ApprovalSignature),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Validate and reserve an action nonce exactly once for the configured local
    /// agent. Re-reading Approved on the same in-memory request remains valid, but
    /// a new request carrying the same nonce is rejected, including after restart
    /// when a replay ledger is configured.
    /// </summary>
    public static bool ValidateAndReserve(
        ResponseActionRequest request,
        DateTimeOffset? nowUtc = null)
    {
        if (request is null)
            return false;

        string? expectedAgentId;
        lock (Gate) expectedAgentId = _expectedAgentId;

        // Central signs and serializes actions without a local endpoint binding;
        // nonce consumption belongs only to an agent process.
        if (string.IsNullOrWhiteSpace(expectedAgentId))
            return IsApprovalValid(request, nowUtc, enforceExpectedAgentId: false);

        if (ReservedRequests.TryGetValue(request, out _))
            return IsApprovalValid(request, nowUtc, enforceExpectedAgentId: true);

        var now = nowUtc ?? DateTimeOffset.UtcNow;
        if (!IsApprovalValid(request, now, enforceExpectedAgentId: true) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.ExpiresAtUtc is null)
        {
            return false;
        }

        lock (Gate)
        {
            if (ReservedRequests.TryGetValue(request, out _))
                return IsApprovalValid(request, now, enforceExpectedAgentId: true);

            PurgeExpiredNoncesLocked(now);
            if (ConsumedNonces.ContainsKey(request.Nonce))
                return false;

            if (!PersistNonceLocked(request.Nonce, request.ExpiresAtUtc.Value))
                return false;

            ConsumedNonces[request.Nonce] = request.ExpiresAtUtc.Value;
            ReservedRequests.GetValue(request, static _ => new object());
            return true;
        }
    }

    /// <summary>
    /// Stable payload digest. Signature and digest fields are intentionally
    /// excluded; every field capable of changing the executed action is included.
    /// </summary>
    public static string ComputePayloadSha256(ResponseActionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var canonical = new
        {
            request.RequestId,
            request.Requester,
            request.TargetAgentId,
            request.ActionType,
            request.Reason,
            request.TargetIp,
            request.TargetPort,
            request.Direction,
            request.Protocol,
            request.RuleName,
            request.ProcessId,
            request.ServiceName,
            request.TaskPath,
            request.TaskName,
            request.TargetPath,
            request.FileSha256,
            request.QuarantineId,
            request.IncidentId,
            request.AlertId,
            Approved = request.ApprovalRequested,
            request.ApprovalId,
            request.ApprovedBy,
            ApprovedAtUtc = request.ApprovedAtUtc?.ToUniversalTime().ToString("O"),
            ExpiresAtUtc = request.ExpiresAtUtc?.ToUniversalTime().ToString("O"),
            request.Nonce,
            request.ApprovalKeyId,
            request.DurationMinutes
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(canonical, CanonicalJson);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool PersistNonceLocked(string nonce, DateTimeOffset expiresUtc)
    {
        if (_replayLedgerPath is null)
            return true;

        try
        {
            var directory = Path.GetDirectoryName(_replayLedgerPath);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            File.AppendAllText(
                _replayLedgerPath,
                $"{nonce}|{expiresUtc.ToUnixTimeSeconds()}{Environment.NewLine}");
            HardenReplayLedger(_replayLedgerPath);

            var info = new FileInfo(_replayLedgerPath);
            if (ConsumedNonces.Count > 10_000 || info.Length > 1024 * 1024)
                CompactReplayLedgerLocked(DateTimeOffset.UtcNow);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void PurgeExpiredNoncesLocked(DateTimeOffset now)
    {
        foreach (var nonce in ConsumedNonces
                     .Where(pair => pair.Value <= now.AddMinutes(-5))
                     .Select(pair => pair.Key)
                     .ToList())
        {
            ConsumedNonces.Remove(nonce);
        }
    }

    private static void CompactReplayLedgerLocked(DateTimeOffset now)
    {
        if (_replayLedgerPath is null)
            return;

        PurgeExpiredNoncesLocked(now);
        var directory = Path.GetDirectoryName(_replayLedgerPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var temporary = _replayLedgerPath + ".tmp";
        File.WriteAllLines(
            temporary,
            ConsumedNonces.Select(pair => $"{pair.Key}|{pair.Value.ToUnixTimeSeconds()}"));
        File.Move(temporary, _replayLedgerPath, overwrite: true);
        HardenReplayLedger(_replayLedgerPath);
    }

    private static void HardenReplayLedger(string path)
    {
        if (OperatingSystem.IsWindows())
            return;
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Parent installer/systemd UMask also protects the file.
        }
    }

    private static bool FixedTimeHexEquals(string left, string right)
    {
        try
        {
            var a = Convert.FromHexString(left);
            var b = Convert.FromHexString(right);
            return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
