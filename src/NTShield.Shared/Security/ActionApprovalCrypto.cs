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

    private static string? _signingPrivateKeyPem;
    private static string? _trustedPublicKeyPem;
    private static string? _trustedKeyId;

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

    public static bool HasSigningKey
    {
        get
        {
            lock (Gate) return !string.IsNullOrWhiteSpace(_signingPrivateKeyPem);
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

        // Refuse a mismatched pair instead of producing actions no agent can verify.
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

        // Validate PEM eagerly so malformed policy cannot silently disable response.
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

        if (!IsApprovalValid(request, issued))
            throw new CryptographicException("Central generated an invalid action approval envelope.");
    }

    /// <summary>
    /// Verify target-bound action metadata, expiry, payload hash and RSA-PSS
    /// signature against the public key pinned by Central policy.
    /// </summary>
    public static bool IsApprovalValid(
        ResponseActionRequest request,
        DateTimeOffset? nowUtc = null)
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
        lock (Gate)
        {
            publicKeyPem = _trustedPublicKeyPem;
            trustedKeyId = _trustedKeyId;
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
