using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using NTShield.Shared.Security;

namespace NTShield.Server.Security;

/// <summary>
/// On boot: load or generate enrollment/operator credentials and a Central-only
/// RSA action-signing key pair in secrets.json. The private key never appears in
/// policy, API responses or logs.
/// </summary>
public static class SecretBootstrapper
{
    public static void Apply(IConfiguration configuration, SecurityOptions security)
    {
        _ = configuration;
        var path = string.IsNullOrWhiteSpace(security.SecretsFilePath)
            ? @"C:\ProgramData\NTShield\Server\secrets.json"
            : security.SecretsFilePath;

        if (File.Exists(path))
        {
            try
            {
                var node = JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
                if (node is not null)
                {
                    if (string.IsNullOrWhiteSpace(security.EnrollmentToken) &&
                        node["EnrollmentToken"]?.GetValue<string>() is { Length: > 0 } enrollmentToken)
                    {
                        security.EnrollmentToken = enrollmentToken;
                    }

                    if (string.IsNullOrWhiteSpace(security.OperatorApiKey) &&
                        node["OperatorApiKey"]?.GetValue<string>() is { Length: > 0 } operatorApiKey)
                    {
                        security.OperatorApiKey = operatorApiKey;
                    }

                    if (string.IsNullOrWhiteSpace(security.ActionSigningPrivateKeyPem) &&
                        node["ActionSigningPrivateKeyPem"]?.GetValue<string>() is { Length: > 0 } privatePem)
                    {
                        security.ActionSigningPrivateKeyPem = privatePem;
                    }

                    if (string.IsNullOrWhiteSpace(security.ActionSigningPublicKeyPem) &&
                        node["ActionSigningPublicKeyPem"]?.GetValue<string>() is { Length: > 0 } publicPem)
                    {
                        security.ActionSigningPublicKeyPem = publicPem;
                    }

                    if (string.IsNullOrWhiteSpace(security.ActionSigningKeyId) &&
                        node["ActionSigningKeyId"]?.GetValue<string>() is { Length: > 0 } keyId)
                    {
                        security.ActionSigningKeyId = keyId;
                    }
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "Central secrets file is unreadable or corrupt: {Path}", path);
                if (!security.AutoGenerateSecretsOnBoot)
                    throw;
            }
        }

        var changed = false;
        if (security.AutoGenerateSecretsOnBoot)
        {
            if (string.IsNullOrWhiteSpace(security.EnrollmentToken))
            {
                security.EnrollmentToken = GenerateKey();
                changed = true;
            }

            if (string.IsNullOrWhiteSpace(security.OperatorApiKey))
            {
                security.OperatorApiKey = GenerateKey();
                changed = true;
            }

            if (string.IsNullOrWhiteSpace(security.ActionSigningPrivateKeyPem))
            {
                using var rsa = RSA.Create(3072);
                security.ActionSigningPrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
                security.ActionSigningPublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
                security.ActionSigningKeyId = ActionApprovalCrypto.ComputeKeyId(
                    security.ActionSigningPublicKeyPem);
                changed = true;
            }
        }

        // Derive missing public material from an explicitly supplied private key.
        if (!string.IsNullOrWhiteSpace(security.ActionSigningPrivateKeyPem) &&
            string.IsNullOrWhiteSpace(security.ActionSigningPublicKeyPem))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(security.ActionSigningPrivateKeyPem);
            security.ActionSigningPublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
            changed = true;
        }

        if (!string.IsNullOrWhiteSpace(security.ActionSigningPublicKeyPem) &&
            string.IsNullOrWhiteSpace(security.ActionSigningKeyId))
        {
            security.ActionSigningKeyId = ActionApprovalCrypto.ComputeKeyId(
                security.ActionSigningPublicKeyPem);
            changed = true;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(security.ActionSigningPrivateKeyPem) &&
                !string.IsNullOrWhiteSpace(security.ActionSigningPublicKeyPem))
            {
                ActionApprovalCrypto.ConfigureSigningKey(
                    security.ActionSigningPrivateKeyPem,
                    security.ActionSigningPublicKeyPem,
                    security.ActionSigningKeyId);
            }
            else if (!string.IsNullOrWhiteSpace(security.ActionSigningPublicKeyPem))
            {
                // Verification-only configuration is allowed, but Central will
                // refuse to enqueue destructive actions because it cannot sign.
                ActionApprovalCrypto.ConfigureTrustedPublicKey(
                    security.ActionSigningPublicKeyPem,
                    security.ActionSigningKeyId);
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Fatal(ex, "Invalid Central action-signing key material");
            throw new InvalidOperationException("Central action-signing keys are invalid.", ex);
        }

        if (!changed && File.Exists(path))
        {
            HardenSecretsFile(path);
            return;
        }

        if (!security.AutoGenerateSecretsOnBoot && !File.Exists(path))
        {
            Serilog.Log.Warning(
                "AutoGenerateSecretsOnBoot=false and no secrets file exists at {Path}; Central remains fail-closed.",
                path);
            return;
        }

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            var payload = new
            {
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                EnrollmentToken = security.EnrollmentToken,
                OperatorApiKey = security.OperatorApiKey,
                ActionSigningPrivateKeyPem = security.ActionSigningPrivateKeyPem,
                ActionSigningPublicKeyPem = security.ActionSigningPublicKeyPem,
                ActionSigningKeyId = security.ActionSigningKeyId,
                Note = "EnrollmentToken is for first enrollment. OperatorApiKey is for the Control Center. Never copy ActionSigningPrivateKeyPem to an agent."
            };

            var temporaryPath = path + ".tmp";
            File.WriteAllText(
                temporaryPath,
                JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporaryPath, path, overwrite: true);
            HardenSecretsFile(path);

            Serilog.Log.Warning(
                "Central security secrets initialized at {Path}; API authentication is enabled by default. Action signing key id={KeyId}.",
                path,
                security.ActionSigningKeyId);
        }
        catch (Exception ex)
        {
            Serilog.Log.Fatal(ex, "Failed to persist Central secrets at {Path}", path);
            throw;
        }
    }

    public static string GenerateKey() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    public static string HashApiKey(string key)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(key.Trim());
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void HardenSecretsFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // The installer should additionally ACL this path to SYSTEM and
            // Administrators. Do not weaken inherited ACLs from ProgramData here.
            return;
        }

        try
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Could not set mode 0600 on Central secrets file {Path}", path);
        }
    }
}
