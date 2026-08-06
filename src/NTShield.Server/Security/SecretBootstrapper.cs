using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Security;

/// <summary>
/// On boot: load or generate EnrollmentToken + OperatorApiKey into SecurityOptions + secrets.json.
/// </summary>
public static class SecretBootstrapper
{
    public static void Apply(IConfiguration configuration, SecurityOptions security)
    {
        // Config already bound; merge secrets file if present
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
                        node["EnrollmentToken"]?.GetValue<string>() is { Length: > 0 } et)
                        security.EnrollmentToken = et;
                    if (string.IsNullOrWhiteSpace(security.OperatorApiKey) &&
                        node["OperatorApiKey"]?.GetValue<string>() is { Length: > 0 } ok)
                        security.OperatorApiKey = ok;
                }
            }
            catch
            {
                // ignore corrupt secrets file
            }
        }

        if (!security.AutoGenerateSecretsOnBoot)
            return;

        var changed = false;
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

        if (!changed && File.Exists(path))
            return;

        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var payload = new
            {
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                EnrollmentToken = security.EnrollmentToken,
                OperatorApiKey = security.OperatorApiKey,
                Note = "Copy EnrollmentToken to agents (Server:EnrollmentToken). Copy OperatorApiKey to Dashboard (Central:ApiKey). Enable Security:RequireAuth=true for production."
            };
            File.WriteAllText(path, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
            Serilog.Log.Warning(
                "Central secrets ready at {Path} (EnrollmentToken + OperatorApiKey). Set Security:RequireAuth=true after distributing keys.",
                path);
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Failed to write secrets file {Path}", path);
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
}
