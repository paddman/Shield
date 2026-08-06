using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NTShield.Core.Security;

public static class UpdatePackageValidator
{
    public static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static bool VerifySha256(string filePath, string expectedHex)
    {
        if (string.IsNullOrWhiteSpace(expectedHex))
        {
            return false;
        }

        var actual = ComputeSha256(filePath);
        return string.Equals(actual, expectedHex.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates Authenticode signature presence. Full chain trust can be enforced by policy.
    /// </summary>
    public static bool HasDigitalSignature(string filePath)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
            return cert is not null && cert.Handle != IntPtr.Zero;
        }
        catch
        {
            // PE may use Authenticode catalog; try CreateFromSignedFile fallback is obsolete —
            // treat missing embedded cert as unsigned for policy gate.
            return false;
        }
    }

    public static bool VerifySignedConfig(string configJson, string? signatureBase64, string? publicKeyPem)
    {
        // Signature verification optional until keys are provisioned.
        if (string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicKeyPem))
        {
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            var data = System.Text.Encoding.UTF8.GetBytes(configJson);
            var sig = Convert.FromBase64String(signatureBase64);
            return rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }
}
