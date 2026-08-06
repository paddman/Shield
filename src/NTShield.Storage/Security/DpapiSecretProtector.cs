using System.Security.Cryptography;
using System.Text;

namespace NTShield.Storage.Security;

/// <summary>
/// Protects secrets with Windows DPAPI (LocalMachine scope for service accounts).
/// Available since long before Windows Server 2012.
/// </summary>
public static class DpapiSecretProtector
{
    public static string Protect(string plaintext)
    {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(protectedBytes);
    }

    public static string Unprotect(string protectedBase64)
    {
        var protectedBytes = Convert.FromBase64String(protectedBase64);
        var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(bytes);
    }
}
