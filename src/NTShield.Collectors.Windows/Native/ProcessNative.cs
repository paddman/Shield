using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NTShield.Collectors.Windows.Native;

/// <summary>
/// Process helpers using APIs available since Windows Server 2012.
/// </summary>
internal static class ProcessNative
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    public static string? GetProcessPath(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
            if (handle == IntPtr.Zero)
            {
                return null;
            }
        }

        try
        {
            var size = 1024;
            var sb = new StringBuilder(size);
            if (QueryFullProcessImageName(handle, 0, sb, ref size))
            {
                return sb.ToString();
            }

            return null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public static string? ComputeSha256(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(path);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    public static (string Status, string? Signer) GetSignatureInfo(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return ("Unknown", null);
        }

        try
        {
            // Prefer certificate loader APIs; fall back if file is not a cert store object.
            // Authenticode signed PE: try exporting cert bytes via signed file path through WinVerifyTrust is heavy;
            // use X509Certificate2 when possible without obsolete CreateFromSignedFile.
            var cert = TryLoadSignerCertificate(path);
            if (cert is null)
            {
                return ("UnsignedOrUntrusted", null);
            }

            using (cert)
            {
                return ("Signed", cert.GetNameInfo(X509NameType.SimpleName, false));
            }
        }
        catch
        {
            return ("UnsignedOrUntrusted", null);
        }
    }

    private static X509Certificate2? TryLoadSignerCertificate(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // Required fallback for Authenticode PE on Server 2012-era tooling
            var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return new X509Certificate2(cert);
        }
        catch
        {
            return null;
        }
    }
}
