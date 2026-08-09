using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace NTShield.Server.Security;

public sealed class LocalDashboardCredentialValidator
{
    private const int MinimumIterations = 210_000;
    private readonly IOptions<DashboardAuthOptions> _options;

    public LocalDashboardCredentialValidator(IOptions<DashboardAuthOptions> options)
    {
        _options = options;
    }

    public bool Validate(string? username, string? password, string? totp, DateTimeOffset now)
    {
        var local = _options.Value.Local;
        if (!local.Enabled ||
            string.IsNullOrWhiteSpace(local.Username) ||
            string.IsNullOrWhiteSpace(local.PasswordHash) ||
            string.IsNullOrWhiteSpace(local.TotpSecret) ||
            string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrEmpty(password) ||
            string.IsNullOrWhiteSpace(totp))
        {
            return false;
        }

        return FixedTimeTextEquals(username.Trim(), local.Username.Trim()) &&
               VerifyPassword(password, local.PasswordHash) &&
               VerifyTotp(local.TotpSecret, totp, now);
    }

    public static bool VerifyPassword(string password, string encoded)
    {
        var parts = encoded.Split('$');
        if (parts.Length != 4 ||
            !string.Equals(parts[0], "pbkdf2-sha256", StringComparison.Ordinal) ||
            !int.TryParse(parts[1], out var iterations) ||
            iterations < MinimumIterations)
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            if (salt.Length < 16 || expected.Length < 32) return false;
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool VerifyTotp(string base32Secret, string code, DateTimeOffset now)
    {
        if (code.Length != 6 || !code.All(char.IsAsciiDigit)) return false;
        byte[] key;
        try
        {
            key = DecodeBase32(base32Secret);
        }
        catch (FormatException)
        {
            return false;
        }

        if (key.Length < 10) return false;
        var expected = Encoding.ASCII.GetBytes(code);
        var counter = now.ToUnixTimeSeconds() / 30;
        for (var offset = -1; offset <= 1; offset++)
        {
            var candidate = Encoding.ASCII.GetBytes(GenerateTotp(key, counter + offset));
            if (CryptographicOperations.FixedTimeEquals(candidate, expected)) return true;
        }

        return false;
    }

    private static string GenerateTotp(byte[] key, long counter)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(key, counterBytes, hash);
        var offset = hash[^1] & 0x0f;
        var value = ((hash[offset] & 0x7f) << 24) |
                    (hash[offset + 1] << 16) |
                    (hash[offset + 2] << 8) |
                    hash[offset + 3];
        return (value % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] DecodeBase32(string input)
    {
        var normalized = new string(input.Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray())
            .TrimEnd('=')
            .ToUpperInvariant();
        if (normalized.Length == 0) throw new FormatException("Empty Base32 secret");

        var output = new List<byte>(normalized.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var c in normalized)
        {
            var value = c switch
            {
                >= 'A' and <= 'Z' => c - 'A',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new FormatException("Invalid Base32 secret")
            };
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft < 8) continue;
            output.Add((byte)(buffer >> (bitsLeft - 8)));
            bitsLeft -= 8;
            buffer &= (1 << bitsLeft) - 1;
        }

        return output.ToArray();
    }

    private static bool FixedTimeTextEquals(string left, string right)
    {
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }
}
