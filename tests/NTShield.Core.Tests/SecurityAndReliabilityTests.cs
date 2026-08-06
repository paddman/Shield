using NTShield.Core.Reliability;
using NTShield.Core.Security;
using Xunit;

namespace NTShield.Core.Tests;

public class SecurityAndReliabilityTests
{
    [Fact]
    public void Sanitizer_Redacts_Password_Material()
    {
        var input = "User=admin password=SuperSecret123 token=abc";
        var outp = EventDataSanitizer.SanitizeForLog(input);
        Assert.DoesNotContain("SuperSecret123", outp);
        Assert.Contains("***REDACTED***", outp);
    }

    [Fact]
    public void PathTraversal_Rejected()
    {
        var root = Path.GetTempPath();
        Assert.ThrowsAny<Exception>(() => EventDataSanitizer.SafePath(root, "..\\Windows\\system32"));
    }

    [Fact]
    public void SafePath_Allows_Relative()
    {
        var root = Path.Combine(Path.GetTempPath(), "nts-root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var p = EventDataSanitizer.SafePath(root, "evidence\\file.txt");
        Assert.StartsWith(Path.GetFullPath(root), p, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Allowlist_Contains_Response_Commands_Only()
    {
        Assert.True(EventDataSanitizer.IsAllowlistedCommand("BlockRemoteIp"));
        Assert.False(EventDataSanitizer.IsAllowlistedCommand("cmd.exe /c whoami"));
        Assert.False(EventDataSanitizer.IsAllowlistedCommand("powershell"));
    }

    [Fact]
    public void ExponentialBackoff_Increases_Then_Caps()
    {
        var b = new ExponentialBackoff(TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(100));
        var d1 = b.NextDelay();
        var d2 = b.NextDelay();
        var d3 = b.NextDelay();
        Assert.True(d2 >= d1 || d2.TotalMilliseconds >= 9);
        Assert.True(d3.TotalMilliseconds <= 100 * 1.1);
    }

    [Fact]
    public void ClockSkew_Detection()
    {
        var agent = DateTimeOffset.Parse("2026-01-01T00:05:00Z");
        var server = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var skew = ClockSkew.Compute(agent, server);
        Assert.Equal(TimeSpan.FromMinutes(5), skew);
        Assert.True(ClockSkew.IsSignificant(skew));
    }

    [Fact]
    public void Sha256_Of_Temp_File()
    {
        var path = Path.Combine(Path.GetTempPath(), "nts-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 });
        try
        {
            var hash = UpdatePackageValidator.ComputeSha256(path);
            Assert.Equal(64, hash.Length);
            Assert.True(UpdatePackageValidator.VerifySha256(path, hash));
            Assert.False(UpdatePackageValidator.VerifySha256(path, "00"));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
