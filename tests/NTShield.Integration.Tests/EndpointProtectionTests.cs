using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Agent;
using NTShield.Core.Configuration;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class EndpointProtectionTests
{
    [Fact]
    public async Task Hash_Signature_Produces_Malicious_Result()
    {
        var root = Path.Combine(Path.GetTempPath(), "nts-av-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var file = Path.Combine(root, "sample.bin");
            await File.WriteAllTextAsync(file, "known test payload");
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("known test payload"))).ToLowerInvariant();
            var payload = new ProtectionPackPayload
            {
                HashSignatures =
                [
                    new ProtectionHashSignature { Sha256 = hash, Name = "test-signature", Severity = Severity.Critical }
                ]
            };
            var packPath = Path.Combine(root, "pack.json");
            await File.WriteAllTextAsync(packPath, JsonSerializer.Serialize(new ProtectionPack
            {
                Version = 1,
                PayloadJson = JsonSerializer.Serialize(payload)
            }));

            var service = new EndpointProtectionService(
                Options.Create(new AntivirusOptions
                {
                    EnableDefender = false,
                    EnableYara = false,
                    RealTimeMonitoring = false,
                    ScheduledScanEnabled = false,
                    ScanPaths = [],
                    ExcludedPaths = [],
                    LocalProtectionPackPath = packPath,
                    ProtectionDataDirectory = "protection"
                }),
                Options.Create(new AgentOptions { AgentId = "test", ComputerName = "TEST", DataDirectory = root }),
                NullLogger<EndpointProtectionService>.Instance);
            service.Start();
            try
            {
                var result = await service.ScanFileAsync(file, CancellationToken.None);
                Assert.Equal("malicious", result.Verdict);
                Assert.Equal(Severity.Critical, result.Severity);
                Assert.Contains(result.Signals, s => s.Source == "signature");
            }
            finally
            {
                service.Stop();
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Quarantine_And_Restore_Use_Vault_Metadata()
    {
        var root = Path.Combine(Path.GetTempPath(), "nts-vault-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "restore-me.txt");
        await File.WriteAllTextAsync(file, "restore test");
        var service = new EndpointProtectionService(
            Options.Create(new AntivirusOptions
            {
                EnableDefender = false,
                EnableYara = false,
                RealTimeMonitoring = false,
                ScheduledScanEnabled = false,
                ScanPaths = [],
                ExcludedPaths = [],
                ProtectionDataDirectory = "protection"
            }),
            Options.Create(new AgentOptions { AgentId = "test", ComputerName = "TEST", DataDirectory = root }),
            NullLogger<EndpointProtectionService>.Instance);
        service.Start();
        try
        {
            var quarantined = await service.QuarantineFileAsync(file, "unit-test", CancellationToken.None);
            Assert.True(quarantined.Success, quarantined.Error);
            Assert.False(File.Exists(file));
            Assert.NotEmpty(quarantined.QuarantineId);

            var restored = await service.RestoreQuarantinedFileAsync(quarantined.QuarantineId, CancellationToken.None);
            Assert.True(restored.Success, restored.Error);
            Assert.True(File.Exists(file));
        }
        finally
        {
            service.Stop();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Wildcard_Excluded_Path_Is_Not_Scanned()
    {
        var root = Path.Combine(Path.GetTempPath(), "nts-excluded-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "temporary.ps1");
        await File.WriteAllTextAsync(file, "Write-Output test");
        var service = new EndpointProtectionService(
            Options.Create(new AntivirusOptions
            {
                EnableDefender = false,
                EnableYara = false,
                RealTimeMonitoring = false,
                ScheduledScanEnabled = false,
                ScanPaths = [],
                ExcludedPaths = ["C:\\Users\\*\\AppData\\Local\\Temp\\"],
                ProtectionDataDirectory = "protection"
            }),
            Options.Create(new AgentOptions { AgentId = "test", ComputerName = "TEST", DataDirectory = root }),
            NullLogger<EndpointProtectionService>.Instance);
        service.Start();
        try
        {
            var result = await service.ScanFileAsync(file, CancellationToken.None);
            Assert.Equal("skipped_policy", result.Verdict);
        }
        finally
        {
            service.Stop();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
