using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Agent;
using NTShield.Core.Configuration;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class CodeScanServiceTests
{
    [Fact]
    public async Task ScansWebCodeRedactsSecretsAndSubmitsToBrain()
    {
        var root = Path.Combine(Path.GetTempPath(), "ntshield-code-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "server.js"),
                "const { exec } = require('child_process');\nexec(req.query.cmd);\n");
            await File.WriteAllTextAsync(Path.Combine(root, ".env"), "API_KEY=top-secret-value-12345\n");

            var handler = new CaptureHandler();
            var scanner = new CodeScanService(
                Options.Create(new CodeScanOptions
                {
                    Enabled = true,
                    AutoDiscoverWebRoots = false,
                    Paths = [root],
                    BrainUrl = "https://brain.test",
                    TenantId = "demo",
                    ApiKey = "test-key",
                    MaxFilesPerProject = 10,
                    MaxFindingsPerProject = 20
                }),
                Options.Create(new AgentOptions { AgentId = "agent-test", ComputerName = "TEST-HOST" }),
                NullLogger<CodeScanService>.Instance,
                new HttpClient(handler));

            var results = await scanner.RunAsync(CancellationToken.None);

            var result = Assert.Single(results);
            Assert.True(result.Sent);
            Assert.True(result.LlmUsed);
            Assert.Equal("high", result.Verdict);
            Assert.True(result.Findings >= 2);
            Assert.NotNull(handler.Body);
            Assert.Contains("WEB.COMMAND_INJECTION", handler.Body!, StringComparison.Ordinal);
            Assert.Contains("SECRET.HARDCODED", handler.Body!, StringComparison.Ordinal);
            Assert.DoesNotContain("top-secret-value-12345", handler.Body!, StringComparison.Ordinal);
            Assert.DoesNotContain(root, handler.Body!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"verdict\":\"high\",\"model\":\"qwen3.5:9b\",\"llmUsed\":true}")
            };
        }
    }
}
