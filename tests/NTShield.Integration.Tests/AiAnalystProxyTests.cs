using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.AI;
using NTShield.Shared.Enums;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class AiAnalystProxyTests
{
    [Theory]
    [InlineData("brain-fixed", "alpha", "brain-fixed")]
    [InlineData("{tenant}", "alpha", "alpha")]
    [InlineData(null, "", "default")]
    public async Task Sends_Trusted_Incident_Directly_With_Server_Resolved_Tenant(
        string? configuredTenant,
        string centralTenant,
        string expectedBrainTenant)
    {
        var handler = new RecordingHandler();
        var service = new AiAnalystProxyService(
            Options.Create(new AiAnalystOptions
            {
                Enabled = true,
                BaseUrl = "https://brain.internal/",
                TenantId = configuredTenant!,
                ApiKey = "server-only-key"
            }),
            new TestHttpClientFactory(handler),
            NullLogger<AiAnalystProxyService>.Instance);
        var incident = new Incident
        {
            IncidentId = "trusted-incident",
            TenantId = "alpha",
            Title = "Trusted Central incident",
            Severity = Severity.Critical,
            SourceIp = "203.0.113.10",
            ProcessCommandLine = "tool.exe --password super-secret",
            EvidenceJson = "[{\"rawPacket\":\"do-not-forward\"}]",
            Context = new Dictionary<string, object?> { ["opaquePayload"] = "do-not-forward" },
            EvidenceEvents =
            [
                new EvidenceEventSummary
                {
                    EventId = 4625,
                    EventRecordId = 42,
                    TimestampUtc = DateTimeOffset.Parse("2026-08-08T01:02:03Z"),
                    SourceIp = "203.0.113.10",
                    Username = "alice"
                }
            ]
        };

        var response = await service.AnalyzeIncidentAsync(incident, centralTenant, CancellationToken.None);

        Assert.Equal("{\"ok\":true}", response);
        Assert.Equal("https://brain.internal/v1/incidents/analyze", handler.RequestUri?.ToString());
        Assert.Equal(expectedBrainTenant, handler.TenantHeader);
        Assert.Equal("server-only-key", handler.ApiKeyHeader);
        Assert.Contains("\"incidentId\":\"trusted-incident\"", handler.Body);
        Assert.Contains("\"title\":\"Trusted Central incident\"", handler.Body);
        Assert.Contains("\"sourceIp\":\"203.0.113.10\"", handler.Body);
        Assert.Contains("\"evidencePolicy\":\"structured_references_only\"", handler.Body);
        Assert.Contains("\"eventRecordId\":42", handler.Body);
        Assert.DoesNotContain("super-secret", handler.Body);
        Assert.DoesNotContain("do-not-forward", handler.Body);
        Assert.DoesNotContain("evidenceJson", handler.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rawPacket", handler.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Sends_Temporal_Chain_As_Bounded_Structured_Citations()
    {
        var handler = new RecordingHandler();
        var service = new AiAnalystProxyService(
            Options.Create(new AiAnalystOptions
            {
                Enabled = true,
                BaseUrl = "https://brain.internal",
                TenantId = "{tenant}",
                ApiKey = "server-only-key"
            }),
            new TestHttpClientFactory(handler),
            NullLogger<AiAnalystProxyService>.Instance);
        var summary = new ThreatCampaignV2Summary
        {
            TenantId = "alpha",
            CampaignId = "campaign-42",
            Title = "Repeated outbound contact",
            Severity = "High",
            Status = "Open",
            Revision = 9,
            FirstObservedAtUtc = DateTimeOffset.Parse("2026-08-08T01:00:00Z"),
            LastObservedAtUtc = DateTimeOffset.Parse("2026-08-08T01:10:00Z")
        };
        var observation = new ThreatObservation
        {
            TenantId = "alpha",
            CampaignId = "campaign-42",
            ObservationId = "observation-42",
            EvidenceId = "zeek:flow-42",
            Kind = "network_open",
            Relation = "contacted",
            ObservedAtUtc = DateTimeOffset.Parse("2026-08-08T01:02:00Z"),
            SourceNodeId = "host-a",
            SourceHost = "HOST-A",
            DestinationNodeId = "ip-b",
            DestinationIp = "203.0.113.10",
            RemotePort = 443,
            OccurrenceCount = 1
        };
        var contact = new ThreatContactAggregate
        {
            TenantId = "alpha",
            CampaignId = "campaign-42",
            ContactId = "contact-42",
            SourceNodeId = "host-a",
            DestinationNodeId = "ip-b",
            FirstObservedAtUtc = summary.FirstObservedAtUtc,
            LastObservedAtUtc = summary.LastObservedAtUtc,
            ObservationCount = 7,
            ObservationRecordCount = 7,
            RecurrenceCount = 6,
            MedianGapSeconds = 60,
            BeaconScore = .82
        };

        await service.AnalyzeThreatChainAsync(
            summary, [observation], [contact], 7, 1, "alpha", CancellationToken.None);

        Assert.Equal("alpha", handler.TenantHeader);
        Assert.Contains("\"structuredEvidence\"", handler.Body);
        Assert.Contains("\"refId\":\"zeek:flow-42\"", handler.Body);
        Assert.Contains("\"refId\":\"contact:contact-42\"", handler.Body);
        Assert.Contains("\"source\":\"temporal_chain\"", handler.Body);
        Assert.Contains("\"rawPayloadIncluded\":false", handler.Body);
        Assert.DoesNotContain("rawEvidence", handler.Body, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        public string? TenantHeader { get; private set; }
        public string? ApiKeyHeader { get; private set; }
        public string Body { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            TenantHeader = request.Headers.GetValues("X-NTShield-Tenant").Single();
            ApiKeyHeader = request.Headers.GetValues("X-NTShield-Api-Key").Single();
            Body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}")
            };
        }
    }
}
