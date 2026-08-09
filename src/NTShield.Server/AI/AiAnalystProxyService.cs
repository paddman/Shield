using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using NTShield.Shared.Models;

namespace NTShield.Server.AI;

public sealed class AiAnalystProxyException : Exception
{
    public AiAnalystProxyException(int statusCode, string error)
        : base(error)
    {
        StatusCode = statusCode;
        Error = error;
    }

    public int StatusCode { get; }
    public string Error { get; }
}

/// <summary>
/// Narrow Central-side proxy for the Brain incident analysis endpoint.
/// No upstream LLM secret is exposed to the web client.
/// </summary>
public sealed class AiAnalystProxyService
{
    private readonly AiAnalystOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AiAnalystProxyService> _logger;

    public AiAnalystProxyService(
        IOptions<AiAnalystOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<AiAnalystProxyService> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured =>
        _options.Enabled && Uri.TryCreate(_options.BaseUrl, UriKind.Absolute, out var uri) &&
        (string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase));

    public string TenantId => string.IsNullOrWhiteSpace(_options.TenantId) ? "default" : _options.TenantId.Trim();

    public string ResolveBrainTenantId(string centralTenantId)
    {
        if (string.Equals(_options.TenantId?.Trim(), "{tenant}", StringComparison.OrdinalIgnoreCase))
            return string.IsNullOrWhiteSpace(centralTenantId) ? "default" : centralTenantId.Trim();

        return TenantId;
    }

    public Task<string> AnalyzeIncidentAsync(
        Incident incident,
        string centralTenantId,
        CancellationToken cancellationToken) =>
        AnalyzePayloadAsync(
            BuildStructuredIncidentPayload(incident),
            incident.IncidentId,
            centralTenantId,
            cancellationToken);

    public Task<string> AnalyzeThreatChainAsync(
        ThreatCampaignV2Summary summary,
        IReadOnlyCollection<ThreatObservation> observations,
        IReadOnlyCollection<ThreatContactAggregate> contacts,
        long observationTotal,
        long contactTotal,
        string centralTenantId,
        CancellationToken cancellationToken) =>
        AnalyzePayloadAsync(
            BuildStructuredThreatPayload(summary, observations, contacts, observationTotal, contactTotal),
            summary.CampaignId,
            centralTenantId,
            cancellationToken);

    private async Task<string> AnalyzePayloadAsync(
        object payload,
        string subjectId,
        string centralTenantId,
        CancellationToken cancellationToken)
    {
        if (!IsConfigured)
            throw new AiAnalystProxyException(StatusCodes.Status503ServiceUnavailable, "ai_analyst_not_configured");

        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var endpoint = $"{baseUrl}/v1/incidents/analyze";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("X-NTShield-Tenant", ResolveBrainTenantId(centralTenantId));
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            request.Headers.TryAddWithoutValidation("X-NTShield-Api-Key", _options.ApiKey);
        request.Content = JsonContent.Create(
            payload,
            options: new JsonSerializerOptions(JsonSerializerDefaults.Web));

        try
        {
            using var client = _httpClientFactory.CreateClient("ai-analyst");
            client.Timeout = TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 5, 300));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("AI Analyst proxy failed status={Status} subject={SubjectId}",
                    (int)response.StatusCode, subjectId);
                throw new AiAnalystProxyException((int)response.StatusCode, ExtractError(body));
            }

            return body;
        }
        catch (AiAnalystProxyException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AiAnalystProxyException(StatusCodes.Status504GatewayTimeout, "ai_analyst_timeout");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("AI Analyst proxy unreachable subject={SubjectId}: {Error}", subjectId, ex.Message);
            throw new AiAnalystProxyException(StatusCodes.Status502BadGateway, "ai_analyst_unreachable");
        }
    }

    /// <summary>
    /// Brain receives bounded facts and stable evidence references by default.
    /// Arbitrary Context/EvidenceJson, command lines and packet payloads stay on
    /// Central/provider storage and are never forwarded as an opaque blob.
    /// </summary>
    internal static object BuildStructuredIncidentPayload(Incident incident)
    {
        static string Bound(string? value, int max)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            var clean = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return clean.Length <= max ? clean : clean[..max];
        }

        var evidence = incident.EvidenceEvents
            .Where(item => item.TimestampUtc != default && item.TimestampUtc != DateTimeOffset.MinValue)
            .OrderBy(item => item.TimestampUtc)
            .TakeLast(50)
            .Select(item => new
            {
                eventId = item.EventId,
                eventRecordId = item.EventRecordId,
                timestampUtc = item.TimestampUtc,
                username = Bound(item.Username, 200),
                sourceIp = Bound(item.SourceIp, 64),
                status = Bound(item.Status, 120)
            })
            .ToArray();

        return new
        {
            incidentId = Bound(incident.IncidentId, 200),
            title = Bound(incident.Title, 500),
            ruleId = Bound(incident.RuleId, 200),
            severity = incident.Severity.ToString(),
            description = Bound(incident.Description, 4_000),
            status = Bound(incident.Status, 80),
            incidentScore = incident.IncidentScore,
            detectionStage = Bound(incident.DetectionStage, 500),
            sourceIp = Bound(incident.SourceIp, 64),
            sourceHost = Bound(incident.SourceHost, 255),
            sourceAgentId = Bound(incident.SourceAgentId, 200),
            sourcePort = incident.SourcePort,
            destinationIp = Bound(incident.DestinationIp, 64),
            destinationHost = Bound(incident.DestinationHost, 255),
            destinationAgentId = Bound(incident.DestinationAgentId, 200),
            destinationPort = incident.DestinationPort,
            username = Bound(incident.Username, 200),
            domain = Bound(incident.Domain, 255),
            processName = Bound(incident.ProcessName, 255),
            processId = incident.ProcessId,
            executableSha256 = Bound(incident.ExecutableSha256, 64),
            services = incident.Services.Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => Bound(item, 255)).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToArray(),
            serviceAccount = Bound(incident.ServiceAccount, 255),
            failedAttempts = Math.Max(0, incident.FailedAttempts),
            distinctUsernames = Math.Max(0, incident.DistinctUsernames),
            successfulLoginDetected = incident.SuccessfulLoginDetected,
            privilegedLogon = incident.PrivilegedLogon,
            firstSeen = incident.FirstSeen,
            lastSeen = incident.LastSeen,
            evidenceEvents = evidence,
            privacyMode = "full",
            context = new
            {
                evidencePolicy = "structured_references_only",
                rawPayloadIncluded = false,
                evidenceTruncated = incident.EvidenceEvents.Count > evidence.Length,
                evidenceTotal = incident.EvidenceEvents.Count
            }
        };
    }

    internal static object BuildStructuredThreatPayload(
        ThreatCampaignV2Summary summary,
        IReadOnlyCollection<ThreatObservation> observations,
        IReadOnlyCollection<ThreatContactAggregate> contacts,
        long observationTotal,
        long contactTotal)
    {
        static string Bound(string? value, int max)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            var clean = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return clean.Length <= max ? clean : clean[..max];
        }

        static string Endpoint(string? host, string? ip, string nodeId) =>
            Bound(host, 255) is { Length: > 0 } cleanHost ? cleanHost :
            Bound(ip, 64) is { Length: > 0 } cleanIp ? cleanIp : Bound(nodeId, 200);

        var observationEvidence = observations
            .OrderBy(item => item.ObservedAtUtc)
            .TakeLast(100)
            .Select(item => new
            {
                refId = Bound(string.IsNullOrWhiteSpace(item.EvidenceId)
                    ? $"observation:{item.ObservationId}"
                    : item.EvidenceId, 160),
                source = "temporal_chain",
                kind = Bound(item.Kind, 80),
                timestampUtc = item.ObservedAtUtc,
                summary = Bound(
                    $"{item.Relation}: {Endpoint(item.SourceHost, item.SourceIp, item.SourceNodeId)} -> " +
                    $"{Endpoint(item.DestinationHost, item.DestinationIp, item.DestinationNodeId)}" +
                    (item.RemotePort is null ? string.Empty : $":{item.RemotePort}") +
                    $" count={Math.Max(1, item.OccurrenceCount)}",
                    1_200),
                attributes = new
                {
                    observationId = Bound(item.ObservationId, 200),
                    item.EpisodeId,
                    fromNodeId = Bound(item.SourceNodeId, 200),
                    toNodeId = Bound(item.DestinationNodeId, 200),
                    sourceIp = Bound(item.SourceIp, 64),
                    destinationIp = Bound(item.DestinationIp, 64),
                    protocol = Bound(item.Protocol, 32),
                    item.LocalPort,
                    destinationPort = item.RemotePort,
                    username = Bound(item.Username, 200),
                    processName = Bound(item.ProcessName, 255),
                    technique = Bound(item.Technique, 120),
                    occurrenceCount = Math.Max(1, item.OccurrenceCount),
                    item.Inferred,
                    confidence = Math.Clamp(item.Confidence, 0, 1),
                    timestampQuality = Bound(item.TimestampQuality, 80)
                }
            });

        var contactEvidence = contacts
            .OrderByDescending(item => item.LastObservedAtUtc)
            .Take(50)
            .Select(item => new
            {
                refId = Bound($"contact:{item.ContactId}", 160),
                source = "temporal_chain",
                kind = "contact_aggregate",
                timestampUtc = item.LastObservedAtUtc,
                summary = Bound(
                    $"Repeated contact {Endpoint(item.SourceHost, item.SourceIp, item.SourceNodeId)} -> " +
                    $"{Endpoint(item.DestinationHost, item.DestinationIp, item.DestinationNodeId)} " +
                    $"observations={item.ObservationCount} recurrences={item.RecurrenceCount} " +
                    $"reconnects={item.ReconnectCount}",
                    1_200),
                attributes = new
                {
                    contactKey = Bound(item.ContactId, 200),
                    fromNodeId = Bound(item.SourceNodeId, 200),
                    toNodeId = Bound(item.DestinationNodeId, 200),
                    item.FirstObservedAtUtc,
                    item.LastObservedAtUtc,
                    item.ObservationCount,
                    item.ObservationRecordCount,
                    item.RecurrenceCount,
                    item.OpenCount,
                    item.CloseCount,
                    item.ReconnectCount,
                    item.DurationSeconds,
                    item.MedianGapSeconds,
                    item.P95GapSeconds,
                    item.BeaconScore,
                    item.Inferred,
                    confidence = Math.Clamp(item.Confidence, 0, 1),
                    evidenceRefs = item.EvidenceRefs.Take(20).Select(value => Bound(value, 160)).ToArray()
                }
            });

        var structuredEvidence = observationEvidence.Cast<object>().Concat(contactEvidence).Take(150).ToArray();
        return new
        {
            incidentId = Bound($"campaign:{summary.CampaignId}", 200),
            title = Bound(summary.Title, 500),
            ruleId = "temporal_attack_chain_v2",
            severity = Bound(summary.Severity, 32),
            description = Bound(summary.Summary, 4_000),
            status = Bound(summary.Status, 80),
            firstSeen = summary.FirstObservedAtUtc,
            lastSeen = summary.LastObservedAtUtc,
            structuredEvidence,
            privacyMode = "full",
            context = new
            {
                evidencePolicy = "structured_references_only",
                rawPayloadIncluded = false,
                campaignId = Bound(summary.CampaignId, 200),
                summary.Revision,
                observationTotal,
                contactTotal,
                evidenceTruncated = observationTotal > observations.Count || contactTotal > contacts.Count,
                unknownsRequired = true
            }
        };
    }

    private static string ExtractError(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "ai_analyst_failed";
        return body.Length > 300 ? body[..300] : body;
    }
}
