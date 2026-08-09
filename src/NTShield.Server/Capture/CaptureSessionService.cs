using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using NTShield.Server.Services;

namespace NTShield.Server.Capture;

public sealed class CaptureProviderUnavailableException : Exception
{
    public CaptureProviderUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class CaptureAuditUnavailableException : Exception
{
    public CaptureAuditUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class CaptureSessionService
{
    private static readonly Regex IdPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$", RegexOptions.Compiled);
    private static readonly Regex Sha256Pattern = new("^[a-fA-F0-9]{64}$", RegexOptions.Compiled);
    private static readonly Regex HeaderNamePattern = new("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$", RegexOptions.Compiled);
    private static readonly HashSet<string> ExportFormats = new(StringComparer.OrdinalIgnoreCase) { "pcap", "pcapng" };
    private static readonly HashSet<string> DecryptionStates = new(StringComparer.OrdinalIgnoreCase)
    {
        "not_attempted", "metadata_only", "decrypted_by_provider", "excluded", "failed",
        "quic_bypass", "certificate_pinning_bypass", "mtls_bypass", "policy_exclusion", "inspection_failed"
    };
    private readonly ICaptureControlStore _store;
    private readonly ICaptureProviderResolver _providers;
    private readonly CaptureControlOptions _options;
    private readonly ILogger<CaptureSessionService> _logger;
    private readonly IDataProtector _cursorProtector;

    public CaptureSessionService(
        ICaptureControlStore store,
        ICaptureProviderResolver providers,
        IOptions<CaptureControlOptions> options,
        ILogger<CaptureSessionService> logger,
        IDataProtectionProvider dataProtection)
    {
        _store = store;
        _providers = providers;
        _options = options.Value;
        _logger = logger;
        _cursorProtector = dataProtection.CreateProtector("NTShield.Capture.SessionCursor.v2");
    }

    public async Task IngestProviderSessionAsync(
        string providerId,
        CaptureProviderSession input,
        CancellationToken cancellationToken = default)
    {
        providerId = ValidateId(providerId, "provider id");
        _ = _providers.GetRequired(providerId);
        var providerConfig = _options.Providers.First(item =>
            string.Equals(item.Id, providerId, StringComparison.OrdinalIgnoreCase));
        var tenantId = TopologyService.NormalizeTenantId(input.TenantId);
        if (providerConfig.TenantIds.Count > 0 && !providerConfig.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase))
            throw new CaptureValidationException($"Provider '{providerId}' is not assigned to tenant '{tenantId}'.");

        var normalizedTls = NormalizeTls(input.Tls);
        if (normalizedTls is not null)
            normalizedTls.DecryptedArtifactReference = Optional(input.TlsArtifactReference, 1024);
        var session = new CaptureSessionMetadata
        {
            TenantId = tenantId,
            SessionId = ValidateId(input.SessionId, "session id"),
            FlowId = ValidateId(input.FlowId, "flow id"),
            CorrelationId = OptionalId(input.CorrelationId, "correlation id"),
            CampaignId = OptionalId(input.CampaignId, "campaign id"),
            EdgeId = OptionalId(input.EdgeId, "edge id"),
            IncidentId = OptionalId(input.IncidentId, "incident id"),
            ProviderId = providerId,
            SensorId = ValidateId(input.SensorId, "sensor id"),
            StartedAtUtc = input.StartedAtUtc,
            EndedAtUtc = input.EndedAtUtc,
            SourceIp = ValidateAddress(input.SourceIp, "source IP"),
            SourcePort = ValidatePort(input.SourcePort),
            DestinationIp = ValidateAddress(input.DestinationIp, "destination IP"),
            DestinationPort = ValidatePort(input.DestinationPort),
            Protocol = Required(input.Protocol, "protocol", 24).ToLowerInvariant(),
            Application = Optional(input.Application, 80),
            SourceHost = Optional(input.SourceHost, 255),
            DestinationHost = Optional(input.DestinationHost, 255),
            SourceAgentId = OptionalId(input.SourceAgentId, "source agent id"),
            DestinationAgentId = OptionalId(input.DestinationAgentId, "destination agent id"),
            ProcessId = input.ProcessId,
            ProcessName = Optional(input.ProcessName, 260),
            ProcessPath = Optional(input.ProcessPath, 1024),
            UserName = Optional(input.UserName, 256),
            PacketCount = input.PacketCount,
            ByteCount = input.ByteCount,
            PayloadAvailable = input.PayloadAvailable && !string.IsNullOrWhiteSpace(input.PayloadReference),
            PayloadBytes = input.PayloadBytes,
            PayloadSha256 = Optional(input.PayloadSha256, 64)?.ToLowerInvariant(),
            EncryptionKeyVersion = OptionalId(input.EncryptionKeyVersion, "encryption key version"),
            StorageTier = input.StorageTier,
            StoragePoolId = OptionalId(input.StoragePoolId, "storage pool id"),
            PayloadReference = Optional(input.PayloadReference, 1024),
            Tls = normalizedTls,
            Tags = (input.Tags ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => Required(item, "tag", 64)).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToList()
        };
        if (session.StartedAtUtc == default || session.StartedAtUtc > DateTimeOffset.UtcNow.AddMinutes(5))
            throw new CaptureValidationException("Session start time is invalid.");
        if (session.EndedAtUtc < session.StartedAtUtc)
            throw new CaptureValidationException("Session end time precedes its start time.");
        if (session.PacketCount < 0 || session.ByteCount < 0 || session.PayloadBytes < 0)
            throw new CaptureValidationException("Session counters cannot be negative.");
        if (session.ProcessId < 0) throw new CaptureValidationException("Process id cannot be negative.");
        if (session.PayloadAvailable && (session.PayloadSha256 is null || !Sha256Pattern.IsMatch(session.PayloadSha256)))
            throw new CaptureValidationException("Payload-bearing sessions require a SHA-256 manifest checksum.");
        if (session.PayloadAvailable &&
            (string.IsNullOrWhiteSpace(session.EncryptionKeyVersion) || string.IsNullOrWhiteSpace(session.StoragePoolId)))
            throw new CaptureValidationException("Payload-bearing sessions require a logical KMS key version and storage pool id.");
        if (session.PayloadAvailable && session.StorageTier == CaptureStorageTier.MetadataOnly)
            throw new CaptureValidationException("Payload-bearing sessions require a hot, cold, or archive storage tier.");
        if (!session.PayloadAvailable)
        {
            session.PayloadReference = null;
            session.PayloadBytes = 0;
            session.PayloadSha256 = null;
            session.EncryptionKeyVersion = null;
            session.StoragePoolId = null;
            session.StorageTier = CaptureStorageTier.MetadataOnly;
        }
        if (session.Tls?.DecryptedArtifactAvailable == true)
        {
            if (string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactReference) ||
                string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactSha256) ||
                !Sha256Pattern.IsMatch(session.Tls.DecryptedArtifactSha256) ||
                string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactProviderId) ||
                string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactKeyVersion) ||
                string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactStoragePoolId) ||
                session.Tls.DecryptedArtifactStorageTier == CaptureStorageTier.MetadataOnly)
                throw new CaptureValidationException("A decrypted TLS artifact requires an opaque provider reference, SHA-256, KMS key version, and storage tier metadata.");
            EnsureProviderAssignedToTenant(session.Tls.DecryptedArtifactProviderId!, tenantId);
        }
        else if (session.Tls is not null)
        {
            session.Tls.DecryptedArtifactReference = null;
            session.Tls.DecryptedArtifactProviderId = null;
            session.Tls.DecryptedArtifactSha256 = null;
            session.Tls.DecryptedArtifactKeyVersion = null;
            session.Tls.DecryptedArtifactStoragePoolId = null;
            session.Tls.DecryptedArtifactStorageTier = CaptureStorageTier.MetadataOnly;
        }

        var policies = (await _store.ListPoliciesAsync(tenantId, cancellationToken))
            .Where(item => item.Enabled && string.Equals(item.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var hotDays = policies.Count == 0 ? Math.Min(7, _options.DefaultSessionRetentionDays) :
            policies.Max(item => item.StorageLifecycle.HotDays);
        var retentionDays = policies.Count == 0 ? _options.DefaultSessionRetentionDays :
            policies.Max(item => item.StorageLifecycle.ExpireAfterDays);
        retentionDays = Math.Clamp(retentionDays, 1, _options.MaxSessionMetadataRetentionDays);
        hotDays = Math.Clamp(hotDays, 1, retentionDays);
        var maximumRetention = session.StartedAtUtc.AddDays(retentionDays);
        if (input.RetainUntilUtc is not null && input.RetainUntilUtc <= session.StartedAtUtc)
            throw new CaptureValidationException("Provider retention time must be after the session start.");
        session.RetainUntilUtc = input.RetainUntilUtc is not null && input.RetainUntilUtc < maximumRetention
            ? input.RetainUntilUtc
            : maximumRetention;
        var maximumHot = session.StartedAtUtc.AddDays(hotDays);
        session.HotUntilUtc = input.HotUntilUtc is not null && input.HotUntilUtc < maximumHot
            ? input.HotUntilUtc
            : maximumHot;
        if (session.HotUntilUtc > session.RetainUntilUtc) session.HotUntilUtc = session.RetainUntilUtc;
        if (!await _store.UpsertSessionAsync(session, cancellationToken))
            throw new CaptureValidationException("Session id is already owned by another capture provider.");
    }

    public async Task<CaptureSessionPage> QueryAsync(
        string tenantId,
        CaptureSessionQuery query,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        query ??= new CaptureSessionQuery();
        query.Take = Math.Clamp(query.Take, 1, _options.MaxSessionsPerQuery);
        query.Address = Optional(query.Address, 64);
        if (query.Address is not null) query.Address = ValidateAddress(query.Address, "address");
        query.Protocol = Optional(query.Protocol, 24)?.ToLowerInvariant();
        query.ProviderId = Optional(query.ProviderId, 128);
        query.CampaignId = OptionalId(query.CampaignId, "campaign id");
        query.EdgeId = OptionalId(query.EdgeId, "edge id");
        if (query.Port is not null) query.Port = ValidatePort(query.Port);
        if (query.FromUtc > query.ToUtc) throw new CaptureValidationException("fromUtc must not be after toUtc.");
        if (query.FromUtc is not null && query.ToUtc - query.FromUtc > TimeSpan.FromDays(31))
            throw new CaptureValidationException("A session query can span at most 31 days.");
        var cursor = ParseCursor(query.Cursor, tenantId, query);
        var rows = await _store.QuerySessionsAsync(tenantId, query, cursor, query.Take + 1, cancellationToken);
        var hasMore = rows.Count > query.Take;
        var items = rows.Take(query.Take).ToList();
        return new CaptureSessionPage
        {
            Items = items,
            NextCursor = hasMore ? EncodeCursor(items[^1], tenantId, query) : null
        };
    }

    public Task<CaptureSessionMetadata?> GetAsync(
        string tenantId,
        string sessionId,
        CancellationToken cancellationToken = default) =>
        _store.GetSessionAsync(
            TopologyService.NormalizeTenantId(tenantId),
            ValidateId(sessionId, "session id"),
            cancellationToken);

    public async Task<PacketAccessGrant> CreateSessionAccessAsync(
        string tenantId,
        string sessionId,
        PacketAccessRequest request,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        sessionId = ValidateId(sessionId, "session id");
        var purpose = Required(request?.Purpose, "purpose", 500);
        var ttl = NormalizeTtl(request?.TtlSeconds);
        var session = await _store.GetSessionAsync(tenantId, sessionId, cancellationToken)
                      ?? throw new KeyNotFoundException("Capture session was not found.");
        EnsurePayloadWithinRetention(session);
        if (!session.PayloadAvailable || string.IsNullOrWhiteSpace(session.PayloadReference))
            throw new CaptureValidationException("Packet payload is not available for this session.");
        EnsureProviderAssignedToTenant(session.ProviderId, tenantId);
        var provider = _providers.GetRequired(session.ProviderId);
        RequireCapability(provider, "payload-access");
        await WriteAccessAttemptOrFailClosedAsync(
            tenantId, actor, "capture.session.access", sessionId, purpose, cancellationToken);
        ProviderAccessGrant? issued = null;
        try
        {
            issued = await provider.CreateSessionAccessAsync(new ProviderSessionAccessRequest
            {
                TenantId = tenantId,
                SessionId = sessionId,
                PayloadReference = session.PayloadReference,
                Purpose = purpose,
                Actor = actor.Actor,
                TtlSeconds = ttl
            }, cancellationToken);
            var result = NormalizeSessionGrant(issued, sessionId, ttl);
            await CommitAccessAuditOrRevokeAsync(
                provider, issued, tenantId, actor, "capture.session.access", sessionId, purpose, cancellationToken);
            return result;
        }
        catch (CaptureAuditUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            if (issued is not null) await TryRevokeAsync(provider, issued.GrantId);
            await TryAppendFailureAuditAsync(
                tenantId, actor, "capture.session.access", sessionId, purpose, "provider_unavailable");
            throw new CaptureProviderUnavailableException("The capture provider could not issue an access grant.", ex);
        }
    }

    public async Task<CaptureExportJob> CreateExportAsync(
        string tenantId,
        CreateCaptureExportRequest request,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        request ??= new CreateCaptureExportRequest();
        var sessionIds = (request.SessionIds ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => ValidateId(item, "session id")).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (sessionIds.Count == 0 || sessionIds.Count > _options.MaxExportSessions)
            throw new CaptureValidationException($"An export requires 1-{_options.MaxExportSessions} unique session ids.");
        var format = Required(request.Format, "format", 16).ToLowerInvariant();
        if (!ExportFormats.Contains(format)) throw new CaptureValidationException("Export format must be pcap or pcapng.");
        var purpose = Required(request.Purpose, "purpose", 500);
        var retentionHours = Math.Clamp(
            request.RetentionHours ?? _options.ExportRetentionHours,
            1,
            _options.MaxExportRetentionHours);
        var sessions = new List<CaptureSessionMetadata>();
        foreach (var id in sessionIds)
        {
            var session = await _store.GetSessionAsync(tenantId, id, cancellationToken)
                          ?? throw new KeyNotFoundException($"Capture session '{id}' was not found.");
            EnsurePayloadWithinRetention(session);
            if (!session.PayloadAvailable || string.IsNullOrWhiteSpace(session.PayloadReference))
                throw new CaptureValidationException($"Packet payload is unavailable for session '{id}'.");
            EnsureProviderAssignedToTenant(session.ProviderId, tenantId);
            sessions.Add(session);
        }
        var providerId = sessions[0].ProviderId;
        if (sessions.Any(item => !string.Equals(item.ProviderId, providerId, StringComparison.OrdinalIgnoreCase)))
            throw new CaptureValidationException("One export job cannot span multiple capture providers.");
        RequireCapability(_providers.GetRequired(providerId), "export");
        var now = DateTimeOffset.UtcNow;
        var job = new CaptureExportJob
        {
            JobId = Guid.NewGuid().ToString("N"),
            TenantId = tenantId,
            ProviderId = providerId,
            SessionIds = sessionIds,
            Format = format,
            Purpose = purpose,
            Status = CaptureJobStatus.Queued,
            RequestedBy = actor.Actor,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            ExpiresAtUtc = now.AddHours(retentionHours)
        };
        await _store.CreateExportJobWithAuditAsync(job, new CaptureAuditEntry
        {
            TenantId = tenantId,
            TimestampUtc = now,
            Actor = actor.Actor,
            Action = "capture.export.create",
            Target = job.JobId,
            Result = "success",
            DetailCode = $"sessions:{sessionIds.Count}",
            Purpose = purpose,
            SourceIp = actor.SourceIp
        }, cancellationToken);
        return job;
    }

    public async Task<PacketAccessGrant> CreateTlsArtifactAccessAsync(
        string tenantId,
        string sessionId,
        PacketAccessRequest request,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        sessionId = ValidateId(sessionId, "session id");
        var purpose = Required(request?.Purpose, "purpose", 500);
        var ttl = NormalizeTtl(request?.TtlSeconds);
        var session = await GetTlsArtifactSessionAsync(tenantId, sessionId, cancellationToken);
        EnsureProviderAssignedToTenant(session.Tls!.DecryptedArtifactProviderId!, tenantId);
        var provider = _providers.GetRequired(session.Tls!.DecryptedArtifactProviderId!);
        RequireCapability(provider, "tls-artifact-access");
        await WriteAccessAttemptOrFailClosedAsync(
            tenantId, actor, "capture.tls-artifact.access", sessionId, purpose, cancellationToken);
        ProviderAccessGrant? issued = null;
        try
        {
            issued = await provider.CreateTlsArtifactAccessAsync(new ProviderTlsArtifactAccessRequest
            {
                TenantId = tenantId,
                SessionId = sessionId,
                ArtifactReference = session.Tls!.DecryptedArtifactReference!,
                Purpose = purpose,
                Actor = actor.Actor,
                TtlSeconds = ttl
            }, cancellationToken);
            var result = NormalizeSessionGrant(issued, sessionId, ttl);
            await CommitAccessAuditOrRevokeAsync(
                provider, issued, tenantId, actor, "capture.tls-artifact.access", sessionId, purpose, cancellationToken);
            return result;
        }
        catch (CaptureAuditUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            if (issued is not null) await TryRevokeAsync(provider, issued.GrantId);
            await TryAppendFailureAuditAsync(
                tenantId, actor, "capture.tls-artifact.access", sessionId, purpose, "provider_unavailable");
            throw new CaptureProviderUnavailableException("The TLS provider could not issue an artifact access grant.", ex);
        }
    }

    public async Task<TlsDecodedPreview> GetTlsPreviewAsync(
        string tenantId,
        string sessionId,
        PacketAccessRequest request,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        sessionId = ValidateId(sessionId, "session id");
        var purpose = Required(request?.Purpose, "purpose", 500);
        var session = await GetTlsArtifactSessionAsync(tenantId, sessionId, cancellationToken);
        EnsureProviderAssignedToTenant(session.Tls!.DecryptedArtifactProviderId!, tenantId);
        var provider = _providers.GetRequired(session.Tls!.DecryptedArtifactProviderId!);
        RequireCapability(provider, "tls-preview");
        await WriteAccessAttemptOrFailClosedAsync(
            tenantId, actor, "capture.tls-artifact.preview", sessionId, purpose, cancellationToken);
        try
        {
            var preview = await provider.GetTlsPreviewAsync(new ProviderTlsPreviewRequest
            {
                TenantId = tenantId,
                SessionId = sessionId,
                ArtifactReference = session.Tls!.DecryptedArtifactReference!,
                Purpose = purpose,
                Actor = actor.Actor,
                MaxTransactions = _options.MaxTlsPreviewTransactions
            }, cancellationToken);
            NormalizePreview(preview, session);
            try
            {
                await AuditAsync(
                    tenantId, actor, "capture.tls-artifact.preview", sessionId,
                    "success", $"transactions:{preview.Transactions.Count}", cancellationToken, purpose);
            }
            catch (Exception ex)
            {
                throw new CaptureAuditUnavailableException(
                    "The decoded preview was withheld because its audit completion could not be persisted.", ex);
            }
            return preview;
        }
        catch (CaptureAuditUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            await TryAppendFailureAuditAsync(
                tenantId, actor, "capture.tls-artifact.preview", sessionId, purpose, "provider_unavailable");
            throw new CaptureProviderUnavailableException("The TLS provider could not return a bounded decoded preview.", ex);
        }
    }

    public Task<IReadOnlyList<CaptureExportJob>> ListExportsAsync(
        string tenantId,
        int take,
        CancellationToken cancellationToken = default) =>
        _store.ListExportJobsAsync(TopologyService.NormalizeTenantId(tenantId), Math.Clamp(take, 1, 100), cancellationToken);

    public Task<CaptureExportJob?> GetExportAsync(
        string tenantId,
        string jobId,
        CancellationToken cancellationToken = default) =>
        _store.GetExportJobAsync(
            TopologyService.NormalizeTenantId(tenantId),
            ValidateId(jobId, "job id"),
            cancellationToken);

    public async Task<CaptureExportAccessGrant> CreateExportAccessAsync(
        string tenantId,
        string jobId,
        PacketAccessRequest request,
        CaptureActorContext actor,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        jobId = ValidateId(jobId, "job id");
        var purpose = Required(request?.Purpose, "purpose", 500);
        var ttl = NormalizeTtl(request?.TtlSeconds);
        var job = await _store.GetExportJobAsync(tenantId, jobId, cancellationToken)
                  ?? throw new KeyNotFoundException("Capture export job was not found.");
        if (job.Status != CaptureJobStatus.Completed || string.IsNullOrWhiteSpace(job.OutputReference))
            throw new CaptureValidationException("Capture export is not ready for access.");
        if (job.ExpiresAtUtc <= DateTimeOffset.UtcNow)
            throw new CaptureValidationException("Capture export has expired.");
        EnsureProviderAssignedToTenant(job.ProviderId, tenantId);
        var provider = _providers.GetRequired(job.ProviderId);
        RequireCapability(provider, "export");
        await WriteAccessAttemptOrFailClosedAsync(
            tenantId, actor, "capture.export.access", jobId, purpose, cancellationToken);
        ProviderAccessGrant? issued = null;
        try
        {
            issued = await provider.CreateExportAccessAsync(new ProviderExportAccessRequest
            {
                TenantId = tenantId,
                JobId = jobId,
                OutputReference = job.OutputReference,
                Purpose = purpose,
                Actor = actor.Actor,
                TtlSeconds = ttl
            }, cancellationToken);
            var (grantId, uri) = NormalizeProviderGrant(issued, ttl);
            await CommitAccessAuditOrRevokeAsync(
                provider, issued, tenantId, actor, "capture.export.access", jobId, purpose, cancellationToken);
            return new CaptureExportAccessGrant
            {
                GrantId = grantId,
                JobId = jobId,
                AccessUrl = uri,
                ExpiresAtUtc = issued.ExpiresAtUtc
            };
        }
        catch (CaptureAuditUnavailableException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            if (issued is not null) await TryRevokeAsync(provider, issued.GrantId);
            await TryAppendFailureAuditAsync(
                tenantId, actor, "capture.export.access", jobId, purpose, "provider_unavailable");
            throw new CaptureProviderUnavailableException("The capture provider could not issue an export access grant.", ex);
        }
    }

    public async Task<IReadOnlyList<CaptureAiEvidenceReference>> BuildAiEvidenceReferencesAsync(
        string tenantId,
        IEnumerable<string> sessionIds,
        CancellationToken cancellationToken = default)
    {
        tenantId = TopologyService.NormalizeTenantId(tenantId);
        var ids = sessionIds.Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToList();
        var results = new List<CaptureAiEvidenceReference>();
        foreach (var id in ids)
        {
            var session = await _store.GetSessionAsync(tenantId, ValidateId(id, "session id"), cancellationToken);
            if (session is null) continue;
            results.Add(new CaptureAiEvidenceReference
            {
                SessionId = session.SessionId,
                ProviderId = session.ProviderId,
                StartedAtUtc = session.StartedAtUtc,
                Flow = $"{session.SourceIp}:{session.SourcePort?.ToString() ?? "-"}->{session.DestinationIp}:{session.DestinationPort?.ToString() ?? "-"}",
                Protocol = session.Protocol,
                ByteCount = session.ByteCount,
                PayloadAvailable = session.PayloadAvailable,
                PayloadSha256 = session.PayloadSha256,
                StorageTier = session.StorageTier,
                TlsServerName = session.Tls?.ServerName,
                TlsFingerprint = session.Tls?.Ja4 ?? session.Tls?.Ja3 ?? session.Tls?.CertificateSha256
            });
        }
        return results;
    }

    public Task<IReadOnlyList<CaptureAuditEntry>> ListAuditAsync(
        string tenantId,
        int take,
        CancellationToken cancellationToken = default) =>
        _store.ListAuditAsync(
            TopologyService.NormalizeTenantId(tenantId),
            Math.Clamp(take, 1, _options.MaxAuditEntriesPerQuery),
            cancellationToken);

    internal static string ValidateId(string value, string field)
    {
        value = value?.Trim() ?? "";
        if (!IdPattern.IsMatch(value)) throw new CaptureValidationException($"Invalid {field}.");
        return value;
    }

    internal static string Required(string? value, string field, int max)
    {
        var text = value?.Trim();
        if (string.IsNullOrWhiteSpace(text) || text.Length > max)
            throw new CaptureValidationException($"{field} is required and must be at most {max} characters.");
        return text;
    }

    private static string? Optional(string? value, int max)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text)) return null;
        if (text.Length > max) throw new CaptureValidationException($"Text must be at most {max} characters.");
        return text;
    }

    private static string? OptionalId(string? value, string field) =>
        string.IsNullOrWhiteSpace(value) ? null : ValidateId(value, field);

    private static string ValidateAddress(string value, string field)
    {
        if (!IPAddress.TryParse(value, out var address)) throw new CaptureValidationException($"Invalid {field}.");
        return address.ToString();
    }

    private static int? ValidatePort(int? port)
    {
        if (port is < 1 or > 65535) throw new CaptureValidationException("Port must be between 1 and 65,535.");
        return port;
    }

    private TlsSessionMetadata? NormalizeTls(TlsSessionMetadata? input)
    {
        if (input is null) return null;
        input.Version = Optional(input.Version, 32);
        input.ServerName = Optional(input.ServerName, 253);
        input.Alpn = Optional(input.Alpn, 64);
        input.Cipher = Optional(input.Cipher, 128);
        input.Ja3 = Optional(input.Ja3, 128);
        input.Ja4 = Optional(input.Ja4, 128);
        input.CertificateSha256 = Optional(input.CertificateSha256, 64);
        input.CertificateIssuer = Optional(input.CertificateIssuer, 500);
        input.CertificateSubject = Optional(input.CertificateSubject, 500);
        input.DecryptedArtifactSha256 = Optional(input.DecryptedArtifactSha256, 64)?.ToLowerInvariant();
        input.DecryptedArtifactProviderId = OptionalId(
            input.DecryptedArtifactProviderId, "decrypted artifact provider id");
        if (input.DecryptedArtifactProviderId is not null) _ = _providers.GetRequired(input.DecryptedArtifactProviderId);
        input.DecryptedArtifactKeyVersion = OptionalId(
            input.DecryptedArtifactKeyVersion, "decrypted artifact key version");
        input.DecryptedArtifactStoragePoolId = OptionalId(
            input.DecryptedArtifactStoragePoolId, "decrypted artifact storage pool id");
        input.DecryptionState = Required(input.DecryptionState, "TLS decryption state", 64).ToLowerInvariant();
        if (!DecryptionStates.Contains(input.DecryptionState))
            throw new CaptureValidationException("Unknown TLS decryption state.");
        return input;
    }

    private async Task<CaptureSessionMetadata> GetTlsArtifactSessionAsync(
        string tenantId,
        string sessionId,
        CancellationToken cancellationToken)
    {
        var session = await _store.GetSessionAsync(tenantId, sessionId, cancellationToken)
                      ?? throw new KeyNotFoundException("Capture session was not found.");
        EnsurePayloadWithinRetention(session);
        if (session.Tls?.DecryptedArtifactAvailable != true ||
            string.IsNullOrWhiteSpace(session.Tls.DecryptedArtifactReference))
            throw new CaptureValidationException("A provider-owned decrypted TLS artifact is not available for this session.");
        return session;
    }

    internal static void EnsurePayloadWithinRetention(
        CaptureSessionMetadata session,
        DateTimeOffset? nowUtc = null)
    {
        if (session.RetainUntilUtc is null ||
            session.RetainUntilUtc.Value <= (nowUtc ?? DateTimeOffset.UtcNow))
            throw new CaptureValidationException(
                "Packet or decrypted payload retention has expired for this session.");
    }

    private void EnsureProviderAssignedToTenant(string providerId, string tenantId)
    {
        var configured = _options.Providers.FirstOrDefault(item =>
            item.Enabled && string.Equals(item.Id, providerId, StringComparison.OrdinalIgnoreCase));
        if (configured is null || !configured.TenantIds.Contains(tenantId, StringComparer.OrdinalIgnoreCase))
            throw new CaptureValidationException(
                $"Provider '{providerId}' is not assigned to tenant '{tenantId}'.");
    }

    private void NormalizePreview(TlsDecodedPreview preview, CaptureSessionMetadata session)
    {
        if (preview is null || !string.Equals(preview.SessionId, session.SessionId, StringComparison.Ordinal) ||
            !string.Equals(preview.ArtifactSha256, session.Tls?.DecryptedArtifactSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("TLS provider returned preview metadata for a different artifact.");
        preview.ArtifactSha256 = preview.ArtifactSha256.ToLowerInvariant();
        preview.Transactions ??= [];
        if (preview.Transactions.Count > _options.MaxTlsPreviewTransactions)
            throw new InvalidDataException("TLS provider preview exceeded the configured transaction limit.");
        foreach (var transaction in preview.Transactions)
        {
            transaction.Protocol = CleanPreviewText(transaction.Protocol, 24, required: true)!;
            transaction.Method = CleanPreviewText(transaction.Method, 24);
            transaction.Authority = CleanPreviewText(transaction.Authority, 253);
            if (transaction.Authority?.Contains('@') == true)
                throw new InvalidDataException("TLS preview authority must not contain user information.");
            transaction.PathTemplate = CleanPreviewText(transaction.PathTemplate, 512);
            if (transaction.PathTemplate?.Contains('?') == true || transaction.PathTemplate?.Contains('#') == true)
                throw new InvalidDataException("TLS preview path must be a provider-redacted template without query or fragment.");
            if (transaction.StatusCode is < 100 or > 599)
                throw new InvalidDataException("TLS preview contains an invalid response status.");
            transaction.RequestContentType = CleanPreviewText(transaction.RequestContentType, 128);
            transaction.ResponseContentType = CleanPreviewText(transaction.ResponseContentType, 128);
            if (transaction.RequestBodyBytes < 0 || transaction.ResponseBodyBytes < 0)
                throw new InvalidDataException("TLS preview body-size counters cannot be negative.");
            transaction.RequestHeaderNames = NormalizeHeaderNames(transaction.RequestHeaderNames);
            transaction.ResponseHeaderNames = NormalizeHeaderNames(transaction.ResponseHeaderNames);
        }
    }

    private static string? CleanPreviewText(string? value, int max, bool required = false)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            if (required) throw new InvalidDataException("TLS preview is missing a required value.");
            return null;
        }
        if (text.Length > max || text.Any(char.IsControl))
            throw new InvalidDataException("TLS preview contains an invalid or oversized value.");
        return text;
    }

    private static List<string> NormalizeHeaderNames(IEnumerable<string>? names)
    {
        var result = (names ?? []).Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (result.Count > 32 || result.Any(item => !HeaderNamePattern.IsMatch(item)))
            throw new InvalidDataException("TLS preview header-name list is invalid or oversized.");
        return result;
    }

    private int NormalizeTtl(int? requested) => Math.Clamp(
        requested ?? _options.AccessGrantTtlSeconds,
        30,
        _options.MaxAccessGrantTtlSeconds);

    private static void RequireCapability(ICaptureProviderAdapter provider, string capability)
    {
        if (!provider.Capabilities.Contains(capability))
            throw new CaptureValidationException($"Provider '{provider.ProviderId}' does not support {capability}.");
    }

    private static PacketAccessGrant NormalizeSessionGrant(ProviderAccessGrant grant, string sessionId, int ttl)
    {
        var (grantId, uri) = NormalizeProviderGrant(grant, ttl);
        return new PacketAccessGrant
        {
            GrantId = grantId,
            SessionId = sessionId,
            AccessUrl = uri,
            ExpiresAtUtc = grant.ExpiresAtUtc
        };
    }

    private static (string GrantId, Uri AccessUrl) NormalizeProviderGrant(
        ProviderAccessGrant grant,
        int ttl)
    {
        if (grant is null || string.IsNullOrWhiteSpace(grant.GrantId) || !IdPattern.IsMatch(grant.GrantId))
            throw new InvalidDataException("Capture provider returned an invalid access-grant id.");
        return (grant.GrantId, ValidateGrant(grant, ttl));
    }

    private static Uri ValidateGrant(ProviderAccessGrant grant, int ttl)
    {
        if (!Uri.TryCreate(grant.AccessUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip))))
            throw new InvalidDataException("Capture provider returned an unsafe access URL.");
        var now = DateTimeOffset.UtcNow;
        if (grant.ExpiresAtUtc <= now || grant.ExpiresAtUtc > now.AddSeconds(ttl + 60))
            throw new InvalidDataException("Capture provider returned an invalid access-grant lifetime.");
        return uri;
    }

    private CaptureSessionCursor? ParseCursor(string? value, string tenantId, CaptureSessionQuery query)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Length > 4096) throw new CaptureValidationException("Invalid session cursor.");
        try
        {
            var model = JsonSerializer.Deserialize<CursorModel>(_cursorProtector.Unprotect(value));
            if (model is null || model.StartedAtUtc == default || !model.Matches(tenantId, query))
                throw new FormatException();
            return new CaptureSessionCursor(model.StartedAtUtc, ValidateId(model.SessionId, "cursor session id"));
        }
        catch (Exception ex) when (ex is FormatException or JsonException or CaptureValidationException or CryptographicException)
        {
            throw new CaptureValidationException("Invalid session cursor.");
        }
    }

    private string EncodeCursor(CaptureSessionMetadata session, string tenantId, CaptureSessionQuery query) =>
        _cursorProtector.Protect(JsonSerializer.Serialize(new CursorModel
        {
            StartedAtUtc = session.StartedAtUtc,
            SessionId = session.SessionId,
            TenantId = tenantId,
            CampaignId = query.CampaignId,
            EdgeId = query.EdgeId,
            FromUtc = query.FromUtc,
            ToUtc = query.ToUtc,
            Address = query.Address,
            Port = query.Port,
            Protocol = query.Protocol,
            PayloadAvailable = query.PayloadAvailable,
            ProviderId = query.ProviderId
        }));

    private Task AuditAsync(
        string tenantId,
        CaptureActorContext actor,
        string action,
        string target,
        string result,
        string? detailCode,
        CancellationToken cancellationToken,
        string? purpose = null) =>
        _store.AppendAuditAsync(new CaptureAuditEntry
        {
            TenantId = tenantId,
            TimestampUtc = DateTimeOffset.UtcNow,
            Actor = actor.Actor,
            Action = action,
            Target = target,
            Result = result,
            DetailCode = detailCode,
            Purpose = purpose,
            SourceIp = actor.SourceIp
        }, cancellationToken);

    private async Task WriteAccessAttemptOrFailClosedAsync(
        string tenantId,
        CaptureActorContext actor,
        string action,
        string target,
        string purpose,
        CancellationToken cancellationToken)
    {
        try
        {
            await AuditAsync(
                tenantId, actor, action, target, "attempt", "purpose_validated", cancellationToken, purpose);
        }
        catch (Exception ex)
        {
            throw new CaptureAuditUnavailableException(
                "Forensic access was denied because its audit attempt could not be persisted.", ex);
        }
    }

    private async Task CommitAccessAuditOrRevokeAsync(
        ICaptureProviderAdapter provider,
        ProviderAccessGrant grant,
        string tenantId,
        CaptureActorContext actor,
        string action,
        string target,
        string purpose,
        CancellationToken cancellationToken)
    {
        try
        {
            await AuditAsync(
                tenantId, actor, action, target, "success", "time_limited_grant", cancellationToken, purpose);
        }
        catch (Exception ex)
        {
            await TryRevokeAsync(provider, grant.GrantId);
            throw new CaptureAuditUnavailableException(
                "The provider grant was revoked because its audit completion could not be persisted.", ex);
        }
    }

    private async Task TryAppendFailureAuditAsync(
        string tenantId,
        CaptureActorContext actor,
        string action,
        string target,
        string purpose,
        string detailCode)
    {
        try
        {
            await AuditAsync(
                tenantId, actor, action, target, "fail", detailCode, CancellationToken.None, purpose);
        }
        catch (Exception ex)
        {
            // The immutable attempt was already persisted before provider access.
            _logger.LogError(ex, "Could not append capture access failure audit target={Target}", target);
        }
    }

    private async Task TryRevokeAsync(ICaptureProviderAdapter provider, string grantId)
    {
        try
        {
            await provider.RevokeAccessGrantAsync(grantId, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Capture access grant revocation failed provider={Provider} grant={Grant}",
                provider.ProviderId, grantId);
        }
    }

    private sealed class CursorModel
    {
        public DateTimeOffset StartedAtUtc { get; set; }
        public string SessionId { get; set; } = "";
        public string TenantId { get; set; } = "";
        public string? CampaignId { get; set; }
        public string? EdgeId { get; set; }
        public DateTimeOffset? FromUtc { get; set; }
        public DateTimeOffset? ToUtc { get; set; }
        public string? Address { get; set; }
        public int? Port { get; set; }
        public string? Protocol { get; set; }
        public bool? PayloadAvailable { get; set; }
        public string? ProviderId { get; set; }

        public bool Matches(string tenantId, CaptureSessionQuery query) =>
            string.Equals(TenantId, tenantId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(CampaignId, query.CampaignId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(EdgeId, query.EdgeId, StringComparison.OrdinalIgnoreCase) &&
            FromUtc?.ToUniversalTime() == query.FromUtc?.ToUniversalTime() &&
            ToUtc?.ToUniversalTime() == query.ToUtc?.ToUniversalTime() &&
            string.Equals(Address, query.Address, StringComparison.OrdinalIgnoreCase) &&
            Port == query.Port &&
            string.Equals(Protocol, query.Protocol, StringComparison.OrdinalIgnoreCase) &&
            PayloadAvailable == query.PayloadAvailable &&
            string.Equals(ProviderId, query.ProviderId, StringComparison.OrdinalIgnoreCase);
    }
}
