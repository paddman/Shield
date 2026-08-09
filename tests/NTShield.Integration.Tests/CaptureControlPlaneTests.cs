using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Capture;
using NTShield.Server.Security;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class CaptureControlPlaneTests
{
    [Fact]
    public async Task Policies_Are_Tenant_Isolated_And_Concurrent_Updates_Use_Optimistic_Concurrency()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            var alpha = await fixture.Policies.CreateAsync(
                "alpha", ValidPolicy("shared-policy", "Alpha"), Actor(), CancellationToken.None);
            var beta = await fixture.Policies.CreateAsync(
                "beta", ValidPolicy("shared-policy", "Beta"), Actor(), CancellationToken.None);

            Assert.Equal("alpha", alpha.TenantId);
            Assert.Equal("beta", beta.TenantId);
            Assert.Equal("Alpha", (await fixture.Policies.GetAsync("alpha", "shared-policy"))?.Name);
            Assert.Equal("Beta", (await fixture.Policies.GetAsync("beta", "shared-policy"))?.Name);

            var first = ValidPolicy(alpha.PolicyId, "First editor");
            var second = ValidPolicy(alpha.PolicyId, "Second editor");
            var results = await Task.WhenAll(
                CaptureUpdateAsync(fixture.Policies, first, alpha.Version),
                CaptureUpdateAsync(fixture.Policies, second, alpha.Version));
            var winner = Assert.Single(results, item => item.Policy is not null);
            var loser = Assert.Single(results, item => item.Error is not null);
            var conflict = Assert.IsType<CaptureVersionConflictException>(loser.Error);
            Assert.Equal(2, conflict.CurrentVersion);
            var stored = await fixture.Policies.GetAsync("alpha", alpha.PolicyId);
            Assert.Equal(2, stored?.Version);
            Assert.Equal(winner.Policy?.Name, stored?.Name);
            Assert.Equal("Beta", (await fixture.Policies.GetAsync("beta", "shared-policy"))?.Name);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Capacity_Admission_Rejects_Oversubscription_And_Inline_Tls_Must_Remain_Fail_Open()
    {
        var fixture = await CreateFixtureAsync(capacityBytes: 128 * 1024 * 1024, maxIngressMbps: 100m);
        try
        {
            var oversized = ValidPolicy("oversized", "Oversized");
            oversized.Enabled = true;
            oversized.Mode = CaptureMode.FullPackets;
            oversized.EstimatedIngressMbps = 500m;
            oversized.RetentionDays = 30;
            oversized.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 7, ColdDays = 23 };
            var simulation = await fixture.Policies.SimulateAsync("alpha", oversized);
            Assert.False(simulation.Admitted);
            Assert.Contains("provider_ingress_capacity_exceeded", simulation.Reasons);
            Assert.Contains("tenant_retention_capacity_exceeded", simulation.Reasons);
            var rejected = await Assert.ThrowsAsync<CaptureCapacityRejectedException>(() =>
                fixture.Policies.CreateAsync("alpha", oversized, Actor()));
            Assert.False(rejected.Result.Admitted);

            var unsafeTls = ValidPolicy("unsafe-tls", "Unsafe TLS");
            unsafeTls.Tls = new TlsInspectionPolicy
            {
                Mode = TlsInspectionMode.ExternalProxy,
                ProviderId = "provider-1",
                FailOpen = false
            };
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("alpha", unsafeTls));

            unsafeTls.Tls.FailOpen = true;
            unsafeTls.Tls.AttemptQuicTcpFallback = false;
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("alpha", unsafeTls));

            unsafeTls.Tls.AttemptQuicTcpFallback = true;
            unsafeTls.Tls.RetainDecryptedArtifactsInProvider = true;
            Assert.True((await fixture.Policies.SimulateAsync("alpha", unsafeTls)).Admitted);
            var providerJson = JsonSerializer.Serialize(
                unsafeTls,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.Contains("\"attemptQuicTcpFallback\":true", providerJson, StringComparison.Ordinal);

            var splitProvider = ValidPolicy("split-provider", "Split provider");
            splitProvider.Tls = new TlsInspectionPolicy
            {
                Mode = TlsInspectionMode.ExternalProxy,
                ProviderId = "provider-2",
                FailOpen = true,
                AttemptQuicTcpFallback = true
            };
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("beta", splitProvider));

            await fixture.Store.UpsertProviderHealthAsync(new CaptureProviderHealth
            {
                ProviderId = "provider-1",
                Kind = "test",
                State = CaptureProviderState.Degraded,
                CheckedAtUtc = DateTimeOffset.UtcNow,
                CapacityBytes = 128 * 1024 * 1024,
                MaxSustainableIngressMbps = 100m,
                StoragePressure = CaptureStoragePressureState.Critical,
                StorageCriticalMetadataOnly = true,
                FailOpen = true
            });
            var packetPolicy = ValidPolicy("storage-critical", "Storage critical");
            packetPolicy.Enabled = true;
            packetPolicy.Mode = CaptureMode.SelectivePackets;
            var storageAdmission = await fixture.Policies.SimulateAsync("alpha", packetPolicy);
            Assert.False(storageAdmission.Admitted);
            Assert.Contains(CaptureGapReasonCodes.StorageCriticalMetadataOnly, storageAdmission.Reasons);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task One_Gigabit_Ninety_Day_Plan_Uses_Exact_Raw_Capacity_And_Cannot_Bypass_Admission()
    {
        var fixture = await CreateFixtureAsync(
            capacityBytes: 1_000_000_000_000_000L,
            maxIngressMbps: 10_000m);
        try
        {
            var policy = ValidPolicy("one-gigabit", "One gigabit for 90 days");
            policy.Enabled = true;
            policy.Mode = CaptureMode.FullPackets;
            policy.EstimatedIngressMbps = 1_000m;
            policy.RetentionDays = 90;
            policy.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 7, ColdDays = 83 };

            var simulation = await fixture.Policies.SimulateAsync("alpha", policy);
            Assert.Equal(972_000_000_000_000L, simulation.ProjectedRetainedBytes);
            Assert.False(simulation.Admitted);
            Assert.Contains("provider_retention_capacity_exceeded", simulation.Reasons);
            Assert.Contains("tenant_retention_capacity_exceeded", simulation.Reasons);

            policy.EstimatedIngressMbps = 0m;
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("alpha", policy));

            policy.EstimatedIngressMbps = 1_000m;
            policy.RetentionDays = 91;
            policy.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 7, ColdDays = 84 };
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("alpha", policy));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Packet_Admission_Fails_When_Provider_Capacity_Is_Unknown()
    {
        var fixture = await CreateFixtureAsync(capacityBytes: 0, maxIngressMbps: 0m);
        try
        {
            var policy = ValidPolicy("unknown-capacity", "Unknown capacity");
            policy.Enabled = true;
            policy.Mode = CaptureMode.SelectivePackets;
            policy.EstimatedIngressMbps = 10m;

            var simulation = await fixture.Policies.SimulateAsync("alpha", policy);
            Assert.False(simulation.Admitted);
            Assert.Contains("provider_retention_capacity_unknown", simulation.Reasons);
            Assert.Contains("tenant_retention_capacity_unknown", simulation.Reasons);
            Assert.Contains("provider_ingress_capacity_unknown", simulation.Reasons);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Provider_Assignment_And_Capacity_Are_Enforced_Across_Tenants()
    {
        var fixture = await CreateFixtureAsync(
            capacityBytes: 500L * 1024 * 1024 * 1024,
            maxIngressMbps: 10_000m);
        try
        {
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Policies.SimulateAsync("gamma", ValidPolicy("wrong-tenant", "Wrong tenant")));

            static CapturePolicy PacketPolicy(string id, string name)
            {
                var policy = ValidPolicy(id, name);
                policy.Enabled = true;
                policy.Mode = CaptureMode.SelectivePackets;
                policy.EstimatedIngressMbps = 30m;
                policy.RetentionDays = 1;
                policy.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 1, ColdDays = 0 };
                return policy;
            }

            var alpha = await fixture.Policies.CreateAsync(
                "alpha", PacketPolicy("alpha-capacity", "Alpha capacity"), Actor());
            Assert.True(alpha.Enabled);

            var rejected = await Assert.ThrowsAsync<CaptureCapacityRejectedException>(() =>
                fixture.Policies.CreateAsync(
                    "beta", PacketPolicy("beta-capacity", "Beta capacity"), Actor()));
            Assert.Contains("provider_retention_capacity_exceeded", rejected.Result.Reasons);
            Assert.True(rejected.Result.ProviderProjectedRetainedBytes >
                        rejected.Result.TenantProjectedRetainedBytes);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Session_Query_Is_Bounded_Tenant_Scoped_And_Raw_Provider_References_Are_Not_Serialized()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            var policy = ValidPolicy("retention", "Retention");
            policy.Enabled = true;
            policy.RetentionDays = 2;
            policy.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 2, ColdDays = 0 };
            await fixture.Policies.CreateAsync("alpha", policy, Actor());
            var now = DateTimeOffset.UtcNow.AddMinutes(-10);
            for (var index = 0; index < 3; index++)
            {
                await fixture.Sessions.IngestProviderSessionAsync("provider-1", ProviderSession(
                    "alpha", $"alpha-{index}", now.AddMinutes(index), $"opaque-alpha-{index}"));
            }
            await fixture.Sessions.IngestProviderSessionAsync(
                "provider-1", ProviderSession("beta", "beta-0", now, "opaque-beta"));

            var first = await fixture.Sessions.QueryAsync("alpha", new CaptureSessionQuery { Take = 2 });
            Assert.Equal(2, first.Items.Count);
            Assert.NotNull(first.NextCursor);
            Assert.All(first.Items, item => Assert.Equal("alpha", item.TenantId));
            var second = await fixture.Sessions.QueryAsync("alpha", new CaptureSessionQuery
            {
                Take = 2,
                Cursor = first.NextCursor
            });
            Assert.Single(second.Items);
            Assert.DoesNotContain(second.Items[0].SessionId, first.Items.Select(item => item.SessionId));
            await Assert.ThrowsAsync<CaptureValidationException>(() => fixture.Sessions.QueryAsync(
                "beta", new CaptureSessionQuery { Take = 2, Cursor = first.NextCursor }));
            await Assert.ThrowsAsync<CaptureValidationException>(() => fixture.Sessions.QueryAsync(
                "alpha", new CaptureSessionQuery
                {
                    Take = 2,
                    Cursor = first.NextCursor,
                    Protocol = "udp"
                }));
            var tampered = first.NextCursor![..^1] + (first.NextCursor[^1] == 'A' ? 'B' : 'A');
            await Assert.ThrowsAsync<CaptureValidationException>(() => fixture.Sessions.QueryAsync(
                "alpha", new CaptureSessionQuery { Take = 2, Cursor = tampered }));
            Assert.Null(await fixture.Sessions.GetAsync("beta", "alpha-0"));

            var stored = await fixture.Sessions.GetAsync("alpha", "alpha-0");
            Assert.NotNull(stored);
            Assert.True(stored!.RetainUntilUtc <= stored.StartedAtUtc.AddDays(2).AddSeconds(1));
            var json = JsonSerializer.Serialize(stored);
            Assert.DoesNotContain("opaque-alpha", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("payloadReference", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("opaque-tls", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("decryptedArtifactReference", json, StringComparison.OrdinalIgnoreCase);
            var originalReference = stored.PayloadReference;
            stored.ProviderId = "different-provider";
            stored.PayloadReference = "cross-provider-replacement";
            Assert.False(await fixture.Store.UpsertSessionAsync(stored));
            Assert.Equal(originalReference, (await fixture.Sessions.GetAsync("alpha", "alpha-0"))?.PayloadReference);

            var evidence = await fixture.Sessions.BuildAiEvidenceReferencesAsync(
                "alpha", ["alpha-0", "alpha-1"]);
            var evidenceJson = JsonSerializer.Serialize(evidence);
            Assert.Equal(2, evidence.Count);
            Assert.DoesNotContain("opaque-alpha", evidenceJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("accessUrl", evidenceJson, StringComparison.OrdinalIgnoreCase);

            var byCorrelation = await fixture.Sessions.QueryAsync("alpha", new CaptureSessionQuery
            {
                CampaignId = "campaign-1",
                EdgeId = "edge-1",
                FromUtc = now.AddMinutes(-1),
                ToUtc = now.AddMinutes(5),
                Take = 10
            });
            Assert.Equal(3, byCorrelation.Items.Count);

            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.IngestProviderSessionAsync(
                    "provider-1", ProviderSession("gamma", "gamma-0", now, "opaque-gamma")));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task V2_Access_And_Policy_Mutations_Require_Interactive_Roles()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy(CaptureAuthorizationPolicies.PacketAccess, policy =>
                policy.RequireRole(DashboardRoles.SocOperator, DashboardRoles.SocAdmin))
            .AddPolicy(CaptureAuthorizationPolicies.Administration, policy =>
                policy.RequireRole(DashboardRoles.SocAdmin));
        builder.Services.AddCaptureControlPlane(builder.Configuration);
        var app = builder.Build();
        app.MapCaptureControlPlane();

        try
        {
            var routeEndpoints = ((IEndpointRouteBuilder)app).DataSources
                .SelectMany(source => source.Endpoints)
                .OfType<RouteEndpoint>()
                .ToList();
            var access = Find(routeEndpoints, "/api/v2/packet-sessions/{id}/access", HttpMethods.Post);
            var nestedExport = Find(routeEndpoints, "/api/v2/packet-sessions/{id}/exports", HttpMethods.Post);
            var tlsPreview = Find(routeEndpoints, "/api/v2/packet-sessions/{id}/tls-preview", HttpMethods.Post);
            var policyCreate = Find(routeEndpoints, "/api/v2/capture-policies", HttpMethods.Post);
            Assert.NotNull(Find(routeEndpoints, "/api/v2/packet-sessions", HttpMethods.Get));
            Assert.NotNull(Find(routeEndpoints, "/api/v2/capture-health", HttpMethods.Get));
            Assert.Contains(access.Metadata.GetOrderedMetadata<IAuthorizeData>(), item =>
                item.Policy == CaptureAuthorizationPolicies.PacketAccess);
            Assert.Contains(nestedExport.Metadata.GetOrderedMetadata<IAuthorizeData>(), item =>
                item.Policy == CaptureAuthorizationPolicies.PacketAccess);
            Assert.Contains(tlsPreview.Metadata.GetOrderedMetadata<IAuthorizeData>(), item =>
                item.Policy == CaptureAuthorizationPolicies.PacketAccess);
            Assert.Contains(policyCreate.Metadata.GetOrderedMetadata<IAuthorizeData>(), item =>
                item.Policy == CaptureAuthorizationPolicies.Administration);

            var authorization = app.Services.GetRequiredService<IAuthorizationService>();
            Assert.False((await authorization.AuthorizeAsync(
                Principal(DashboardRoles.Executive), null, CaptureAuthorizationPolicies.PacketAccess)).Succeeded);
            Assert.False((await authorization.AuthorizeAsync(
                Principal("agent"), null, CaptureAuthorizationPolicies.PacketAccess)).Succeeded);
            Assert.True((await authorization.AuthorizeAsync(
                Principal(DashboardRoles.SocOperator), null, CaptureAuthorizationPolicies.PacketAccess)).Succeeded);
            Assert.False((await authorization.AuthorizeAsync(
                Principal(DashboardRoles.SocOperator), null, CaptureAuthorizationPolicies.Administration)).Succeeded);
            Assert.True((await authorization.AuthorizeAsync(
                Principal(DashboardRoles.SocAdmin), null, CaptureAuthorizationPolicies.Administration)).Succeeded);
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task Packet_Access_And_Export_Are_Purpose_Bound_And_Audited_Without_Urls()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            await fixture.Sessions.IngestProviderSessionAsync(
                "provider-1",
                ProviderSession("alpha", "session-1", DateTimeOffset.UtcNow.AddMinutes(-1), "opaque-handle"));
            var grant = await fixture.Sessions.CreateSessionAccessAsync(
                "alpha",
                "session-1",
                new PacketAccessRequest { Purpose = "Incident IR-42 evidence review", TtlSeconds = 120 },
                Actor());
            Assert.Equal("session-1", grant.SessionId);
            Assert.Equal(Uri.UriSchemeHttps, grant.AccessUrl.Scheme);
            Assert.True(fixture.Provider.AttemptObservedBeforeGrant);
            Assert.Equal("opaque-handle", fixture.Provider.LastPayloadReference);
            Assert.Equal(1, fixture.Provider.SessionAccessCalls);
            await Assert.ThrowsAsync<KeyNotFoundException>(() => fixture.Sessions.CreateSessionAccessAsync(
                "beta", "session-1", new PacketAccessRequest { Purpose = "Cross tenant attempt" }, Actor()));
            Assert.Equal(1, fixture.Provider.SessionAccessCalls);

            var tlsGrant = await fixture.Sessions.CreateTlsArtifactAccessAsync(
                "alpha",
                "session-1",
                new PacketAccessRequest { Purpose = "Review provider-owned TLS evidence", TtlSeconds = 120 },
                Actor());
            Assert.Equal("session-1", tlsGrant.SessionId);
            var preview = await fixture.Sessions.GetTlsPreviewAsync(
                "alpha",
                "session-1",
                new PacketAccessRequest { Purpose = "Review normalized TLS transaction metadata" },
                Actor());
            Assert.Single(preview.Transactions);
            var previewJson = JsonSerializer.Serialize(preview);
            Assert.DoesNotContain("opaque-tls", previewJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Authorization", previewJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("bodyContent", previewJson, StringComparison.OrdinalIgnoreCase);

            var job = await fixture.Sessions.CreateExportAsync("alpha", new CreateCaptureExportRequest
            {
                SessionIds = ["session-1", "session-1"],
                Format = "pcap",
                Purpose = "Preserve IR-42 evidence"
            }, Actor());
            Assert.Equal(CaptureJobStatus.Queued, job.Status);
            Assert.Single(job.SessionIds);

            var audit = await fixture.Sessions.ListAuditAsync("alpha", 20);
            Assert.Contains(audit, entry => entry.Action == "capture.session.access" && entry.Result == "success");
            Assert.Contains(audit, entry => entry.Action == "capture.session.access" &&
                                            entry.Purpose == "Incident IR-42 evidence review");
            Assert.Contains(audit, entry => entry.Action == "capture.export.create" && entry.Result == "success");
            var auditJson = JsonSerializer.Serialize(audit);
            Assert.DoesNotContain("download.example", auditJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("opaque-handle", auditJson, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Access_Grant_Is_Revoked_And_Not_Returned_When_Completion_Audit_Fails()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            await fixture.Sessions.IngestProviderSessionAsync(
                "provider-1",
                ProviderSession("alpha", "session-audit-fail", DateTimeOffset.UtcNow.AddMinutes(-1), "opaque-audit"));
            fixture.Provider.FailCompletionAudit = true;

            await Assert.ThrowsAsync<CaptureAuditUnavailableException>(() =>
                fixture.Sessions.CreateSessionAccessAsync(
                    "alpha",
                    "session-audit-fail",
                    new PacketAccessRequest { Purpose = "Verify fail-closed grant audit" },
                    Actor()));
            Assert.True(fixture.Provider.AttemptObservedBeforeGrant);
            Assert.Equal(1, fixture.Provider.RevokeCalls);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Invalid_Provider_Grant_Is_Revoked_Before_Any_Success_Audit()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            await fixture.Sessions.IngestProviderSessionAsync(
                "provider-1",
                ProviderSession("alpha", "invalid-grant", DateTimeOffset.UtcNow.AddMinutes(-1), "opaque-invalid"));
            fixture.Provider.ReturnInvalidSessionGrantId = true;

            await Assert.ThrowsAsync<CaptureProviderUnavailableException>(() =>
                fixture.Sessions.CreateSessionAccessAsync(
                    "alpha",
                    "invalid-grant",
                    new PacketAccessRequest { Purpose = "Validate an untrusted provider grant" },
                    Actor()));

            Assert.Equal(1, fixture.Provider.RevokeCalls);
            var audit = await fixture.Store.ListAuditAsync("alpha", 20);
            Assert.Contains(audit, entry => entry.Action == "capture.session.access" &&
                                            entry.Target == "invalid-grant" && entry.Result == "attempt");
            Assert.DoesNotContain(audit, entry => entry.Action == "capture.session.access" &&
                                                 entry.Target == "invalid-grant" && entry.Result == "success");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Expired_Retention_Rejects_Packet_Tls_And_Export_Before_Provider_Access()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            var expired = ProviderSession(
                "alpha", "expired-session", DateTimeOffset.UtcNow.AddDays(-40), "opaque-expired");
            expired.RetainUntilUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
            await fixture.Sessions.IngestProviderSessionAsync("provider-1", expired);

            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.CreateSessionAccessAsync(
                    "alpha", "expired-session", new PacketAccessRequest { Purpose = "Expired evidence" }, Actor()));
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.CreateTlsArtifactAccessAsync(
                    "alpha", "expired-session", new PacketAccessRequest { Purpose = "Expired TLS evidence" }, Actor()));
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.GetTlsPreviewAsync(
                    "alpha", "expired-session", new PacketAccessRequest { Purpose = "Expired TLS preview" }, Actor()));
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.CreateExportAsync("alpha", new CreateCaptureExportRequest
                {
                    SessionIds = ["expired-session"],
                    Purpose = "Expired export"
                }, Actor()));

            Assert.Equal(0, fixture.Provider.SessionAccessCalls);
            Assert.Equal(0, fixture.Provider.TlsAccessCalls);
            Assert.Equal(0, fixture.Provider.TlsPreviewCalls);
            Assert.Equal(0, fixture.Provider.ExportCalls);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Default_Retention_Is_Ninety_Days_And_Separate_Provider_Artifacts_Are_Deleted()
    {
        var fixture = await CreateFixtureAsync();
        var worker = new CaptureRetentionWorker(
            fixture.Store,
            fixture.Resolver,
            fixture.WrappedOptions,
            NullLogger<CaptureRetentionWorker>.Instance);
        try
        {
            var defaultStart = DateTimeOffset.UtcNow.AddMinutes(-1);
            var defaultRetention = ProviderSession("alpha", "default-retention", defaultStart, "default-payload");
            defaultRetention.RetainUntilUtc = null;
            await fixture.Sessions.IngestProviderSessionAsync("provider-1", defaultRetention);
            var storedDefault = await fixture.Sessions.GetAsync("alpha", "default-retention");
            Assert.Equal(defaultStart.AddDays(90), storedDefault?.RetainUntilUtc);
            Assert.Equal(defaultStart.AddDays(7), storedDefault?.HotUntilUtc);

            var expired = ProviderSession(
                "beta", "cross-provider-retention", DateTimeOffset.UtcNow.AddDays(-2), "same-opaque-reference");
            expired.RetainUntilUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
            expired.TlsArtifactReference = expired.PayloadReference;
            expired.Tls!.DecryptedArtifactProviderId = "provider-2";
            await fixture.Sessions.IngestProviderSessionAsync("provider-1", expired);

            await worker.StartAsync(CancellationToken.None);
            for (var index = 0; index < 100 &&
                 await fixture.Sessions.GetAsync("beta", "cross-provider-retention") is not null; index++)
                await Task.Delay(20);
            await worker.StopAsync(CancellationToken.None);

            var secondProvider = Assert.IsType<FakeCaptureProvider>(
                fixture.Resolver.GetRequired("provider-2"));
            Assert.Contains(("beta", "same-opaque-reference"), fixture.Provider.DeletedPayloads);
            Assert.Contains(("beta", "same-opaque-reference"), secondProvider.DeletedPayloads);
            Assert.Null(await fixture.Sessions.GetAsync("beta", "cross-provider-retention"));
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Export_Create_Audit_Is_Atomic_And_Stale_Running_Lease_Is_Reclaimed()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            var now = DateTimeOffset.UtcNow;
            CaptureExportJob Job(string id) => new()
            {
                JobId = id,
                TenantId = "alpha",
                ProviderId = "provider-1",
                SessionIds = ["session-1"],
                Purpose = "lease test",
                RequestedBy = "user:test",
                Status = CaptureJobStatus.Queued,
                CreatedAtUtc = now,
                UpdatedAtUtc = now,
                ExpiresAtUtc = now.AddHours(1)
            };
            var invalidAudit = new CaptureAuditEntry
            {
                TenantId = "alpha",
                TimestampUtc = now,
                Actor = null!,
                Action = "capture.export.create",
                Target = "atomic-failure",
                Result = "success"
            };
            await Assert.ThrowsAnyAsync<Exception>(() =>
                fixture.Store.CreateExportJobWithAuditAsync(Job("atomic-failure"), invalidAudit));
            Assert.Null(await fixture.Store.GetExportJobAsync("alpha", "atomic-failure"));

            await fixture.Store.CreateExportJobWithAuditAsync(Job("lease-job"), new CaptureAuditEntry
            {
                TenantId = "alpha",
                TimestampUtc = now,
                Actor = "user:test",
                Action = "capture.export.create",
                Target = "lease-job",
                Result = "success"
            });
            var first = await fixture.Store.TryClaimNextExportJobAsync(
                "worker-one", now, now.AddSeconds(30));
            Assert.NotNull(first);
            Assert.Equal(1, first!.AttemptCount);
            Assert.Null(await fixture.Store.TryClaimNextExportJobAsync(
                "worker-two", now.AddSeconds(1), now.AddSeconds(31)));

            var reclaimed = await fixture.Store.TryClaimNextExportJobAsync(
                "worker-two", now.AddSeconds(31), now.AddSeconds(61));
            Assert.NotNull(reclaimed);
            Assert.Equal(2, reclaimed!.AttemptCount);
            first.Status = CaptureJobStatus.Completed;
            Assert.False(await fixture.Store.TryUpdateClaimedExportJobAsync(first, "worker-one"));
            reclaimed.Status = CaptureJobStatus.Failed;
            reclaimed.ErrorCode = "test_complete";
            Assert.True(await fixture.Store.TryUpdateClaimedExportJobAsync(reclaimed, "worker-two"));
            Assert.Equal(CaptureJobStatus.Failed,
                (await fixture.Store.GetExportJobAsync("alpha", "lease-job"))?.Status);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Export_Worker_Rejects_Source_That_Expires_After_Job_Creation()
    {
        var fixture = await CreateFixtureAsync();
        var worker = new CaptureExportWorker(
            fixture.Store,
            fixture.Resolver,
            fixture.WrappedOptions,
            NullLogger<CaptureExportWorker>.Instance);
        try
        {
            await fixture.Sessions.IngestProviderSessionAsync(
                "provider-1",
                ProviderSession("alpha", "expires-after-queue", DateTimeOffset.UtcNow.AddMinutes(-1), "opaque-expiring"));
            var job = await fixture.Sessions.CreateExportAsync("alpha", new CreateCaptureExportRequest
            {
                SessionIds = ["expires-after-queue"],
                Purpose = "Verify dispatch-time retention"
            }, Actor());
            var session = await fixture.Store.GetSessionAsync("alpha", "expires-after-queue");
            Assert.NotNull(session);
            session!.RetainUntilUtc = DateTimeOffset.UtcNow.AddSeconds(-1);
            Assert.True(await fixture.Store.UpsertSessionAsync(session));

            await worker.StartAsync(CancellationToken.None);
            CaptureExportJob? stored = null;
            for (var index = 0; index < 100; index++)
            {
                stored = await fixture.Store.GetExportJobAsync("alpha", job.JobId);
                if (stored?.AttemptCount > 0 && stored.Status != CaptureJobStatus.Running) break;
                await Task.Delay(20);
            }
            await worker.StopAsync(CancellationToken.None);

            Assert.NotNull(stored);
            Assert.True(stored!.AttemptCount > 0);
            Assert.NotEqual(CaptureJobStatus.Running, stored.Status);
            Assert.Equal("invalid_provider_data", stored.ErrorCode);
            Assert.Equal(0, fixture.Provider.ExportCalls);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Policy_Mutation_Audit_And_Outbox_Commit_Before_Provider_Side_Effects()
    {
        var fixture = await CreateFixtureAsync();
        var worker = new CapturePolicyReconcileWorker(
            fixture.Store,
            fixture.Resolver,
            fixture.WrappedOptions,
            NullLogger<CapturePolicyReconcileWorker>.Instance);
        try
        {
            var policy = await fixture.Policies.CreateAsync(
                "alpha", ValidPolicy("desired-state", "Desired state"), Actor());
            Assert.Equal(0, fixture.Provider.ApplyPolicyCalls);
            var audit = await fixture.Store.ListAuditAsync("alpha", 20);
            Assert.Contains(audit, item => item.Action == "capture.policy.create" &&
                                           item.Target == policy.PolicyId && item.Result == "success");

            await Assert.ThrowsAsync<CaptureVersionConflictException>(() =>
                fixture.Policies.DeleteAsync("alpha", policy.PolicyId, policy.Version + 1, Actor()));
            Assert.Equal(0, fixture.Provider.DeletePolicyCalls);
            Assert.True(await fixture.Policies.DeleteAsync(
                "alpha", policy.PolicyId, policy.Version, Actor()));
            Assert.Equal(0, fixture.Provider.DeletePolicyCalls);
            Assert.Null(await fixture.Policies.GetAsync("alpha", policy.PolicyId));

            await worker.StartAsync(CancellationToken.None);
            for (var index = 0; index < 100 && fixture.Provider.DeletePolicyCalls == 0; index++)
                await Task.Delay(20);
            await worker.StopAsync(CancellationToken.None);
            Assert.Equal(0, fixture.Provider.ApplyPolicyCalls);
            Assert.Equal(1, fixture.Provider.DeletePolicyCalls);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Provider_Sync_Quarantines_Malformed_Item_And_Advances_Page()
    {
        var fixture = await CreateFixtureAsync();
        var worker = new CaptureProviderSyncWorker(
            fixture.Store,
            fixture.Resolver,
            fixture.Sessions,
            fixture.WrappedOptions,
            NullLogger<CaptureProviderSyncWorker>.Instance);
        try
        {
            var now = DateTimeOffset.UtcNow.AddMinutes(-1);
            var poison = ProviderSession("alpha", "poison-1", now, "opaque-poison");
            poison.SourceIp = "not-an-ip";
            fixture.Provider.NextPage = new CaptureProviderSessionPage
            {
                Items =
                [
                    poison,
                    ProviderSession("alpha", "valid-after-poison", now, "opaque-valid")
                ],
                NextCursor = "page-1"
            };

            await worker.StartAsync(CancellationToken.None);
            for (var index = 0; index < 100 &&
                 await fixture.Store.GetProviderCursorAsync("provider-1") != "page-1"; index++)
                await Task.Delay(20);
            await worker.StopAsync(CancellationToken.None);

            Assert.Equal("page-1", await fixture.Store.GetProviderCursorAsync("provider-1"));
            Assert.Null(await fixture.Sessions.GetAsync("alpha", "poison-1"));
            Assert.NotNull(await fixture.Sessions.GetAsync("alpha", "valid-after-poison"));
            var audit = await fixture.Store.ListAuditAsync("alpha", 20);
            Assert.Contains(audit, item => item.Action == "capture.provider.session.quarantine" &&
                                           item.Target == "poison-1" && item.Result == "rejected");
            Assert.DoesNotContain(audit, item => item.DetailCode?.Contains("not-an-ip", StringComparison.Ordinal) == true);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Tls_Artifact_Provider_Must_Be_Assigned_To_The_Session_Tenant()
    {
        var fixture = await CreateFixtureAsync();
        try
        {
            var session = ProviderSession(
                "alpha", "wrong-tls-provider", DateTimeOffset.UtcNow.AddMinutes(-1), "opaque-payload");
            session.Tls!.DecryptedArtifactProviderId = "provider-2";
            await Assert.ThrowsAsync<CaptureValidationException>(() =>
                fixture.Sessions.IngestProviderSessionAsync("provider-1", session));
            Assert.Null(await fixture.Sessions.GetAsync("alpha", "wrong-tls-provider"));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task Separate_Central_Instances_Serialize_Shared_Provider_Capacity_Admission()
    {
        var fixture = await CreateFixtureAsync(
            capacityBytes: 500L * 1024 * 1024 * 1024,
            maxIngressMbps: 10_000m);
        try
        {
            var secondStore = new SqliteCaptureControlStore(
                fixture.WrappedOptions,
                NullLogger<SqliteCaptureControlStore>.Instance);
            await secondStore.InitializeAsync();
            var secondCapacity = new CaptureCapacityService(
                secondStore, fixture.Resolver, fixture.WrappedOptions);
            var secondService = new CapturePolicyService(
                secondStore,
                fixture.Resolver,
                secondCapacity,
                fixture.WrappedOptions,
                NullLogger<CapturePolicyService>.Instance);

            static CapturePolicy PacketPolicy(string id)
            {
                var policy = ValidPolicy(id, id);
                policy.Enabled = true;
                policy.Mode = CaptureMode.SelectivePackets;
                policy.EstimatedIngressMbps = 30m;
                policy.RetentionDays = 1;
                policy.StorageLifecycle = new CaptureStorageLifecycle { HotDays = 1, ColdDays = 0 };
                return policy;
            }

            var outcomes = await Task.WhenAll(
                TryCreatePolicyAsync(fixture.Policies, "alpha", PacketPolicy("instance-one")),
                TryCreatePolicyAsync(secondService, "beta", PacketPolicy("instance-two")));
            Assert.Single(outcomes, item => item.Policy is not null);
            Assert.Single(outcomes, item => item.Error is CaptureCapacityRejectedException);
            var all = (await fixture.Policies.ListAsync("alpha"))
                .Concat(await secondService.ListAsync("beta"))
                .Where(item => item.Enabled && item.ProviderId == "provider-1")
                .ToList();
            Assert.Single(all);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task<(CapturePolicy? Policy, Exception? Error)> TryCreatePolicyAsync(
        CapturePolicyService service,
        string tenantId,
        CapturePolicy policy)
    {
        try
        {
            return (await service.CreateAsync(tenantId, policy, Actor()), null);
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    private static async Task<(CapturePolicy? Policy, Exception? Error)> CaptureUpdateAsync(
        CapturePolicyService service,
        CapturePolicy policy,
        int expectedVersion)
    {
        try
        {
            return (await service.UpdateAsync("alpha", policy.PolicyId, policy, expectedVersion, Actor()), null);
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    private static CapturePolicy ValidPolicy(string id, string name) => new()
    {
        PolicyId = id,
        Name = name,
        ProviderId = "provider-1",
        Mode = CaptureMode.MetadataOnly,
        Enabled = false,
        EstimatedIngressMbps = 10m,
        SamplingPercent = 100m,
        MaxSessionDurationSeconds = 300,
        MaxBytesPerSession = 100 * 1024 * 1024,
        RetentionDays = 7,
        StorageLifecycle = new CaptureStorageLifecycle { HotDays = 7, ColdDays = 0 },
        Priority = 100,
        Scope = new CapturePolicyScope { Protocols = ["tcp"] },
        Tls = new TlsInspectionPolicy { Mode = TlsInspectionMode.MetadataOnly, FailOpen = true }
    };

    private static CaptureProviderSession ProviderSession(
        string tenantId,
        string sessionId,
        DateTimeOffset startedAtUtc,
        string payloadReference) => new()
    {
        TenantId = tenantId,
        SessionId = sessionId,
        FlowId = $"flow-{sessionId}",
        CorrelationId = $"correlation-{sessionId}",
        CampaignId = "campaign-1",
        EdgeId = "edge-1",
        SensorId = "sensor-1",
        StartedAtUtc = startedAtUtc,
        EndedAtUtc = startedAtUtc.AddSeconds(30),
        SourceIp = "10.0.0.10",
        SourcePort = 50123,
        DestinationIp = "203.0.113.20",
        DestinationPort = 443,
        Protocol = "tcp",
        Application = "https",
        PacketCount = 42,
        ByteCount = 4096,
        PayloadAvailable = true,
        PayloadBytes = 4096,
        PayloadSha256 = new string('a', 64),
        EncryptionKeyVersion = "kms-v3",
        StorageTier = CaptureStorageTier.Hot,
        StoragePoolId = "minio-hot-a",
        PayloadReference = payloadReference,
        TlsArtifactReference = $"opaque-tls-{sessionId}",
        RetainUntilUtc = startedAtUtc.AddDays(30),
        Tls = new TlsSessionMetadata
        {
            IsTls = true,
            ServerName = "service.example",
            Ja4 = "t13d1516h2_8daaf6152771_02713d6af862",
            DecryptionState = "decrypted_by_provider",
            DecryptedArtifactAvailable = true,
            DecryptedArtifactProviderId = "provider-1",
            DecryptedArtifactSha256 = new string('c', 64),
            DecryptedArtifactKeyVersion = "kms-v3",
            DecryptedArtifactStorageTier = CaptureStorageTier.Hot,
            DecryptedArtifactStoragePoolId = "minio-hot-a"
        }
    };

    private static CaptureActorContext Actor() => new("user:test-operator", "127.0.0.1");

    private static async Task<Fixture> CreateFixtureAsync(
        long capacityBytes = 500L * 1024 * 1024 * 1024,
        decimal maxIngressMbps = 10_000m)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ntshield-capture-{Guid.NewGuid():N}.db");
        var options = new CaptureControlOptions
        {
            Enabled = true,
            DatabasePath = path,
            DefaultTenantCapacityBytes = capacityBytes,
            CapacityAdmissionPercent = 85m,
            Providers =
            [
                new CaptureProviderOptions
                {
                    Id = "provider-1",
                    Kind = "test",
                    BaseUrl = "https://provider.example/",
                    CapacityBytes = capacityBytes,
                    MaxSustainableIngressMbps = maxIngressMbps,
                    FailOpen = true,
                    TenantIds = ["Alpha", "beta"]
                },
                new CaptureProviderOptions
                {
                    Id = "provider-2",
                    Kind = "test",
                    BaseUrl = "https://provider-2.example/",
                    CapacityBytes = capacityBytes,
                    MaxSustainableIngressMbps = maxIngressMbps,
                    FailOpen = true,
                    TenantIds = ["beta"]
                }
            ]
        };
        var wrapped = Options.Create(options);
        var store = new SqliteCaptureControlStore(wrapped, NullLogger<SqliteCaptureControlStore>.Instance);
        await store.InitializeAsync();
        await store.UpsertProviderHealthAsync(new CaptureProviderHealth
        {
            ProviderId = "provider-1",
            Kind = "test",
            State = CaptureProviderState.Healthy,
            CheckedAtUtc = DateTimeOffset.UtcNow,
            CapacityBytes = capacityBytes,
            MaxSustainableIngressMbps = maxIngressMbps,
            FailOpen = true,
            Capabilities = ["metadata", "policy", "payload-access", "export", "retention"]
        });
        var provider = new FakeCaptureProvider("provider-1", capacityBytes, maxIngressMbps, store, path);
        var secondaryProvider = new FakeCaptureProvider("provider-2", capacityBytes, maxIngressMbps, store, path);
        var resolver = new FakeProviderResolver(provider, secondaryProvider);
        var capacity = new CaptureCapacityService(store, resolver, wrapped);
        var policies = new CapturePolicyService(
            store, resolver, capacity, wrapped, NullLogger<CapturePolicyService>.Instance);
        var sessions = new CaptureSessionService(
            store, resolver, wrapped, NullLogger<CaptureSessionService>.Instance,
            new EphemeralDataProtectionProvider());
        return new Fixture(path, store, policies, sessions, provider, resolver, wrapped);
    }

    private sealed class Fixture : IDisposable
    {
        public Fixture(
            string path,
            ICaptureControlStore store,
            CapturePolicyService policies,
            CaptureSessionService sessions,
            FakeCaptureProvider provider,
            FakeProviderResolver resolver,
            IOptions<CaptureControlOptions> wrappedOptions)
        {
            Path = path;
            Store = store;
            Policies = policies;
            Sessions = sessions;
            Provider = provider;
            Resolver = resolver;
            WrappedOptions = wrappedOptions;
        }

        private string Path { get; }
        public ICaptureControlStore Store { get; }
        public CapturePolicyService Policies { get; }
        public CaptureSessionService Sessions { get; }
        public FakeCaptureProvider Provider { get; }
        public FakeProviderResolver Resolver { get; }
        public IOptions<CaptureControlOptions> WrappedOptions { get; }

        public void Dispose()
        {
            SqliteConnectionClearPools();
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var file = Path + suffix;
                if (File.Exists(file)) File.Delete(file);
            }
        }

        private static void SqliteConnectionClearPools() => Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }

    private sealed class FakeProviderResolver : ICaptureProviderResolver
    {
        private readonly IReadOnlyList<ICaptureProviderAdapter> _providers;
        public FakeProviderResolver(params ICaptureProviderAdapter[] providers) => _providers = providers;
        public IReadOnlyCollection<ICaptureProviderAdapter> All => _providers;
        public ICaptureProviderAdapter GetRequired(string providerId) =>
            _providers.FirstOrDefault(provider =>
                string.Equals(providerId, provider.ProviderId, StringComparison.OrdinalIgnoreCase))
            ?? throw new CaptureValidationException("Unknown provider.");
    }

    private sealed class FakeCaptureProvider : ICaptureProviderAdapter
    {
        private readonly long _capacityBytes;
        private readonly decimal _maxIngressMbps;
        private readonly ICaptureControlStore _store;
        private readonly string _databasePath;
        public FakeCaptureProvider(
            string providerId,
            long capacityBytes,
            decimal maxIngressMbps,
            ICaptureControlStore store,
            string databasePath)
        {
            ProviderId = providerId;
            _capacityBytes = capacityBytes;
            _maxIngressMbps = maxIngressMbps;
            _store = store;
            _databasePath = databasePath;
        }

        public string ProviderId { get; }
        public string Kind => "test";
        public bool FailOpen => true;
        public int SessionAccessCalls { get; private set; }
        public int TlsAccessCalls { get; private set; }
        public int TlsPreviewCalls { get; private set; }
        public int ExportCalls { get; private set; }
        public int ApplyPolicyCalls { get; private set; }
        public int DeletePolicyCalls { get; private set; }
        public bool AttemptObservedBeforeGrant { get; private set; }
        public string? LastPayloadReference { get; private set; }
        public bool FailCompletionAudit { get; set; }
        public bool ReturnInvalidSessionGrantId { get; set; }
        public int RevokeCalls { get; private set; }
        public List<(string TenantId, string PayloadReference)> DeletedPayloads { get; } = [];
        public CaptureProviderSessionPage? NextPage { get; set; }
        public IReadOnlySet<string> Capabilities { get; } = new HashSet<string>(
            ["metadata", "policy", "payload-access", "export", "retention", "tls-artifact-access", "tls-preview"],
            StringComparer.OrdinalIgnoreCase);
        public Task<CaptureProviderHealth> ProbeAsync(CancellationToken cancellationToken) => Task.FromResult(new CaptureProviderHealth
        {
            ProviderId = ProviderId,
            Kind = Kind,
            State = CaptureProviderState.Healthy,
            CheckedAtUtc = DateTimeOffset.UtcNow,
            CapacityBytes = _capacityBytes,
            MaxSustainableIngressMbps = _maxIngressMbps,
            FailOpen = true
        });
        public Task<CaptureProviderSessionPage> FetchSessionMetadataAsync(string? cursor, int take, CancellationToken cancellationToken)
        {
            var page = NextPage ?? new CaptureProviderSessionPage { NextCursor = cursor };
            NextPage = null;
            return Task.FromResult(page);
        }
        public Task ApplyPolicyAsync(CapturePolicy policy, CancellationToken cancellationToken)
        {
            ApplyPolicyCalls++;
            return Task.CompletedTask;
        }
        public Task DeletePolicyAsync(string tenantId, string policyId, CancellationToken cancellationToken)
        {
            DeletePolicyCalls++;
            return Task.CompletedTask;
        }
        public async Task<ProviderAccessGrant> CreateSessionAccessAsync(ProviderSessionAccessRequest request, CancellationToken cancellationToken)
        {
            SessionAccessCalls++;
            LastPayloadReference = request.PayloadReference;
            AttemptObservedBeforeGrant = (await _store.ListAuditAsync(request.TenantId, 20, cancellationToken))
                .Any(entry => entry.Action == "capture.session.access" && entry.Result == "attempt" && entry.Target == request.SessionId);
            if (FailCompletionAudit)
            {
                await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync(cancellationToken);
                await using var command = connection.CreateCommand();
                command.CommandText = "DROP TABLE capture_audit;";
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            return new ProviderAccessGrant
            {
                GrantId = ReturnInvalidSessionGrantId ? "invalid grant id" : Guid.NewGuid().ToString("N"),
                AccessUrl = "https://download.example/session",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds)
            };
        }
        public Task<ProviderExportResult> StartExportAsync(ProviderExportRequest request, CancellationToken cancellationToken)
        {
            ExportCalls++;
            return Task.FromResult(new ProviderExportResult
            {
                OutputReference = "opaque-export",
                OutputSha256 = new string('b', 64),
                EncryptionKeyVersion = "kms-v3",
                StorageTier = CaptureStorageTier.Hot,
                StoragePoolId = "minio-hot-a"
            });
        }
        public Task<ProviderAccessGrant> CreateTlsArtifactAccessAsync(
            ProviderTlsArtifactAccessRequest request,
            CancellationToken cancellationToken)
        {
            TlsAccessCalls++;
            return Task.FromResult(new ProviderAccessGrant
            {
                GrantId = Guid.NewGuid().ToString("N"),
                AccessUrl = "https://download.example/tls-artifact",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds)
            });
        }
        public Task<TlsDecodedPreview> GetTlsPreviewAsync(
            ProviderTlsPreviewRequest request,
            CancellationToken cancellationToken)
        {
            TlsPreviewCalls++;
            return Task.FromResult(new TlsDecodedPreview
            {
                SessionId = request.SessionId,
                ArtifactSha256 = new string('c', 64),
                Truncated = false,
                Transactions =
                [
                    new TlsDecodedTransactionPreview
                    {
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Protocol = "HTTP/2",
                        Method = "GET",
                        Authority = "service.example",
                        PathTemplate = "/api/orders/{id}",
                        StatusCode = 200,
                        RequestContentType = "application/json",
                        ResponseContentType = "application/json",
                        ResponseBodyBytes = 512,
                        RequestHeaderNames = ["accept", "content-type"],
                        ResponseHeaderNames = ["content-type"]
                    }
                ]
            });
        }
        public Task<ProviderAccessGrant> CreateExportAccessAsync(ProviderExportAccessRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new ProviderAccessGrant
            {
                GrantId = Guid.NewGuid().ToString("N"),
                AccessUrl = "https://download.example/export",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds)
            });
        public Task DeletePayloadAsync(string tenantId, string payloadReference, CancellationToken cancellationToken)
        {
            DeletedPayloads.Add((tenantId, payloadReference));
            return Task.CompletedTask;
        }
        public Task RevokeAccessGrantAsync(string grantId, CancellationToken cancellationToken)
        {
            RevokeCalls++;
            return Task.CompletedTask;
        }
    }

    private static RouteEndpoint Find(
        IEnumerable<RouteEndpoint> endpoints,
        string route,
        string method) => endpoints.Single(endpoint =>
            endpoint.RoutePattern.RawText == route &&
            endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method) == true);

    private static ClaimsPrincipal Principal(string role) => new(new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, "test"), new Claim(ClaimTypes.Role, role)],
        "test"));
}
