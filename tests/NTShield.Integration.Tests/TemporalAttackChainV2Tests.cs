using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NTShield.Server.Correlation;
using NTShield.Server.Data;
using NTShield.Server.Services;
using NTShield.Shared.Contracts;
using NTShield.Shared.Models;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class TemporalAttackChainV2Tests
{
    [Fact]
    public async Task Episodes_Use_Sixty_Minute_Inactivity_And_Late_Event_Bridges_Sessions()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var watermark = DateTimeOffset.Parse("2026-08-08T12:00:00Z");

        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("boundary", "one", "2026-08-08T01:59:00Z")));
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("boundary", "two", "2026-08-08T02:01:00Z")));
        var boundary = await store.ListThreatObservationsAsync(
            "default", "boundary", watermark, null, null, null, null, 10);
        Assert.Equal(2, boundary.Count);
        Assert.NotNull(boundary[0].EpisodeId);
        Assert.Equal(boundary[0].EpisodeId, boundary[1].EpisodeId);
        Assert.Equal(1, (await store.GetThreatCampaignV2SummaryAsync("default", "boundary"))!.EpisodeCount);

        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("bridge", "early", "2026-08-08T00:00:00Z")));
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("bridge", "late", "2026-08-08T02:00:00Z")));
        Assert.Equal(2, (await store.GetThreatCampaignV2SummaryAsync("default", "bridge"))!.EpisodeCount);

        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("bridge", "middle", "2026-08-08T01:00:00Z")));
        var bridged = await store.ListThreatObservationsAsync(
            "default", "bridge", watermark, null, null, null, null, 10);
        Assert.Equal(3, bridged.Count);
        Assert.Single(bridged.Select(item => item.EpisodeId).Distinct());
        Assert.Equal(1, (await store.GetThreatCampaignV2SummaryAsync("default", "bridge"))!.EpisodeCount);
    }

    [Fact]
    public async Task Membership_Is_Tenant_Scoped_And_Overrides_Source_Campaign_On_Read()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var observation = Observation("campaign-a", "shared", "2026-08-08T04:00:00Z");
        Assert.True(await store.TryAppendThreatObservationAsync(observation));
        Assert.False(await store.TryAppendThreatObservationAsync(observation));

        await store.UpsertThreatObservationMembershipAsync(new ThreatObservationMembership
        {
            TenantId = "default",
            CampaignId = "campaign-b",
            ObservationId = observation.ObservationId,
            AssignedAtUtc = DateTimeOffset.Parse("2026-08-08T04:01:00Z"),
            Confidence = .8,
            Provenance = "test_shared_evidence"
        });

        var rows = await store.ListThreatObservationsAsync(
            "default", "campaign-b", DateTimeOffset.Parse("2026-08-08T12:00:00Z"),
            null, null, null, null, 10);
        var shared = Assert.Single(rows);
        Assert.Equal("campaign-b", shared.CampaignId);
        Assert.Equal(observation.ObservationId, shared.ObservationId);
        Assert.NotNull(shared.EpisodeId);
        var sharedSummary = await store.GetThreatCampaignV2SummaryAsync("default", "campaign-b");
        Assert.NotNull(sharedSummary);
        Assert.Equal(1, sharedSummary!.ObservationCount);
        Assert.Single(await store.ListThreatContactsAsync(
            "default", "campaign-b", DateTimeOffset.Parse("2026-08-08T12:00:00Z"),
            null, null, null, null, 10));

        var otherTenant = await store.ListThreatObservationsAsync(
            "other", "campaign-b", DateTimeOffset.Parse("2026-08-08T12:00:00Z"),
            null, null, null, null, 10);
        Assert.Empty(otherTenant);
    }

    [Fact]
    public void Temporal_Dtos_Use_Locked_Wire_Field_Names()
    {
        var json = JsonSerializer.Serialize(new
        {
            node = new ThreatGraphNode { NodeId = "n", Kind = "host" },
            edge = new ThreatGraphEdge
            {
                EdgeId = "e", SourceNodeId = "a", DestinationNodeId = "b", Relation = "connected"
            },
            contact = new ThreatContactAggregate
            {
                ContactId = "c", SourceNodeId = "a", DestinationNodeId = "b", RemotePort = 443,
                FirstObservedAtUtc = DateTimeOffset.UnixEpoch,
                LastObservedAtUtc = DateTimeOffset.UnixEpoch.AddMinutes(5),
                OpenCount = 3
            },
            bucket = new ThreatTimelineBucket
            {
                StartUtc = DateTimeOffset.UnixEpoch, EndUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
            }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"type\":\"host\"", json);
        Assert.Contains("\"fromNodeId\":\"a\"", json);
        Assert.Contains("\"toNodeId\":\"b\"", json);
        Assert.Contains("\"contactKey\":\"c\"", json);
        Assert.Contains("\"destinationPort\":443", json);
        Assert.Contains("\"reconnectCount\":2", json);
        Assert.Contains("\"durationSeconds\":300", json);
        Assert.Contains("\"bucketStartUtc\"", json);
        var edge = JsonSerializer.Serialize(new ThreatGraphEdge(),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("\"predecessorEdgeIds\":[]", edge);
        Assert.Contains("\"evidenceRefs\":[]", edge);
    }

    [Fact]
    public void Campaign_List_Bounds_Detail_Samples_And_Stays_Below_Compressed_Response_Budget()
    {
        var bound = typeof(TemporalThreatEndpoints).GetMethod(
            "BoundCampaignListItem", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(bound);
        var page = new ThreatCampaignV2Page
        {
            Items = Enumerable.Range(0, 100).Select(index => new ThreatCampaignV2Summary
            {
                TenantId = "tenant-a",
                CampaignId = $"campaign-{index:D3}",
                Revision = 42,
                Status = "Open",
                Severity = "Critical",
                Confidence = .95,
                FirstObservedAtUtc = DateTimeOffset.Parse("2026-08-01T00:00:00Z"),
                LastObservedAtUtc = DateTimeOffset.Parse("2026-08-08T00:00:00Z"),
                UpdatedAtUtc = DateTimeOffset.Parse("2026-08-08T00:00:01Z"),
                ObservationCount = 20_000,
                AffectedAssetCount = 96,
                RelatedIncidentCount = 50,
                Title = PseudoRandomText(index, 300),
                Summary = PseudoRandomText(index + 1_000, 2_000),
                InvolvedHosts = Enumerable.Range(0, 32)
                    .Select(value => PseudoRandomText(index * 100 + value, 200)).ToList(),
                InvolvedIps = Enumerable.Range(0, 64)
                    .Select(value => PseudoRandomText(index * 200 + value, 128)).ToList(),
                RelatedIncidentIds = Enumerable.Range(0, 50)
                    .Select(value => PseudoRandomText(index * 300 + value, 160)).ToList()
            }).ToList()
        };

        foreach (var item in page.Items) bound!.Invoke(null, [item]);
        Assert.All(page.Items, item =>
        {
            Assert.True(item.InvolvedHosts.Count <= 2);
            Assert.True(item.InvolvedIps.Count <= 2);
            Assert.True(item.RelatedIncidentIds.Count <= 2);
            Assert.Equal(20_000, item.ObservationCount);
            Assert.Equal(50, item.RelatedIncidentCount);
        });

        var json = JsonSerializer.SerializeToUtf8Bytes(page, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(json);
        Assert.True(compressed.Length <= 200 * 1024,
            $"100 campaign summaries compressed to {compressed.Length:N0} bytes.");
    }

    [Fact]
    public async Task Temporal_Outbox_Leases_Retries_And_Completes_Durably()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var now = DateTimeOffset.Parse("2026-08-08T06:00:00Z");
        await store.EnqueueTemporalCorrelationWorkAsync(new TemporalCorrelationWorkItem
        {
            WorkId = "work-one",
            TenantId = "tenant-a",
            PayloadJson = "{}",
            EnqueuedAtUtc = now
        });

        var first = Assert.Single(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-a", now, TimeSpan.FromMinutes(2), 10));
        Assert.Equal(1, first.Attempts);
        Assert.Empty(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-b", now.AddMinutes(1), TimeSpan.FromMinutes(2), 10));

        await store.FailTemporalCorrelationWorkAsync(
            first.WorkId, "worker-a", now.AddMinutes(3), "transient", CancellationToken.None);
        Assert.Empty(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-b", now.AddMinutes(2), TimeSpan.FromMinutes(2), 10));
        var retried = Assert.Single(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-b", now.AddMinutes(3), TimeSpan.FromMinutes(2), 10));
        Assert.Equal(2, retried.Attempts);
        await store.CompleteTemporalCorrelationWorkAsync(retried.WorkId, "worker-b");
        Assert.Empty(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-c", now.AddHours(1), TimeSpan.FromMinutes(2), 10));
    }

    [Fact]
    public async Task Temporal_Outbox_Lease_Is_Exclusive_Until_It_Expires()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var now = DateTimeOffset.Parse("2026-08-08T06:00:00Z");
        await store.EnqueueTemporalCorrelationWorkAsync(new TemporalCorrelationWorkItem
        {
            WorkId = "stale-lease",
            TenantId = "tenant-a",
            PayloadJson = "{}",
            EnqueuedAtUtc = now
        });

        var first = Assert.Single(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-a", now, TimeSpan.FromMinutes(5), 1));
        Assert.Equal(1, first.Attempts);
        Assert.Empty(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-b", now.AddMinutes(4), TimeSpan.FromMinutes(5), 1));

        var recovered = Assert.Single(await store.LeaseTemporalCorrelationWorkAsync(
            "worker-b", now.AddMinutes(5).AddSeconds(1), TimeSpan.FromMinutes(5), 1));
        Assert.Equal(2, recovered.Attempts);
        await store.CompleteTemporalCorrelationWorkAsync(recovered.WorkId, "worker-b");
    }

    [Fact]
    public async Task Campaign_List_Snapshot_Preserves_Unreturned_Row_After_Concurrent_Update()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var observed = DateTimeOffset.Parse("2026-08-08T05:00:00Z");
        foreach (var campaignId in new[] { "campaign-a", "campaign-b", "campaign-c" })
        {
            await store.UpsertThreatCampaignV2SummaryAsync(Summary(campaignId, observed));
            await Task.Delay(10);
        }

        var watermark = DateTimeOffset.UtcNow;
        var firstPage = await store.ListThreatCampaignV2SummariesAsync(
            "default", watermark, null, null, null, null, null, null, 2);
        Assert.Equal(2, firstPage.Count);
        var unreturnedId = new[] { "campaign-a", "campaign-b", "campaign-c" }
            .Single(id => firstPage.All(item => item.CampaignId != id));

        await Task.Delay(10);
        var update = Summary(unreturnedId, observed.AddMinutes(1));
        update.Status = "Investigating";
        await store.UpsertThreatCampaignV2SummaryAsync(update);
        Assert.Equal(2, (await store.GetThreatCampaignV2SummaryAsync("default", unreturnedId))!.Revision);

        var secondPage = await store.ListThreatCampaignV2SummariesAsync(
            "default", watermark, null, null, null, null,
            firstPage[^1].SnapshotAtUtc, firstPage[^1].CampaignId, 2);
        var oldSnapshot = Assert.Single(secondPage);
        Assert.Equal(unreturnedId, oldSnapshot.CampaignId);
        Assert.Equal(1, oldSnapshot.Revision);
        Assert.Equal("Open", oldSnapshot.Status);
        Assert.Equal(3, firstPage.Concat(secondPage).Select(item => item.CampaignId).Distinct().Count());
    }

    [Fact]
    public async Task Retention_Removes_Detail_Before_Campaign_Aggregate()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("retained-summary", "old", "2026-01-01T00:00:00Z")));

        await store.SweepTemporalThreatDataAsync(
            DateTimeOffset.Parse("2026-02-01T00:00:00Z"),
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"));
        Assert.Equal(0, await store.CountThreatObservationDetailsAsync(
            "default", "retained-summary", DateTimeOffset.Parse("2027-01-01T00:00:00Z")));
        Assert.Equal(1, await store.CountThreatObservationsAsync(
            "default", "retained-summary", DateTimeOffset.Parse("2027-01-01T00:00:00Z")));
        Assert.Single(await store.ListThreatTimelineBucketsAsync(
            "default", "retained-summary", DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            null, null, 3600, null, 10));
        Assert.Single(await store.ListThreatContactsAsync(
            "default", "retained-summary", DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            null, null, null, null, 10));
        Assert.NotNull(await store.GetThreatCampaignV2SummaryAsync("default", "retained-summary"));

        await store.SweepTemporalThreatDataAsync(
            DateTimeOffset.Parse("2026-02-01T00:00:00Z"),
            DateTimeOffset.Parse("2026-02-01T00:00:00Z"));
        Assert.Null(await store.GetThreatCampaignV2SummaryAsync("default", "retained-summary"));
        Assert.Empty(await store.ListThreatCampaignV2SummariesAsync(
            "default", DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            null, null, null, null, null, null, 10));
    }

    [Fact]
    public async Task Unassigned_Network_Candidates_Are_Durable_Clock_Corrected_And_Lifecycle_Idempotent()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var service = new TemporalAttackChainService(
            fixture.Store, NullLogger<TemporalAttackChainService>.Instance);
        var ingestUtc = DateTimeOffset.UtcNow;
        var rawObserved = ingestUtc.AddMinutes(4);
        var batch = new AgentIngestBatch
        {
            AgentId = "agent-a",
            ComputerName = "host-a",
            SentAtUtc = ingestUtc.AddHours(-8), // offline queue age must not be interpreted as clock skew
            ClockSkewSeconds = 300,
            ClockSkewMeasuredAtUtc = ingestUtc,
            NetworkConnections =
            [
                new NetworkConnectionRecord
                {
                    AgentId = "agent-a",
                    ComputerName = "host-a",
                    TimestampUtc = rawObserved,
                    StartedAtUtc = rawObserved.AddMinutes(-1),
                    Protocol = "TCP",
                    LocalAddress = "10.0.0.1",
                    LocalPort = 49152,
                    RemoteAddress = "198.51.100.20",
                    RemotePort = 443,
                    ProcessId = 42,
                    ConnectionKey = "tuple-one",
                    LifecycleId = "life-one",
                    IsNew = true
                }
            ]
        };

        Assert.Equal(1, await service.RecordAsync(batch, [], [], "tenant-a", CancellationToken.None));
        Assert.Equal(0, await service.RecordAsync(batch, [], [], "tenant-a", CancellationToken.None));
        var candidates = await fixture.Store.ListThreatCandidateObservationsAsync(
            "tenant-a", string.Empty, ingestUtc.AddDays(-1), ingestUtc.AddDays(1), 10);
        var candidate = Assert.Single(candidates);
        Assert.Equal(string.Empty, candidate.CampaignId);
        Assert.Equal(rawObserved, candidate.RawObservedAtUtc);
        Assert.InRange(candidate.ClockSkewSeconds!.Value, 299, 301);
        Assert.InRange(candidate.ObservedAtUtc, ingestUtc.AddMinutes(-2), ingestUtc);
        Assert.NotNull(candidate.StartedAtUtc);
        Assert.Contains("clock_corrected", candidate.TimestampQuality);

        batch.NetworkConnections[0].LifecycleId = "life-two";
        Assert.Equal(1, await service.RecordAsync(batch, [], [], "tenant-a", CancellationToken.None));
        candidates = await fixture.Store.ListThreatCandidateObservationsAsync(
            "tenant-a", string.Empty, ingestUtc.AddDays(-1), ingestUtc.AddDays(1), 10);
        Assert.Equal(2, candidates.Count);
        Assert.Equal(2, candidates.Select(item => item.ObservationId).Distinct().Count());
    }

    [Fact]
    public async Task Legacy_Backfill_Is_Bounded_Idempotent_And_Does_Not_Invent_Counts()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var service = new TemporalAttackChainService(
            fixture.Store, NullLogger<TemporalAttackChainService>.Instance);
        var campaign = new ThreatCampaign
        {
            TenantId = "tenant-a",
            CampaignId = "legacy-one",
            FirstSeenUtc = DateTimeOffset.Parse("2026-08-01T00:00:00Z"),
            LastSeenUtc = DateTimeOffset.Parse("2026-08-01T00:05:00Z"),
            Hops =
            [
                new ThreatHop
                {
                    TimestampUtc = DateTimeOffset.Parse("2026-08-01T00:03:00Z"),
                    FromIp = "10.0.0.1",
                    ToIp = "10.0.0.2",
                    Port = 445,
                    Technique = "remote_service",
                    Evidence = "legacy summary had no raw event count"
                }
            ]
        };

        Assert.Equal(1, await service.BackfillLegacyCampaignAsync(campaign));
        Assert.Equal(0, await service.BackfillLegacyCampaignAsync(campaign));
        var rows = await fixture.Store.ListThreatObservationsAsync(
            "tenant-a", "legacy-one", DateTimeOffset.UtcNow.AddDays(1),
            null, null, null, null, 10);
        var observation = Assert.Single(rows);
        Assert.Equal(1, observation.OccurrenceCount);
        Assert.Equal("legacy_collapsed", observation.TimestampQuality);
    }

    [Fact]
    public async Task Tombstoned_Merge_State_Is_Not_Resurrected_By_Later_Projection_Update()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("merge-source", "merge", "2026-08-08T07:00:00Z")));
        var tombstoned = DateTimeOffset.Parse("2026-08-08T08:00:00Z");
        await store.MarkThreatCampaignMergedAsync(
            "default", "merge-source", "merge-target", tombstoned);

        await store.UpsertThreatCampaignV2SummaryAsync(new ThreatCampaignV2Summary
        {
            TenantId = "default",
            CampaignId = "merge-source",
            Revision = 1,
            Status = "Open",
            Severity = "High",
            FirstObservedAtUtc = tombstoned.AddHours(-1),
            LastObservedAtUtc = tombstoned.AddMinutes(1),
            UpdatedAtUtc = tombstoned.AddMinutes(1)
        });
        var summary = await store.GetThreatCampaignV2SummaryAsync("default", "merge-source");
        Assert.Equal("Merged", summary!.Status);
        Assert.Equal("merge-target", summary.MergedIntoCampaignId);
        Assert.Equal(tombstoned, summary.TombstonedAtUtc);
        Assert.Equal(0, await store.CountActiveThreatCampaignsAsync("default"));
    }

    [Fact]
    public async Task Periodicity_Alone_Remains_Inferred_Until_Independent_Evidence_Corroborates()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var service = new TemporalAttackChainService(
            fixture.Store, NullLogger<TemporalAttackChainService>.Instance);
        var start = DateTimeOffset.UtcNow.AddMinutes(-10);

        for (var index = 0; index < 3; index++)
            await service.RecordAsync(NetworkBatch(start.AddMinutes(index), $"life-{index}"), [], [],
                "tenant-a", CancellationToken.None);
        Assert.Empty(await fixture.Store.ListThreatCampaignV2SummariesAsync(
            "tenant-a", DateTimeOffset.UtcNow.AddMinutes(1), null, null, null, null,
            null, null, 10));

        for (var index = 3; index < 5; index++)
            await service.RecordAsync(NetworkBatch(start.AddMinutes(index), $"life-{index}"), [], [],
                "tenant-a", CancellationToken.None);
        var inferred = Assert.Single(await fixture.Store.ListThreatCampaignV2SummariesAsync(
            "tenant-a", DateTimeOffset.UtcNow.AddMinutes(1), null, null, null, null,
            null, null, 10));
        Assert.Equal("Candidate", inferred.Status);
        Assert.Equal(0, await fixture.Store.CountActiveThreatCampaignsAsync("tenant-a"));

        var detectionTime = start.AddMinutes(5);
        await service.RecordAsync(new AgentIngestBatch
        {
            AgentId = "agent-a",
            ComputerName = "host-a",
            SentAtUtc = detectionTime,
            Alerts =
            [
                new DetectionAlert
                {
                    AlertId = "corroborating-alert",
                    AgentId = "agent-a",
                    ComputerName = "host-a",
                    TimestampUtc = detectionTime,
                    SourceIp = "198.51.100.20",
                    DestinationIp = "10.0.0.1",
                    RuleId = "SUSPICIOUS_REMOTE_CONTACT"
                }
            ]
        }, [], [], "tenant-a", CancellationToken.None);
        var promoted = Assert.Single(await fixture.Store.ListThreatCampaignV2SummariesAsync(
            "tenant-a", DateTimeOffset.UtcNow.AddMinutes(1), null, null, null, null,
            null, null, 10));
        Assert.Equal("Open", promoted.Status);
        Assert.True(promoted.Confidence >= .8);
        Assert.Equal(1, await fixture.Store.CountActiveThreatCampaignsAsync("tenant-a"));
    }

    [Fact]
    public async Task Late_Contact_Recomputes_Chronological_Gaps()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("cadence", "zero", "2026-08-08T00:00:00Z")));
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("cadence", "two", "2026-08-08T02:00:00Z")));
        Assert.True(await store.TryAppendThreatObservationAsync(
            Observation("cadence", "one-late", "2026-08-08T01:00:00Z")));

        var contact = Assert.Single(await store.ListThreatContactsAsync(
            "default", "cadence", DateTimeOffset.Parse("2026-08-09T00:00:00Z"),
            null, null, null, null, 10));
        Assert.Equal(3_600, contact.MedianGapSeconds);
        Assert.Equal(3_600, contact.P95GapSeconds);
        Assert.Equal("exact_last_64_chronological_gaps", contact.MetricQuality);
    }

    [Fact]
    public async Task Explicit_Contacts_Preserve_Branches_And_Cycles_Without_Inventing_Sequential_Edges()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var observed = DateTimeOffset.Parse("2026-08-08T04:00:00Z");
        var expected = new[]
        {
            (Contact: "a-to-b", Source: "node-a", Destination: "node-b", Offset: 0),
            (Contact: "a-to-c", Source: "node-a", Destination: "node-c", Offset: 1),
            (Contact: "c-to-a", Source: "node-c", Destination: "node-a", Offset: 2)
        };

        foreach (var edge in expected)
        {
            var observation = Observation(
                "branch-cycle", edge.Contact, observed.AddMinutes(edge.Offset).ToString("O"));
            observation.ContactId = edge.Contact;
            observation.SourceNodeId = edge.Source;
            observation.DestinationNodeId = edge.Destination;
            observation.SourceIp = edge.Source == "node-a" ? "10.0.0.1" : "10.0.0.3";
            observation.DestinationIp = edge.Destination switch
            {
                "node-a" => "10.0.0.1",
                "node-b" => "10.0.0.2",
                _ => "10.0.0.3"
            };
            Assert.True(await fixture.Store.TryAppendThreatObservationAsync(observation));
        }

        var contacts = await fixture.Store.ListThreatContactsAsync(
            "default", "branch-cycle", observed.AddHours(8),
            null, null, null, null, 10);

        Assert.Equal(3, contacts.Count);
        Assert.Contains(contacts, item => item.SourceNodeId == "node-a" && item.DestinationNodeId == "node-b");
        Assert.Contains(contacts, item => item.SourceNodeId == "node-a" && item.DestinationNodeId == "node-c");
        Assert.Contains(contacts, item => item.SourceNodeId == "node-c" && item.DestinationNodeId == "node-a");
        Assert.DoesNotContain(contacts, item => item.SourceNodeId == "node-b" && item.DestinationNodeId == "node-c");
        Assert.DoesNotContain(contacts, item => item.SourceNodeId == item.DestinationNodeId);
    }

    [Fact]
    public async Task Contact_Aggregate_Preserves_Long_Lived_Open_Close_And_Reconnect_Lifecycle()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var start = DateTimeOffset.Parse("2026-08-08T02:00:00Z");
        var phases = new[]
        {
            (Id: "open-one", Kind: "network_open", OffsetSeconds: 0),
            (Id: "active-one", Kind: "network_observation", OffsetSeconds: 30),
            (Id: "close-one", Kind: "network_close", OffsetSeconds: 120),
            (Id: "open-two", Kind: "network_open", OffsetSeconds: 180)
        };

        foreach (var phase in phases)
        {
            var observation = Observation(
                "network-lifecycle", phase.Id, start.AddSeconds(phase.OffsetSeconds).ToString("O"));
            observation.ContactId = "stable-endpoint-pair";
            observation.Kind = phase.Kind;
            Assert.True(await fixture.Store.TryAppendThreatObservationAsync(observation));
        }

        var contact = Assert.Single(await fixture.Store.ListThreatContactsAsync(
            "default", "network-lifecycle", start.AddHours(9),
            null, null, null, null, 10));
        Assert.Equal(4, contact.ObservationCount);
        Assert.Equal(2, contact.OpenCount);
        Assert.Equal(1, contact.CloseCount);
        Assert.Equal(1, contact.ReconnectCount);
        Assert.Equal(180, contact.DurationSeconds);
        Assert.Equal(3, contact.RecurrenceCount);
    }

    [Fact]
    public async Task Shared_Nat_Ip_Alone_Does_Not_Join_Legacy_Campaign()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var service = new TemporalAttackChainService(
            fixture.Store, NullLogger<TemporalAttackChainService>.Instance);
        var observed = DateTimeOffset.UtcNow.AddMinutes(-1);
        var incident = new Incident
        {
            TenantId = "tenant-a",
            IncidentId = "incident-one",
            SourceIp = "10.10.10.10",
            DestinationIp = "10.10.10.20",
            FirstSeen = observed,
            LastSeen = observed
        };
        var campaign = new ThreatCampaign
        {
            TenantId = "tenant-a",
            CampaignId = "legacy-nat",
            FirstSeenUtc = observed.AddMinutes(-5),
            LastSeenUtc = observed.AddMinutes(5),
            InvolvedIps = ["203.0.113.5"],
            RelatedIncidentIds = [incident.IncidentId]
        };
        var batch = NetworkBatch(observed, "nat-life");
        batch.NetworkConnections[0].RemoteAddress = "203.0.113.5";
        await service.RecordAsync(batch, [incident], [campaign], "tenant-a", CancellationToken.None);

        var observations = await fixture.Store.ListThreatObservationsAsync(
            "tenant-a", "legacy-nat", DateTimeOffset.UtcNow.AddMinutes(1),
            null, null, null, null, 20);
        Assert.NotEmpty(observations); // deterministic incident projection still exists
        Assert.DoesNotContain(observations, item => item.EvidenceType == "network_connection");
    }

    [Fact]
    public async Task Legacy_Backfill_Resumes_After_Summary_And_Persists_Page_Cursor()
    {
        await using var fixture = await TemporalStoreFixture.CreateAsync();
        var store = fixture.Store;
        var service = new TemporalAttackChainService(
            store, NullLogger<TemporalAttackChainService>.Instance);
        var seen = DateTimeOffset.Parse("2026-08-01T00:00:00Z");
        await store.UpsertThreatCampaignV2SummaryAsync(new ThreatCampaignV2Summary
        {
            TenantId = "tenant-a",
            CampaignId = "partial-backfill",
            Revision = 1,
            Status = "Open",
            Severity = "Low",
            FirstObservedAtUtc = seen,
            LastObservedAtUtc = seen,
            UpdatedAtUtc = seen
        });
        var campaign = new ThreatCampaign
        {
            TenantId = "tenant-a",
            CampaignId = "partial-backfill",
            FirstSeenUtc = seen,
            LastSeenUtc = seen,
            Hops =
            [
                new ThreatHop
                {
                    TimestampUtc = seen,
                    FromIp = "10.0.0.1",
                    ToIp = "10.0.0.2",
                    Evidence = "durable resume"
                }
            ]
        };
        Assert.Equal(1, await service.BackfillLegacyCampaignAsync(campaign));

        await store.UpsertCampaignJsonAsync("campaign-b", JsonSerializer.Serialize(campaign));
        campaign.CampaignId = "campaign-a";
        await store.UpsertCampaignJsonAsync("campaign-a", JsonSerializer.Serialize(campaign));
        var firstPage = Assert.Single(await store.ListCampaignJsonPageAsync(null, 1));
        Assert.Equal("campaign-a", firstPage.Id);
        var secondPage = Assert.Single(await store.ListCampaignJsonPageAsync(firstPage.Id, 1));
        Assert.Equal("campaign-b", secondPage.Id);
        await store.SaveTemporalBackfillCursorAsync(secondPage.Id);
        Assert.Equal("campaign-b", await store.GetTemporalBackfillCursorAsync());
        await store.SaveTemporalBackfillCursorAsync(null);
        Assert.Null(await store.GetTemporalBackfillCursorAsync());
    }

    private static ThreatObservation Observation(string campaignId, string id, string observedAt) => new()
    {
        TenantId = "default",
        CampaignId = campaignId,
        ObservationId = "observation-" + id,
        ContactId = "contact-independent",
        Kind = "network_connection",
        Relation = "connected",
        ObservedAtUtc = DateTimeOffset.Parse(observedAt),
        IngestedAtUtc = DateTimeOffset.Parse("2026-08-08T10:00:00Z"),
        SourceNodeId = "ip-a",
        SourceIp = "10.0.0.1",
        DestinationNodeId = "ip-b",
        DestinationIp = "10.0.0.2",
        Protocol = "tcp",
        RemotePort = 443,
        EvidenceType = "test",
        EvidenceId = "evidence-" + id
    };

    private static ThreatCampaignV2Summary Summary(string campaignId, DateTimeOffset observedAt) => new()
    {
        TenantId = "default",
        CampaignId = campaignId,
        Revision = 1,
        Status = "Open",
        Severity = "Medium",
        Confidence = .85,
        FirstObservedAtUtc = observedAt,
        LastObservedAtUtc = observedAt,
        UpdatedAtUtc = observedAt,
        Title = campaignId
    };

    private static AgentIngestBatch NetworkBatch(DateTimeOffset observedAtUtc, string lifecycleId) => new()
    {
        AgentId = "agent-a",
        ComputerName = "host-a",
        SentAtUtc = observedAtUtc,
        NetworkConnections =
        [
            new NetworkConnectionRecord
            {
                AgentId = "agent-a",
                ComputerName = "host-a",
                TimestampUtc = observedAtUtc,
                Protocol = "TCP",
                LocalAddress = "10.0.0.1",
                LocalPort = 49152,
                RemoteAddress = "198.51.100.20",
                RemotePort = 443,
                ConnectionKey = "same-tuple",
                LifecycleId = lifecycleId
            }
        ]
    };

    private static string PseudoRandomText(int seed, int length)
    {
        var builder = new StringBuilder(length);
        for (var block = 0; builder.Length < length; block++)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{seed}:{block}"));
            builder.Append(Convert.ToHexString(bytes));
        }
        return builder.ToString(0, length);
    }

    private sealed class TemporalStoreFixture : IAsyncDisposable
    {
        private TemporalStoreFixture(string path, SqliteCentralStore store)
        {
            Path = path;
            Store = store;
        }

        private string Path { get; }
        public SqliteCentralStore Store { get; }

        public static async Task<TemporalStoreFixture> CreateAsync()
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"ntshield-temporal-{Guid.NewGuid():N}.db");
            var store = new SqliteCentralStore(
                Options.Create(new SqliteCentralOptions { DatabasePath = path }),
                NullLogger<SqliteCentralStore>.Instance);
            await store.InitializeAsync();
            return new TemporalStoreFixture(path, store);
        }

        public ValueTask DisposeAsync()
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var candidate = Path + suffix;
                if (File.Exists(candidate)) File.Delete(candidate);
            }
            return ValueTask.CompletedTask;
        }
    }
}
