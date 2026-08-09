from __future__ import annotations

from app.evidence import EvidenceNormalizer
from app.models import EvidenceItem, EvidenceSource, IncidentInput


def test_structured_temporal_evidence_preserves_citation_without_raw_payload():
    incident = IncidentInput(
        incident_id="campaign-42",
        title="Repeated outbound contact",
        structured_evidence=[
            EvidenceItem(
                ref_id="observation:obs-42",
                source=EvidenceSource.TEMPORAL_CHAIN,
                kind="network_open",
                timestamp_utc="2026-08-08T01:02:03Z",
                summary="host-a contacted 203.0.113.10:443",
                attributes={"contactCount": 7, "medianGapSeconds": 60},
            )
        ],
    )

    evidence = EvidenceNormalizer().normalize(incident)

    structured = next(item for item in evidence if item.ref_id == "observation:obs-42")
    assert structured.source == EvidenceSource.TEMPORAL_CHAIN
    assert structured.attributes["contactCount"] == 7
    assert all(item.source != EvidenceSource.RAW for item in evidence)


def test_masked_structured_evidence_does_not_mutate_request_model():
    item = EvidenceItem(
        ref_id="contact:alpha",
        source=EvidenceSource.TEMPORAL_CHAIN,
        kind="contact_aggregate",
        summary="alice@example.com contacted 198.51.100.20",
        attributes={"owner": "alice@example.com"},
    )
    incident = IncidentInput(
        incident_id="campaign-masked",
        privacy_mode="masked",
        structured_evidence=[item],
    )

    normalized = EvidenceNormalizer().normalize(incident)

    assert normalized[-1].summary != item.summary
    assert incident.structured_evidence[0].summary == "alice@example.com contacted 198.51.100.20"
