from __future__ import annotations

import pytest

from app.models import IncidentInput, NON_DESTRUCTIVE_ACTIONS


@pytest.mark.asyncio
async def test_fallback_is_grounded_and_destructive_actions_require_approval(brain):
    incident = IncidentInput(
        incident_id="inc-spray-1",
        title="Password Spray Then Success",
        severity="High",
        source_ip="10.0.10.25",
        destination_ip="10.0.20.10",
        username="svc-backup",
        failed_attempts=54,
        distinct_usernames=12,
        successful_login_detected=True,
        evidence_events=[
            {
                "eventId": 4625,
                "eventRecordId": 1001,
                "timestampUtc": "2026-08-02T12:00:00Z",
                "sourceIp": "10.0.10.25",
                "username": "administrator",
            },
            {
                "eventId": 4624,
                "eventRecordId": 1002,
                "timestampUtc": "2026-08-02T12:01:00Z",
                "sourceIp": "10.0.10.25",
                "username": "svc-backup",
            },
        ],
    )

    decision = await brain.analyze("tenant-a", incident)

    valid_refs = {"incident:inc-spray-1", "win:1001", "win:1002"}
    assert decision.deterministic_fallback is True
    assert decision.risk_score >= 70
    assert decision.evidence
    assert {item.ref_id for item in decision.evidence}.issubset(valid_refs)
    assert decision.recommended_actions
    for action in decision.recommended_actions:
        if action.action not in NON_DESTRUCTIVE_ACTIONS:
            assert action.requires_human_approval is True


@pytest.mark.asyncio
async def test_deception_hit_sets_critical_floor(brain):
    decision = await brain.analyze(
        "tenant-a",
        IncidentInput(
            incident_id="decoy-1",
            title="Honey credential accessed",
            severity="Low",
            source_ip="10.1.2.3",
            deception_hits=[{"token_id": "canary-77", "source_ip": "10.1.2.3", "asset": "fake-share"}],
        ),
    )
    assert decision.risk_score >= 90
    assert "deception" in decision.classification.lower()
