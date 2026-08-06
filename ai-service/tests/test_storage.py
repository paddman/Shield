from __future__ import annotations

import pytest

from app.models import IncidentInput


@pytest.mark.asyncio
async def test_analysis_is_isolated_by_tenant(brain, store):
    incident = IncidentInput(incident_id="same-id", title="Test event", severity="Medium")
    decision_a = await brain.analyze("tenant-a", incident)
    decision_b = await brain.analyze("tenant-b", incident)

    assert store.get_analysis("tenant-a", "same-id").analysis_id == decision_a.analysis_id
    assert store.get_analysis("tenant-b", "same-id").analysis_id == decision_b.analysis_id
    assert decision_a.analysis_id != decision_b.analysis_id
