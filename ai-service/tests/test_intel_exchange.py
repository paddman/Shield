from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.intel_exchange import (
    IndicatorType,
    IntelExchangeStore,
    IntelPublishRequest,
    canonicalize_indicator,
)


def _publish(store: IntelExchangeStore, tenant: str, incident: str, risk: int) -> None:
    store.publish(
        tenant,
        IntelPublishRequest(
            indicator_type=IndicatorType.IP,
            indicator="8.8.8.8",
            incident_id=incident,
            risk_score=risk,
            confidence=0.91,
            approved=True,
            approved_by="soc-analyst",
            first_seen_utc=datetime(2026, 8, 1, tzinfo=timezone.utc),
            last_seen_utc=datetime(2026, 8, 2, tzinfo=timezone.utc),
            tags=["scanner", "known-bad"],
            evidence_refs=[f"incident:{incident}"],
        ),
    )


def test_exchange_returns_aggregates_without_tenant_identity(settings):
    store = IntelExchangeStore(settings.database_path)
    _publish(store, "tenant-a", "inc-a", 82)
    _publish(store, "tenant-b", "inc-b", 94)

    result = store.lookup("tenant-a", IndicatorType.IP, "8.8.8.8")
    payload = result.model_dump_json()

    assert result.found is True
    assert result.observation_count == 2
    assert result.tenant_count == 2
    assert result.seen_by_other_tenants == 1
    assert result.max_risk_score == 94
    assert "tenant-a" not in payload
    assert "tenant-b" not in payload


def test_exchange_rejects_private_ip_and_unapproved_publication():
    with pytest.raises(ValueError):
        canonicalize_indicator(IndicatorType.IP, "10.0.0.7")

    with pytest.raises(ValidationError):
        IntelPublishRequest(
            indicator_type=IndicatorType.DOMAIN,
            indicator="malicious.example",
            incident_id="inc-1",
            risk_score=90,
            confidence=0.8,
            approved=False,
            approved_by="",
        )
