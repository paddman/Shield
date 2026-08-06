from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.anomaly import HybridAnomalyEngine
from app.models import AnomalyObservationRequest


def test_isolation_forest_flags_large_behavior_change(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)

    for index in range(14):
        result = engine.score(
            "tenant-a",
            AnomalyObservationRequest(
                asset_id="web-01",
                features={
                    "connections_per_minute": 95 + (index % 4),
                    "unique_destination_ports": 4 + (index % 2),
                    "failed_login_rate": index % 2,
                },
                learn=True,
                timestamp_utc=base + timedelta(minutes=index),
            ),
        )

    assert result.state in {"learning", "ready"}

    outlier = engine.score(
        "tenant-a",
        AnomalyObservationRequest(
            asset_id="web-01",
            features={
                "connections_per_minute": 4000,
                "unique_destination_ports": 421,
                "failed_login_rate": 120,
            },
            learn=False,
            timestamp_utc=base + timedelta(hours=1),
        ),
    )

    assert outlier.state == "ready"
    assert outlier.score >= 0.8
    assert outlier.contributors
