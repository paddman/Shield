from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.anomaly import HybridAnomalyEngine
from app.behavioral_models import BehavioralObservationRequest


def observation(
    asset_id: str,
    features: dict[str, float],
    minute: int,
    *,
    profile: str = "generic",
    schema_version: str = "v1",
    learn: bool = True,
) -> BehavioralObservationRequest:
    return BehavioralObservationRequest(
        asset_id=asset_id,
        profile=profile,
        schema_version=schema_version,
        features=features,
        learn=learn,
        timestamp_utc=datetime(2026, 8, 1, tzinfo=timezone.utc)
        + timedelta(minutes=minute),
    )


def train_network_baseline(
    engine: HybridAnomalyEngine,
    *,
    profile: str = "generic",
    schema_version: str = "v1",
) -> None:
    for index in range(12):
        engine.score(
            "tenant-a",
            observation(
                "web-01",
                {
                    "connections_per_minute": 95 + (index % 4),
                    "unique_destination_ports": 4 + (index % 2),
                    "failed_login_rate": index % 2,
                },
                index,
                profile=profile,
                schema_version=schema_version,
            ),
        )


def test_behavior_profiles_have_independent_baselines(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    train_network_baseline(engine, profile="network")

    auth_result = engine.score(
        "tenant-a",
        observation(
            "web-01",
            {"failed_logins": 1, "distinct_users": 1},
            20,
            profile="auth",
        ),
    )

    assert auth_result.state == "learning"
    assert auth_result.baseline_samples == 1
    assert engine.baseline_status("tenant-a", "web-01", "network").state == "ready"
    assert engine.baseline_status("tenant-a", "web-01", "auth").baseline_samples == 1


def test_warmup_guard_rejects_baseline_poisoning(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    for index in range(8):
        engine.score(
            "tenant-a",
            observation(
                "web-01",
                {
                    "connections_per_minute": 100 + (index % 2),
                    "unique_destination_ports": 4,
                },
                index,
            ),
        )

    poison = engine.score(
        "tenant-a",
        observation(
            "web-01",
            {
                "connections_per_minute": 9_999,
                "unique_destination_ports": 500,
            },
            9,
            learn=True,
        ),
    )

    assert poison.baseline_rejected is True
    assert poison.learned is False
    assert poison.baseline_samples == 8
    assert poison.score >= settings.anomaly_learn_threshold


def test_constant_feature_uses_scale_floor(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    for index in range(12):
        engine.score(
            "tenant-a",
            observation("db-01", {"cpu_percent": 100.0}, index),
        )

    small_change = engine.score(
        "tenant-a",
        observation(
            "db-01",
            {"cpu_percent": 100.2},
            20,
            learn=False,
        ),
    )

    assert small_change.score < settings.anomaly_threshold
    assert small_change.is_anomaly is False


def test_ready_model_is_cached_between_scores(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    train_network_baseline(engine)

    first = engine.score(
        "tenant-a",
        observation(
            "web-01",
            {
                "connections_per_minute": 96,
                "unique_destination_ports": 4,
                "failed_login_rate": 0,
            },
            20,
            learn=False,
        ),
    )
    second = engine.score(
        "tenant-a",
        observation(
            "web-01",
            {
                "connections_per_minute": 96,
                "unique_destination_ports": 4,
                "failed_login_rate": 0,
            },
            21,
            learn=False,
        ),
    )

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert engine.status().cached_models == 1


def test_schema_versions_do_not_mix(settings, store):
    engine = HybridAnomalyEngine(store, settings)
    train_network_baseline(engine, profile="network", schema_version="v1")

    new_schema = engine.score(
        "tenant-a",
        observation(
            "web-01",
            {"bytes_per_minute": 1_000},
            20,
            profile="network",
            schema_version="v2",
        ),
    )

    assert new_schema.state == "learning"
    assert new_schema.baseline_samples == 1
    assert engine.baseline_status(
        "tenant-a",
        "web-01",
        "network",
        "v1",
    ).state == "ready"
