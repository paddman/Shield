from __future__ import annotations

import math
from statistics import median

import numpy as np
from sklearn.ensemble import IsolationForest

from .audit import AuditStore
from .config import Settings
from .models import AnomalyObservationRequest, AnomalyResult, RiskSignal


class HybridAnomalyEngine:
    """Per-tenant, per-asset behavioral baseline using Isolation Forest + robust MAD."""

    def __init__(self, store: AuditStore, settings: Settings) -> None:
        self._store = store
        self._min_samples = max(8, settings.anomaly_min_samples)
        self._max_samples = max(self._min_samples, settings.anomaly_max_samples)
        self._contamination = min(0.25, max(0.001, settings.anomaly_contamination))

    def score(
        self,
        tenant_id: str,
        request: AnomalyObservationRequest,
    ) -> AnomalyResult:
        baseline = self._store.load_observations(
            tenant_id=tenant_id,
            asset_id=request.asset_id,
            limit=self._max_samples,
        )

        if len(baseline) < self._min_samples:
            if request.learn:
                self._store.add_observation(
                    tenant_id,
                    request.asset_id,
                    request.timestamp_utc,
                    request.features,
                )
            return AnomalyResult(
                asset_id=request.asset_id,
                state="learning",
                score=0.0,
                confidence=round(len(baseline) / self._min_samples, 2),
                baseline_samples=len(baseline),
                model="isolation_forest+robust_mad",
                contributors=[],
            )

        feature_names = sorted(set(request.features).union(*(item.keys() for item in baseline)))
        medians = {
            name: median([float(row[name]) for row in baseline if name in row] or [0.0])
            for name in feature_names
        }
        matrix = np.asarray(
            [[float(row.get(name, medians[name])) for name in feature_names] for row in baseline],
            dtype=float,
        )
        current = np.asarray(
            [[float(request.features.get(name, medians[name])) for name in feature_names]],
            dtype=float,
        )

        model = IsolationForest(
            n_estimators=160,
            contamination=self._contamination,
            random_state=42,
            n_jobs=1,
        )
        model.fit(matrix)
        baseline_anomaly = -model.score_samples(matrix)
        current_anomaly = float(-model.score_samples(current)[0])
        percentile = float(np.mean(baseline_anomaly <= current_anomaly))
        isolation_score = max(0.0, min(1.0, (percentile - 0.5) * 2.0))

        robust_values: list[tuple[str, float, float]] = []
        for index, name in enumerate(feature_names):
            values = [float(row.get(name, medians[name])) for row in baseline]
            center = float(median(values))
            deviations = [abs(value - center) for value in values]
            mad = float(median(deviations))
            scale = max(1e-9, 1.4826 * mad)
            z = abs(float(current[0, index]) - center) / scale
            robust_values.append((name, z, float(current[0, index]) - center))

        robust_values.sort(key=lambda item: item[1], reverse=True)
        max_z = robust_values[0][1] if robust_values else 0.0
        mad_score = 1.0 - math.exp(-max_z / 4.0)
        combined = max(isolation_score, mad_score)
        confidence = min(0.99, 0.55 + min(0.35, len(baseline) / self._max_samples * 0.35))

        contributors = [
            RiskSignal(
                name=name,
                score_delta=round(min(20.0, z * 2.0), 2),
                reason=f"Feature deviates {z:.2f} robust-z from baseline (delta={delta:.3g})",
                evidence_refs=[],
            )
            for name, z, delta in robust_values[:5]
            if z >= 2.0
        ]

        if request.learn and combined < 0.8:
            # Avoid poisoning a stable baseline with a very strong outlier.
            self._store.add_observation(
                tenant_id,
                request.asset_id,
                request.timestamp_utc,
                request.features,
            )

        return AnomalyResult(
            asset_id=request.asset_id,
            state="ready",
            score=round(max(0.0, min(1.0, combined)), 4),
            confidence=round(confidence, 3),
            baseline_samples=len(baseline),
            model="isolation_forest+robust_mad",
            contributors=contributors,
        )
