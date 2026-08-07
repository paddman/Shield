from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from statistics import median

import numpy as np
from sklearn.ensemble import IsolationForest

from .audit import AuditStore
from .behavioral_models import (
    BehavioralAnomalyResult,
    BehavioralBaselineStatus,
    BehavioralEngineStatus,
)
from .config import Settings
from .models import AnomalyObservationRequest, AnomalyResult, RiskSignal


@dataclass(slots=True)
class _TrainedBaseline:
    fingerprint: str
    feature_names: tuple[str, ...]
    medians: np.ndarray
    scales: np.ndarray
    model: IsolationForest | None
    baseline_scores: np.ndarray


class HybridAnomalyEngine:
    """Tenant-safe behavior model using cached Isolation Forest and robust deviation."""

    MODEL_VERSION = "behavioral-iforest-mad-v2"

    def __init__(self, store: AuditStore, settings: Settings) -> None:
        self._store = store
        self._min_samples = max(8, settings.anomaly_min_samples)
        self._max_samples = max(self._min_samples, settings.anomaly_max_samples)
        self._contamination = min(0.25, max(0.001, settings.anomaly_contamination))
        self._threshold = min(0.99, max(0.50, settings.anomaly_threshold))
        requested_learn_threshold = min(0.95, max(0.05, settings.anomaly_learn_threshold))
        self._learn_threshold = min(self._threshold - 0.05, requested_learn_threshold)
        self._warmup_guard_samples = min(
            self._min_samples,
            max(3, settings.anomaly_warmup_guard_samples),
        )
        self._n_estimators = min(512, max(32, settings.anomaly_n_estimators))
        self._cache_capacity = min(4_096, max(1, settings.anomaly_cache_size))
        self._relative_scale_floor = min(
            0.50,
            max(0.0, settings.anomaly_relative_scale_floor),
        )
        self._absolute_scale_floor = max(1e-12, settings.anomaly_absolute_scale_floor)
        self._cache: OrderedDict[tuple[str, str], _TrainedBaseline] = OrderedDict()
        self._cache_lock = threading.RLock()

    def score(
        self,
        tenant_id: str,
        request: AnomalyObservationRequest,
    ) -> AnomalyResult:
        profile = self._dimension(getattr(request, "profile", "generic"), "generic", 80)
        schema_version = self._dimension(
            getattr(request, "schema_version", "v1"),
            "v1",
            40,
        )
        storage_asset_id = self._storage_asset_id(
            request.asset_id,
            profile,
            schema_version,
        )
        baseline = self._store.load_observations(
            tenant_id=tenant_id,
            asset_id=storage_asset_id,
            limit=self._max_samples,
        )

        if len(baseline) < self._min_samples:
            return self._score_learning(
                tenant_id=tenant_id,
                request=request,
                profile=profile,
                schema_version=schema_version,
                storage_asset_id=storage_asset_id,
                baseline=baseline,
            )

        trained, cache_hit = self._get_or_train(
            tenant_id,
            storage_asset_id,
            baseline,
        )
        if trained.model is None:
            raise RuntimeError("ready baseline is missing its Isolation Forest model")

        current = np.asarray(
            [
                [
                    float(request.features.get(name, trained.medians[index]))
                    for index, name in enumerate(trained.feature_names)
                ]
            ],
            dtype=float,
        )
        current_score = float(-trained.model.score_samples(current)[0])
        isolation_score = self._isolation_score(
            current_score,
            trained.baseline_scores,
        )
        robust_score, robust_values = self._robust_score(current[0], trained)
        schema_score, missing_names, extra_names = self._schema_score(
            trained.feature_names,
            request.features,
        )
        combined = max(isolation_score, robust_score, schema_score * 0.65)
        learned = bool(request.learn and combined < self._learn_threshold)
        if learned:
            self._store.add_observation(
                tenant_id,
                storage_asset_id,
                request.timestamp_utc,
                request.features,
            )

        confidence = self._confidence(len(baseline), schema_score)
        contributors = self._contributors(
            robust_values,
            isolation_score=isolation_score,
            schema_score=schema_score,
            missing_names=missing_names,
            extra_names=extra_names,
        )
        baseline_samples = min(
            self._max_samples,
            len(baseline) + (1 if learned else 0),
        )
        return BehavioralAnomalyResult(
            asset_id=request.asset_id,
            profile=profile,
            schema_version=schema_version,
            state="ready",
            score=round(max(0.0, min(1.0, combined)), 4),
            confidence=round(confidence, 3),
            baseline_samples=baseline_samples,
            model=self.MODEL_VERSION,
            model_version=self.MODEL_VERSION,
            contributors=contributors,
            is_anomaly=combined >= self._threshold,
            threshold=self._threshold,
            learned=learned,
            baseline_rejected=bool(request.learn and not learned),
            component_scores={
                "isolation_forest": round(isolation_score, 4),
                "robust_deviation": round(robust_score, 4),
                "schema_drift": round(schema_score, 4),
            },
            feature_count=len(request.features),
            cache_hit=cache_hit,
        )

    def baseline_status(
        self,
        tenant_id: str,
        asset_id: str,
        profile: str = "generic",
        schema_version: str = "v1",
    ) -> BehavioralBaselineStatus:
        safe_profile = self._dimension(profile, "generic", 80)
        safe_schema = self._dimension(schema_version, "v1", 40)
        storage_asset_id = self._storage_asset_id(
            asset_id,
            safe_profile,
            safe_schema,
        )
        samples = len(
            self._store.load_observations(
                tenant_id,
                storage_asset_id,
                self._max_samples,
            )
        )
        return BehavioralBaselineStatus(
            asset_id=asset_id,
            profile=safe_profile,
            schema_version=safe_schema,
            state="ready" if samples >= self._min_samples else "learning",
            baseline_samples=samples,
            min_samples=self._min_samples,
            max_samples=self._max_samples,
            model_version=self.MODEL_VERSION,
        )

    def status(self) -> BehavioralEngineStatus:
        with self._cache_lock:
            cached_models = len(self._cache)
        return BehavioralEngineStatus(
            model_version=self.MODEL_VERSION,
            threshold=self._threshold,
            learn_threshold=self._learn_threshold,
            min_samples=self._min_samples,
            max_samples=self._max_samples,
            contamination=self._contamination,
            cached_models=cached_models,
            cache_capacity=self._cache_capacity,
        )

    def _score_learning(
        self,
        *,
        tenant_id: str,
        request: AnomalyObservationRequest,
        profile: str,
        schema_version: str,
        storage_asset_id: str,
        baseline: list[dict[str, float]],
    ) -> BehavioralAnomalyResult:
        robust_score = 0.0
        schema_score = 0.0
        robust_values: list[tuple[str, float, float]] = []
        missing_names: list[str] = []
        extra_names: list[str] = []

        if len(baseline) >= self._warmup_guard_samples:
            trained = self._train_baseline(
                baseline,
                fingerprint="warmup",
                fit_isolation=False,
            )
            current = np.asarray(
                [
                    float(request.features.get(name, trained.medians[index]))
                    for index, name in enumerate(trained.feature_names)
                ],
                dtype=float,
            )
            robust_score, robust_values = self._robust_score(current, trained)
            schema_score, missing_names, extra_names = self._schema_score(
                trained.feature_names,
                request.features,
            )

        combined = max(robust_score, schema_score * 0.65)
        learned = bool(request.learn and combined < self._learn_threshold)
        if learned:
            self._store.add_observation(
                tenant_id,
                storage_asset_id,
                request.timestamp_utc,
                request.features,
            )

        samples = min(self._max_samples, len(baseline) + (1 if learned else 0))
        return BehavioralAnomalyResult(
            asset_id=request.asset_id,
            profile=profile,
            schema_version=schema_version,
            state="learning",
            score=round(combined, 4),
            confidence=round(min(0.49, samples / self._min_samples * 0.49), 3),
            baseline_samples=samples,
            model=self.MODEL_VERSION,
            model_version=self.MODEL_VERSION,
            contributors=self._contributors(
                robust_values,
                isolation_score=0.0,
                schema_score=schema_score,
                missing_names=missing_names,
                extra_names=extra_names,
            ),
            is_anomaly=combined >= self._threshold,
            threshold=self._threshold,
            learned=learned,
            baseline_rejected=bool(request.learn and not learned),
            component_scores={
                "isolation_forest": 0.0,
                "robust_deviation": round(robust_score, 4),
                "schema_drift": round(schema_score, 4),
            },
            feature_count=len(request.features),
            cache_hit=False,
        )

    def _get_or_train(
        self,
        tenant_id: str,
        storage_asset_id: str,
        baseline: list[dict[str, float]],
    ) -> tuple[_TrainedBaseline, bool]:
        fingerprint = self._fingerprint(baseline)
        cache_key = (tenant_id, storage_asset_id)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.fingerprint == fingerprint:
                self._cache.move_to_end(cache_key)
                return cached, True

        trained = self._train_baseline(
            baseline,
            fingerprint=fingerprint,
            fit_isolation=True,
        )
        with self._cache_lock:
            self._cache[cache_key] = trained
            self._cache.move_to_end(cache_key)
            while len(self._cache) > self._cache_capacity:
                self._cache.popitem(last=False)
        return trained, False

    def _train_baseline(
        self,
        baseline: list[dict[str, float]],
        fingerprint: str,
        *,
        fit_isolation: bool,
    ) -> _TrainedBaseline:
        feature_names = tuple(sorted({name for row in baseline for name in row}))
        medians = np.asarray(
            [
                float(
                    median(
                        [float(row[name]) for row in baseline if name in row]
                        or [0.0]
                    )
                )
                for name in feature_names
            ],
            dtype=float,
        )
        matrix = np.asarray(
            [
                [
                    float(row.get(name, medians[index]))
                    for index, name in enumerate(feature_names)
                ]
                for row in baseline
            ],
            dtype=float,
        )
        scales = np.asarray(
            [
                self._robust_scale(matrix[:, index], medians[index])
                for index in range(len(feature_names))
            ],
            dtype=float,
        )

        model: IsolationForest | None = None
        baseline_scores = np.asarray([], dtype=float)
        if fit_isolation:
            model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=42,
                n_jobs=1,
            )
            model.fit(matrix)
            baseline_scores = -model.score_samples(matrix)

        return _TrainedBaseline(
            fingerprint=fingerprint,
            feature_names=feature_names,
            medians=medians,
            scales=scales,
            model=model,
            baseline_scores=baseline_scores,
        )

    def _robust_scale(self, values: np.ndarray, center: float) -> float:
        deviations = np.abs(values - center)
        mad_scale = 1.4826 * float(np.median(deviations))
        q25, q75 = np.percentile(values, [25, 75])
        iqr_scale = float(q75 - q25) / 1.349 if q75 > q25 else 0.0
        relative_floor = abs(float(center)) * self._relative_scale_floor
        return max(
            self._absolute_scale_floor,
            relative_floor,
            mad_scale,
            iqr_scale,
        )

    @staticmethod
    def _fingerprint(baseline: list[dict[str, float]]) -> str:
        payload = json.dumps(
            baseline,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _isolation_score(self, current: float, baseline: np.ndarray) -> float:
        tolerance = max(1e-12, abs(current) * 1e-9)
        lower = float(np.mean(baseline < current - tolerance))
        equal = float(np.mean(np.abs(baseline - current) <= tolerance))
        percentile = lower + 0.5 * equal
        cutoff = 1.0 - self._contamination

        if percentile <= 0.5:
            return 0.0
        if percentile <= cutoff:
            return self._threshold * (percentile - 0.5) / max(
                1e-9,
                cutoff - 0.5,
            )
        return self._threshold + (1.0 - self._threshold) * (
            percentile - cutoff
        ) / max(1e-9, 1.0 - cutoff)

    @staticmethod
    def _robust_score(
        current: np.ndarray,
        trained: _TrainedBaseline,
    ) -> tuple[float, list[tuple[str, float, float]]]:
        z_values = np.abs(current - trained.medians) / trained.scales
        ranked = sorted(
            [
                (
                    name,
                    float(z_values[index]),
                    float(current[index] - trained.medians[index]),
                )
                for index, name in enumerate(trained.feature_names)
            ],
            key=lambda item: item[1],
            reverse=True,
        )
        max_z = ranked[0][1] if ranked else 0.0
        score = 1.0 - math.exp(-max(0.0, max_z - 1.0) / 2.2)
        return max(0.0, min(1.0, score)), ranked

    @staticmethod
    def _schema_score(
        feature_names: tuple[str, ...],
        current_features: dict[str, float],
    ) -> tuple[float, list[str], list[str]]:
        baseline_names = set(feature_names)
        current_names = set(current_features)
        missing = sorted(baseline_names - current_names)
        extra = sorted(current_names - baseline_names)
        union_size = max(1, len(baseline_names | current_names))
        drift = (len(missing) + len(extra)) / union_size
        return max(0.0, min(1.0, drift)), missing, extra

    def _confidence(self, samples: int, schema_score: float) -> float:
        sample_confidence = 0.55 + min(
            0.40,
            samples / self._max_samples * 0.40,
        )
        schema_penalty = 1.0 - min(0.50, schema_score)
        return max(0.10, min(0.99, sample_confidence * schema_penalty))

    @staticmethod
    def _contributors(
        robust_values: list[tuple[str, float, float]],
        *,
        isolation_score: float,
        schema_score: float,
        missing_names: list[str],
        extra_names: list[str],
    ) -> list[RiskSignal]:
        contributors = [
            RiskSignal(
                name=name,
                score_delta=round(min(20.0, z * 2.0), 2),
                reason=(
                    f"Feature deviates {z:.2f} robust-z from baseline "
                    f"(delta={delta:.3g})"
                ),
                evidence_refs=[],
            )
            for name, z, delta in robust_values[:5]
            if z >= 2.0
        ]
        if isolation_score >= 0.75 and not contributors:
            contributors.append(
                RiskSignal(
                    name="isolation_forest",
                    score_delta=15.0,
                    reason="Multivariate behavior is outside the learned baseline",
                    evidence_refs=[],
                )
            )
        if schema_score > 0:
            detail: list[str] = []
            if missing_names:
                detail.append("missing=" + ",".join(missing_names[:5]))
            if extra_names:
                detail.append("extra=" + ",".join(extra_names[:5]))
            contributors.append(
                RiskSignal(
                    name="feature_schema_drift",
                    score_delta=round(min(15.0, schema_score * 15.0), 2),
                    reason=(
                        "Telemetry feature schema changed ("
                        + "; ".join(detail)
                        + ")"
                    ),
                    evidence_refs=[],
                )
            )
        return contributors[:6]

    @staticmethod
    def _dimension(value: object, default: str, max_length: int) -> str:
        normalized = str(value or default).strip().lower()
        normalized = re.sub(r"[^a-z0-9._-]+", "-", normalized).strip("._-")
        return (normalized or default)[:max_length]

    @staticmethod
    def _storage_asset_id(
        asset_id: str,
        profile: str,
        schema_version: str,
    ) -> str:
        if profile == "generic" and schema_version == "v1":
            return asset_id
        digest = hashlib.sha256(
            f"{profile}\0{schema_version}".encode("utf-8")
        ).hexdigest()[:12]
        return (
            f"{asset_id}::behavior::{profile[:40]}::"
            f"{schema_version[:24]}::{digest}"
        )
