from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import AnomalyObservationRequest, AnomalyResult, ApiModel

_PROFILE_RE = r"^[a-z0-9][a-z0-9._-]{0,79}$"
_SCHEMA_RE = r"^[a-z0-9][a-z0-9._-]{0,39}$"


class BehavioralObservationRequest(AnomalyObservationRequest):
    """A numerical observation scoped to one behavior profile and schema."""

    features: dict[str, float] = Field(min_length=1, max_length=128)
    profile: str = Field(default="generic", pattern=_PROFILE_RE)
    schema_version: str = Field(default="v1", pattern=_SCHEMA_RE)

    @field_validator("profile", "schema_version", mode="before")
    @classmethod
    def normalize_dimension(cls, value: object) -> str:
        return str(value or "").strip().lower()


class BehavioralAnomalyResult(AnomalyResult):
    profile: str = "generic"
    schema_version: str = "v1"
    is_anomaly: bool = False
    threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    learned: bool = False
    baseline_rejected: bool = False
    component_scores: dict[str, float] = Field(default_factory=dict)
    feature_count: int = Field(default=0, ge=0)
    cache_hit: bool = False
    model_version: str = "behavioral-iforest-mad-v2"


class BehavioralBatchRequest(ApiModel):
    observations: list[BehavioralObservationRequest] = Field(min_length=1, max_length=250)


class BehavioralBatchResult(ApiModel):
    results: list[BehavioralAnomalyResult]
    anomalies: int = Field(ge=0)
    learned: int = Field(ge=0)


class BehavioralBaselineStatus(ApiModel):
    asset_id: str
    profile: str
    schema_version: str
    state: Literal["learning", "ready"]
    baseline_samples: int = Field(ge=0)
    min_samples: int = Field(ge=1)
    max_samples: int = Field(ge=1)
    model_version: str


class BehavioralEngineStatus(ApiModel):
    model_version: str
    threshold: float = Field(ge=0.0, le=1.0)
    learn_threshold: float = Field(ge=0.0, le=1.0)
    min_samples: int = Field(ge=1)
    max_samples: int = Field(ge=1)
    contamination: float = Field(gt=0.0, le=0.25)
    cached_models: int = Field(ge=0)
    cache_capacity: int = Field(ge=1)
