from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from .behavioral_models import (
    BehavioralAnomalyResult,
    BehavioralBaselineStatus,
    BehavioralBatchRequest,
    BehavioralBatchResult,
    BehavioralEngineStatus,
    BehavioralObservationRequest,
)
from .security import TenantContext, require_tenant

router = APIRouter(prefix="/v1/anomaly/behavioral", tags=["Behavioral ML"])


@router.get("/status", response_model=BehavioralEngineStatus)
def behavioral_ml_status(
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> BehavioralEngineStatus:
    del tenant
    return request.app.state.anomaly.status()


@router.get("/baselines/{asset_id}", response_model=BehavioralBaselineStatus)
def behavioral_baseline_status(
    asset_id: str,
    request: Request,
    profile: str = Query(default="generic", min_length=1, max_length=80),
    schema_version: str = Query(default="v1", min_length=1, max_length=40),
    tenant: TenantContext = Depends(require_tenant),
) -> BehavioralBaselineStatus:
    return request.app.state.anomaly.baseline_status(
        tenant.tenant_id,
        asset_id,
        profile,
        schema_version,
    )


@router.post("/observe", response_model=BehavioralAnomalyResult)
def observe_behavior(
    payload: BehavioralObservationRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> BehavioralAnomalyResult:
    raw_result = request.app.state.anomaly.score(tenant.tenant_id, payload)
    result = BehavioralAnomalyResult.model_validate(raw_result.model_dump())
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "ml.behavioral.observe",
        payload.asset_id,
        "success",
        {
            "profile": result.profile,
            "schema_version": result.schema_version,
            "state": result.state,
            "score": result.score,
            "is_anomaly": result.is_anomaly,
            "learned": result.learned,
            "samples": result.baseline_samples,
            "model": result.model_version,
        },
    )
    return result


@router.post("/observe/batch", response_model=BehavioralBatchResult)
def observe_behavior_batch(
    payload: BehavioralBatchRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> BehavioralBatchResult:
    results = [
        BehavioralAnomalyResult.model_validate(
            request.app.state.anomaly.score(
                tenant.tenant_id,
                observation,
            ).model_dump()
        )
        for observation in payload.observations
    ]
    response = BehavioralBatchResult(
        results=results,
        anomalies=sum(1 for result in results if result.is_anomaly),
        learned=sum(1 for result in results if result.learned),
    )
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "ml.behavioral.observe_batch",
        None,
        "success",
        {
            "observations": len(results),
            "anomalies": response.anomalies,
            "learned": response.learned,
        },
    )
    return response
