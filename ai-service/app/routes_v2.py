from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .config import get_settings
from .intel_exchange import (
    IndicatorType,
    IntelExchangeStore,
    IntelPublishRequest,
    IntelPublishResponse,
    IntelReputation,
)
from .investigation import InvestigationRequest, InvestigationResult
from .investigation_hardened import (
    HardenedInvestigationOrchestrator,
    InvestigationDeadlineExceeded,
)
from .security import TenantContext, require_tenant

router = APIRouter(prefix="/v1", tags=["NT SHIELD gap closure"])


def _intel(request: Request) -> IntelExchangeStore:
    if not hasattr(request.app.state, "intel_exchange"):
        request.app.state.intel_exchange = IntelExchangeStore(get_settings().database_path)
    return request.app.state.intel_exchange


def _investigator(request: Request) -> HardenedInvestigationOrchestrator:
    if not hasattr(request.app.state, "investigation_orchestrator"):
        request.app.state.investigation_orchestrator = HardenedInvestigationOrchestrator(
            brain=request.app.state.brain,
            store=request.app.state.store,
            intel=_intel(request),
            central=request.app.state.central,
            llm=request.app.state.llm,
            playbooks=request.app.state.playbooks,
        )
    return request.app.state.investigation_orchestrator


def _require_intel_publisher(tenant: TenantContext) -> str:
    metadata = tenant.metadata or {}
    role = str(metadata.get("role") or "").strip().lower()
    allowed = bool(metadata.get("can_publish_intel")) or role in {
        "admin",
        "operator",
        "soc",
        "soc_analyst",
    }
    if not allowed:
        raise HTTPException(status_code=403, detail="intel_publish_requires_operator_role")
    return str(metadata.get("principal") or metadata.get("operator_id") or role or "operator")[:200]


@router.post("/intel/observations", response_model=IntelPublishResponse, status_code=201)
async def publish_approved_indicator(
    payload: IntelPublishRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> IntelPublishResponse:
    principal = _require_intel_publisher(tenant)
    result = _intel(request).publish(tenant.tenant_id, payload)
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "intel.exchange.publish",
        f"{payload.indicator_type.value}:{payload.indicator}",
        "success",
        {
            "incident_id": payload.incident_id,
            "risk_score": payload.risk_score,
            "confidence": payload.confidence,
            "approved_by": payload.approved_by,
            "authenticated_principal": principal,
            "shared_fields": result.shared_fields,
        },
        actor=f"operator:{principal}",
    )
    return result


@router.get("/intel/lookup", response_model=IntelReputation)
async def lookup_approved_indicator(
    request: Request,
    indicator_type: IndicatorType = Query(...),
    indicator: str = Query(min_length=1, max_length=512),
    tenant: TenantContext = Depends(require_tenant),
) -> IntelReputation:
    try:
        result = _intel(request).lookup(tenant.tenant_id, indicator_type, indicator)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "intel.exchange.lookup",
        f"{result.indicator_type.value}:{result.indicator}",
        "success",
        {
            "found": result.found,
            "tenant_count": result.tenant_count,
            "other_tenants": result.seen_by_other_tenants,
        },
    )
    return result


@router.post("/investigations/run", response_model=InvestigationResult)
async def run_bounded_investigation(
    payload: InvestigationRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> InvestigationResult:
    try:
        return await _investigator(request).run(tenant, payload)
    except InvestigationDeadlineExceeded as exc:
        raise HTTPException(status_code=504, detail="investigation_deadline_exceeded") from exc
    except Exception as exc:
        request.app.state.store.append_audit(
            tenant.tenant_id,
            "ai.investigation.run",
            payload.incident.incident_id,
            "fail",
            {"error": str(exc)[:500]},
        )
        raise HTTPException(status_code=500, detail="investigation_failed") from exc


@router.get("/readiness")
async def readiness(
    tenant: TenantContext = Depends(require_tenant),
) -> dict:
    del tenant
    return {
        "implemented": [
            "endpoint and network evidence normalization",
            "local Qwen evidence-grounded analysis",
            "bounded read-only investigation with a hard wall-clock deadline",
            "per-asset behavioral anomaly baseline",
            "human-approved response recommendations",
            "threat graph",
            "operator-approved privacy-preserving IOC exchange",
            "deception tripwires",
            "audit, feedback and usage metering",
        ],
        "pilot_validation_required": [
            "production PostgreSQL tenant isolation and row-level security",
            "web dashboard integration with the separate Suricata/Zeek application",
            "scheduled hunting and scheduled report delivery",
            "distributed rate limiting, abuse monitoring and tenant quota enforcement",
            "customer-specific retention and capacity tests",
            "Windows Server 2012/2012 R2 compatibility on golden images",
        ],
        "safety_boundary": (
            "AI and investigation tools are read-only. Any blocking, isolation, account, process or "
            "service action remains behind NT Shield Central operator approval."
        ),
    }
