from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .analyst import SentinelBrain
from .anomaly import HybridAnomalyEngine
from .audit import AuditStore
from .central_client import CherryCentralClient
from .deception import DeceptionService
from .config import get_settings
from .llm import OpenAICompatibleLlm
from .models import (
    AnalystDecision,
    DeceptionHitRequest,
    DeceptionHitResponse,
    DeceptionTokenRequest,
    DeceptionTokenResponse,
    DeceptionTokenSummary,
    AnomalyObservationRequest,
    AnomalyResult,
    FeedbackRequest,
    IncidentInput,
    MonthlyReportRequest,
    MonthlyReportResponse,
    ThreatHuntPlan,
    ThreatHuntRequest,
    UsageSummary,
)
from .playbooks import PlaybookRetriever
from .security import TenantContext, TenantRegistry, require_tenant

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ntshield.sentinel.brain")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.settings = settings
    app.state.store = AuditStore(settings.database_path)
    app.state.tenant_registry = TenantRegistry(settings)
    app.state.llm = OpenAICompatibleLlm(settings)
    app.state.anomaly = HybridAnomalyEngine(app.state.store, settings)
    app.state.playbooks = PlaybookRetriever(settings.playbook_dir)
    app.state.brain = SentinelBrain(
        settings=settings,
        store=app.state.store,
        anomaly_engine=app.state.anomaly,
        llm=app.state.llm,
        playbooks=app.state.playbooks,
    )
    app.state.central = CherryCentralClient(settings)
    app.state.deception = DeceptionService(app.state.store)
    logger.info(
        "NTShield Brain started tenants=%s model=%s mode=%s",
        app.state.tenant_registry.tenant_ids,
        settings.llm_model,
        settings.analysis_mode,
    )
    yield


app = FastAPI(
    title="NT Shield Brain",
    version=__version__,
    description=(
        "Evidence-grounded, multi-tenant AI SOC analyst for NT Shield, "
        "Suricata, Zeek and attack-surface telemetry."
    ),
    lifespan=lifespan,
)

if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-NTShield-Tenant", "X-NTShield-Api-Key"],
    )


@app.middleware("http")
async def request_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_payload_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "payload_too_large"},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid_content_length"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
async def health(request: Request) -> dict:
    llm_status = await request.app.state.llm.health()
    return {
        "status": "ok",
        "product": settings.app_name,
        "version": __version__,
        "utc": datetime.now(timezone.utc).isoformat(),
        "environment": settings.environment,
        "analysis_mode": settings.analysis_mode,
        "llm": llm_status,
    }


@app.get("/v1/status")
async def service_status(
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> dict:
    return {
        "tenant_id": tenant.tenant_id,
        "tenant_name": tenant.name,
        "central_configured": bool(tenant.central_url),
        "model": await request.app.state.llm.health(),
        "analysis_mode": settings.analysis_mode,
        "guardrails": {
            "evidence_reference_validation": True,
            "response_action_allowlist": True,
            "human_approval_for_destructive_actions": True,
            "tenant_isolation": True,
            "audit_log": True,
        },
    }


@app.post("/v1/incidents/analyze", response_model=AnalystDecision)
async def analyze_incident(
    incident: IncidentInput,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> AnalystDecision:
    try:
        return await request.app.state.brain.analyze(tenant.tenant_id, incident)
    except Exception as exc:
        request.app.state.store.append_audit(
            tenant.tenant_id,
            "ai.incident.analyze",
            incident.incident_id,
            "fail",
            {"error": str(exc)[:500]},
        )
        logger.exception("Incident analysis failed incident=%s", incident.incident_id)
        raise HTTPException(status_code=500, detail="analysis_failed") from exc


@app.post("/v1/central/incidents/{incident_id}/analyze", response_model=AnalystDecision)
async def analyze_central_incident(
    incident_id: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> AnalystDecision:
    if not tenant.central_url:
        raise HTTPException(status_code=409, detail="tenant_central_not_configured")
    try:
        incident = await request.app.state.central.get_incident(tenant, incident_id)
        return await request.app.state.brain.analyze(tenant.tenant_id, incident)
    except httpx.HTTPStatusError as exc:
        code = 404 if exc.response.status_code == 404 else 502
        raise HTTPException(status_code=code, detail="central_incident_fetch_failed") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="central_unreachable") from exc


@app.get("/v1/central/incidents")
async def list_central_incidents(
    request: Request,
    take: int = Query(default=100, ge=1, le=500),
    tenant: TenantContext = Depends(require_tenant),
) -> list[dict]:
    if not tenant.central_url:
        raise HTTPException(status_code=409, detail="tenant_central_not_configured")
    try:
        incidents = await request.app.state.central.list_incidents(tenant, take=take)
        return [item.model_dump(mode="json", by_alias=True) for item in incidents]
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="central_unreachable") from exc


@app.get("/v1/analyses/{incident_id}", response_model=AnalystDecision)
async def get_analysis(
    incident_id: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> AnalystDecision:
    result = request.app.state.store.get_analysis(tenant.tenant_id, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="analysis_not_found")
    return result


@app.get("/v1/analyses", response_model=list[AnalystDecision])
async def list_analyses(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    tenant: TenantContext = Depends(require_tenant),
) -> list[AnalystDecision]:
    return request.app.state.store.list_analyses(tenant.tenant_id, limit=limit)


@app.post("/v1/anomaly/observe", response_model=AnomalyResult)
async def observe_anomaly_baseline(
    payload: AnomalyObservationRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> AnomalyResult:
    result = request.app.state.anomaly.score(tenant.tenant_id, payload)
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "ml.anomaly.observe",
        payload.asset_id,
        "success",
        {"state": result.state, "score": result.score, "samples": result.baseline_samples},
    )
    return result


@app.post("/v1/deception/tokens", response_model=DeceptionTokenResponse, status_code=201)
async def create_deception_token(
    payload: DeceptionTokenRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> DeceptionTokenResponse:
    return request.app.state.deception.create_token(tenant.tenant_id, payload)


@app.get("/v1/deception/tokens", response_model=list[DeceptionTokenSummary])
async def list_deception_tokens(
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> list[DeceptionTokenSummary]:
    return request.app.state.deception.list_tokens(tenant.tenant_id)


@app.delete("/v1/deception/tokens/{token_id}")
async def revoke_deception_token(
    token_id: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> dict:
    if not request.app.state.deception.revoke_token(tenant.tenant_id, token_id):
        raise HTTPException(status_code=404, detail="deception_token_not_found")
    return {"revoked": True, "token_id": token_id}


@app.post("/v1/deception/hits", response_model=DeceptionHitResponse, status_code=202)
async def ingest_deception_hit(
    payload: DeceptionHitRequest,
    request: Request,
) -> DeceptionHitResponse:
    # The token itself is the bearer secret. Do not reveal whether an invalid token exists.
    if not payload.source_ip and request.client:
        payload = payload.model_copy(update={"source_ip": request.client.host})
    resolved = request.app.state.deception.resolve_hit(payload)
    if resolved is None:
        return DeceptionHitResponse(accepted=True, duplicate=False, incident_id=None)
    if resolved.duplicate or resolved.incident is None:
        return DeceptionHitResponse(accepted=True, duplicate=True, incident_id=None)
    decision = await request.app.state.brain.analyze(resolved.tenant_id, resolved.incident)
    return DeceptionHitResponse(
        accepted=True,
        duplicate=False,
        incident_id=decision.incident_id,
    )


@app.post("/v1/feedback", status_code=202)
async def submit_feedback(
    payload: FeedbackRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> dict:
    request.app.state.store.save_feedback(tenant.tenant_id, payload)
    request.app.state.store.append_audit(
        tenant.tenant_id,
        "ai.feedback",
        payload.incident_id,
        "success",
        {"verdict": payload.verdict, "analysis_id": payload.analysis_id},
    )
    return {"accepted": True, "incident_id": payload.incident_id}


@app.post("/v1/reports/monthly", response_model=MonthlyReportResponse)
async def generate_monthly_report(
    payload: MonthlyReportRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> MonthlyReportResponse:
    return await request.app.state.brain.generate_monthly_report(tenant.tenant_id, payload)


@app.post("/v1/hunt/plan", response_model=ThreatHuntPlan)
async def plan_threat_hunt(
    payload: ThreatHuntRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> ThreatHuntPlan:
    return await request.app.state.brain.plan_hunt(tenant.tenant_id, payload)


@app.get("/v1/playbooks/search")
async def search_playbooks(
    request: Request,
    q: str = Query(min_length=2, max_length=1000),
    top_k: int = Query(default=3, ge=1, le=10),
    tenant: TenantContext = Depends(require_tenant),
) -> list[dict]:
    del tenant
    return [
        {"name": item.name, "score": item.score, "excerpt": item.excerpt}
        for item in request.app.state.playbooks.retrieve(q, top_k=top_k)
    ]


@app.get("/v1/usage/{month}", response_model=UsageSummary)
async def usage_summary(
    month: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> UsageSummary:
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(status_code=400, detail="month_must_be_yyyy_mm")
    return request.app.state.store.usage_summary(tenant.tenant_id, month)
