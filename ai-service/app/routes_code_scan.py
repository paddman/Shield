from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .code_scan import CodeScanAnalyzer, CodeScanStore
from .code_scan_models import CodeScanAnalysis, CodeScanListItem, CodeScanRequest
from .security import TenantContext, require_tenant

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/code-scans", tags=["code-scans"])
_service_lock = threading.Lock()


def _service(request: Request) -> CodeScanAnalyzer:
    current = getattr(request.app.state, "code_scan_analyzer", None)
    if current is not None:
        return current
    with _service_lock:
        current = getattr(request.app.state, "code_scan_analyzer", None)
        if current is None:
            store = CodeScanStore(request.app.state.settings.database_path)
            current = CodeScanAnalyzer(
                settings=request.app.state.settings,
                audit_store=request.app.state.store,
                llm=request.app.state.llm,
                store=store,
            )
            request.app.state.code_scan_store = store
            request.app.state.code_scan_analyzer = current
    return current


@router.post("/analyze", response_model=CodeScanAnalysis)
async def analyze_code_scan(
    payload: CodeScanRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> CodeScanAnalysis:
    try:
        return await _service(request).analyze(tenant.tenant_id, payload)
    except Exception as exc:
        request.app.state.store.append_audit(
            tenant.tenant_id,
            "ai.code_scan.analyze",
            payload.scan_id,
            "fail",
            {"error": str(exc)[:500], "project": payload.project.name},
        )
        logger.exception("Code scan analysis failed scan=%s", payload.scan_id)
        raise HTTPException(status_code=500, detail="code_scan_analysis_failed") from exc


@router.get("", response_model=list[CodeScanListItem])
async def list_code_scans(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    tenant: TenantContext = Depends(require_tenant),
) -> list[CodeScanListItem]:
    return _service(request).list(tenant.tenant_id, limit)


@router.get("/{scan_id}", response_model=CodeScanAnalysis)
async def get_code_scan(
    scan_id: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant),
) -> CodeScanAnalysis:
    if len(scan_id) > 160:
        raise HTTPException(status_code=400, detail="invalid_scan_id")
    result = _service(request).get(tenant.tenant_id, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="code_scan_not_found")
    return result
