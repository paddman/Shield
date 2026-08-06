from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.investigation import InvestigationOrchestrator, InvestigationRequest
from app.investigation_hardened import (
    HardenedInvestigationOrchestrator,
    InvestigationDeadlineExceeded,
)
from app.models import IncidentInput
from app.routes_v2 import _require_intel_publisher
from app.security import TenantContext


def tenant(metadata=None) -> TenantContext:
    return TenantContext(
        tenant_id="tenant-a",
        name="Tenant A",
        central_url=None,
        central_api_key=None,
        central_verify_tls=True,
        metadata=metadata or {},
    )


def test_intel_publication_requires_operator_metadata():
    with pytest.raises(HTTPException) as exc:
        _require_intel_publisher(tenant({"role": "viewer"}))
    assert exc.value.status_code == 403

    assert _require_intel_publisher(
        tenant({"role": "operator", "principal": "soc-01"})
    ) == "soc-01"
    assert _require_intel_publisher(
        tenant({"can_publish_intel": True, "principal": "analyst-02"})
    ) == "analyst-02"


class FakeAuditStore:
    def __init__(self):
        self.rows = []

    def append_audit(self, *args, **kwargs):
        self.rows.append((args, kwargs))


@pytest.mark.asyncio
async def test_hardened_investigation_enforces_wall_clock_deadline(monkeypatch):
    async def slow_run(self, tenant_context, request):
        del self, tenant_context, request
        await asyncio.sleep(0.2)
        raise AssertionError("deadline wrapper failed")

    monkeypatch.setattr(InvestigationOrchestrator, "run", slow_run)
    orchestrator = HardenedInvestigationOrchestrator.__new__(HardenedInvestigationOrchestrator)
    orchestrator._store = FakeAuditStore()

    # Public API validation keeps the minimum at two seconds. model_copy is used
    # only to make this unit test complete in milliseconds.
    request = InvestigationRequest(
        incident=IncidentInput(incident_id="deadline-1", title="Slow connector"),
        max_runtime_seconds=2,
        max_steps=1,
    ).model_copy(update={"max_runtime_seconds": 0.05})

    with pytest.raises(InvestigationDeadlineExceeded):
        await orchestrator.run(tenant(), request)
    assert orchestrator._store.rows
    assert orchestrator._store.rows[0][0][3] == "timeout"
