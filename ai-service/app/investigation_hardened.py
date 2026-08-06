from __future__ import annotations

import asyncio

from .investigation import InvestigationOrchestrator, InvestigationRequest, InvestigationResult
from .security import TenantContext


class InvestigationDeadlineExceeded(TimeoutError):
    """Raised when the full bounded investigation exceeds its declared budget."""


class HardenedInvestigationOrchestrator(InvestigationOrchestrator):
    """Apply an actual wall-clock deadline around planning, tools and synthesis.

    The base orchestrator already limits tool count and checks elapsed time between
    calls. This wrapper closes the remaining gap where a slow model or connector
    could block inside one call longer than the requested budget.
    """

    async def run(self, tenant: TenantContext, request: InvestigationRequest) -> InvestigationResult:
        try:
            async with asyncio.timeout(request.max_runtime_seconds):
                return await super().run(tenant, request)
        except TimeoutError as exc:
            # AuditStore is intentionally available on the base orchestrator.
            self._store.append_audit(
                tenant.tenant_id,
                "ai.investigation.run",
                request.incident.incident_id,
                "timeout",
                {
                    "max_runtime_seconds": request.max_runtime_seconds,
                    "max_steps": request.max_steps,
                    "reason": "hard_wall_clock_deadline",
                },
            )
            raise InvestigationDeadlineExceeded(
                f"investigation exceeded {request.max_runtime_seconds:.1f} seconds"
            ) from exc
