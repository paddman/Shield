from __future__ import annotations

from typing import Any

import httpx

from .config import Settings
from .models import IncidentInput
from .security import TenantContext


class CherryCentralClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def get_incident(self, tenant: TenantContext, incident_id: str) -> IncidentInput:
        if not tenant.central_url:
            raise ValueError("tenant_has_no_central_url")
        headers = {
            "Accept": "application/json",
            "X-NTShield-Tenant": tenant.tenant_id,
        }
        if tenant.central_api_key:
            headers["X-NTShield-Api-Key"] = tenant.central_api_key
        timeout = httpx.Timeout(
            connect=self._settings.central_connect_timeout_seconds,
            read=self._settings.central_read_timeout_seconds,
            write=10.0,
            pool=10.0,
        )
        async with httpx.AsyncClient(timeout=timeout, verify=tenant.central_verify_tls) as client:
            response = await client.get(
                f"{tenant.central_url}/api/v1/incidents/{incident_id}",
                headers=headers,
            )
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        return IncidentInput.model_validate(payload)

    async def list_incidents(self, tenant: TenantContext, take: int = 100) -> list[IncidentInput]:
        if not tenant.central_url:
            raise ValueError("tenant_has_no_central_url")
        headers = {
            "Accept": "application/json",
            "X-NTShield-Tenant": tenant.tenant_id,
        }
        if tenant.central_api_key:
            headers["X-NTShield-Api-Key"] = tenant.central_api_key
        timeout = httpx.Timeout(
            connect=self._settings.central_connect_timeout_seconds,
            read=self._settings.central_read_timeout_seconds,
            write=10.0,
            pool=10.0,
        )
        async with httpx.AsyncClient(timeout=timeout, verify=tenant.central_verify_tls) as client:
            response = await client.get(
                f"{tenant.central_url}/api/v1/incidents",
                params={"take": max(1, min(take, 500))},
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
        return [IncidentInput.model_validate(item) for item in payload]
