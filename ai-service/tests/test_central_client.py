from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.central_client import CherryCentralClient
from app.security import TenantContext


class RecordingAsyncClient:
    calls: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    async def __aenter__(self) -> "RecordingAsyncClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, int] | None = None,
    ) -> httpx.Response:
        self.calls.append({"url": url, "headers": headers, "params": params})
        payload: dict[str, str] | list[dict[str, str]]
        payload = [{"incidentId": "incident-a"}] if params is not None else {"incidentId": "incident-a"}
        return httpx.Response(200, json=payload, request=httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_central_requests_include_configured_brain_tenant(monkeypatch, settings) -> None:
    RecordingAsyncClient.calls = []
    monkeypatch.setattr("app.central_client.httpx.AsyncClient", RecordingAsyncClient)
    tenant = TenantContext(
        tenant_id="customer-a",
        name="Customer A",
        central_url="https://central.invalid:7443",
        central_api_key="operator-key",
        central_verify_tls=True,
        metadata={},
    )
    client = CherryCentralClient(settings)

    await client.get_incident(tenant, "incident-a")
    await client.list_incidents(tenant, take=25)

    assert len(RecordingAsyncClient.calls) == 2
    for call in RecordingAsyncClient.calls:
        assert call["headers"]["X-NTShield-Tenant"] == "customer-a"
        assert call["headers"]["X-NTShield-Api-Key"] == "operator-key"
