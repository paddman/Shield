from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Settings


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(min_length=1, max_length=120)
    name: str = Field(default="", max_length=300)
    api_key: str | None = None
    api_key_sha256: str | None = None
    central_url: str | None = None
    central_api_key: str | None = None
    central_verify_tls: bool = True
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    name: str
    central_url: str | None
    central_api_key: str | None
    central_verify_tls: bool
    metadata: dict[str, Any]


class TenantRegistry:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tenants = self._load(settings)

    @staticmethod
    def _load(settings: Settings) -> dict[str, TenantConfig]:
        try:
            raw = json.loads(settings.tenants_json or "[]")
        except json.JSONDecodeError as exc:
            raise RuntimeError("NTSHIELD_TENANTS_JSON is not valid JSON") from exc

        if isinstance(raw, dict):
            raw = raw.get("tenants", [])
        if not isinstance(raw, list):
            raise RuntimeError("NTSHIELD_TENANTS_JSON must be a JSON list")

        configs: list[TenantConfig] = []
        for item in raw:
            try:
                configs.append(TenantConfig.model_validate(item))
            except ValidationError as exc:
                raise RuntimeError(f"Invalid tenant configuration: {exc}") from exc

        if not configs and settings.allow_dev_tenant and settings.environment != "production":
            configs.append(
                TenantConfig(
                    tenant_id=settings.dev_tenant_id,
                    name="NT Shield Demo",
                    api_key=settings.dev_api_key,
                    central_verify_tls=False,
                )
            )

        return {cfg.tenant_id: cfg for cfg in configs if cfg.enabled}

    @property
    def tenant_ids(self) -> list[str]:
        return sorted(self._tenants)

    def authenticate(self, tenant_id: str, api_key: str) -> TenantContext:
        cfg = self._tenants.get(tenant_id)
        if cfg is None or not cfg.enabled:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown_tenant")

        supplied = api_key.encode("utf-8", errors="ignore")
        valid = False
        if cfg.api_key is not None:
            valid = hmac.compare_digest(supplied, cfg.api_key.encode("utf-8"))
        elif cfg.api_key_sha256 is not None:
            digest = hashlib.sha256(supplied).hexdigest()
            valid = hmac.compare_digest(digest, cfg.api_key_sha256.lower())

        if not valid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_api_key")

        return TenantContext(
            tenant_id=cfg.tenant_id,
            name=cfg.name or cfg.tenant_id,
            central_url=cfg.central_url.rstrip("/") if cfg.central_url else None,
            central_api_key=cfg.central_api_key,
            central_verify_tls=cfg.central_verify_tls,
            metadata=dict(cfg.metadata),
        )


async def require_tenant(
    request: Request,
    x_ntshield_tenant: str = Header(..., alias="X-NTShield-Tenant"),
    x_ntshield_api_key: str = Header(..., alias="X-NTShield-Api-Key"),
) -> TenantContext:
    registry: TenantRegistry = request.app.state.tenant_registry
    return registry.authenticate(x_ntshield_tenant, x_ntshield_api_key)
