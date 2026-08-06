from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .audit import AuditStore
from .models import (
    DeceptionHitRequest,
    DeceptionTokenRequest,
    DeceptionTokenResponse,
    DeceptionTokenSummary,
    DeceptionTokenType,
    IncidentInput,
)


@dataclass(slots=True)
class ResolvedDeceptionHit:
    tenant_id: str
    token_id: str
    duplicate: bool
    incident: IncidentInput | None


class DeceptionService:
    """Defensive canary-token registry. Raw tokens are returned only at creation time."""

    def __init__(self, store: AuditStore, duplicate_window_seconds: int = 300) -> None:
        self._store = store
        self._duplicate_window = max(30, duplicate_window_seconds)

    def create_token(
        self,
        tenant_id: str,
        request: DeceptionTokenRequest,
    ) -> DeceptionTokenResponse:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=request.ttl_days)
        token_id = f"dt_{uuid.uuid4().hex[:20]}"
        raw_token = f"csd1_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self._store.create_deception_token(
            token_id=token_id,
            tenant_id=tenant_id,
            token_hash=token_hash,
            name=request.name,
            token_type=request.token_type.value,
            asset=request.asset,
            metadata=request.metadata,
            created_at_utc=now,
            expires_at_utc=expires,
        )
        self._store.append_audit(
            tenant_id,
            "deception.token.create",
            token_id,
            "success",
            {
                "name": request.name,
                "type": request.token_type.value,
                "asset": request.asset,
                "expires_at_utc": expires.isoformat(),
            },
        )
        return DeceptionTokenResponse(
            token_id=token_id,
            token=raw_token,
            name=request.name,
            token_type=request.token_type,
            asset=request.asset,
            created_at_utc=now,
            expires_at_utc=expires,
        )

    def list_tokens(self, tenant_id: str) -> list[DeceptionTokenSummary]:
        output: list[DeceptionTokenSummary] = []
        for row in self._store.list_deception_tokens(tenant_id):
            output.append(
                DeceptionTokenSummary(
                    token_id=row["token_id"],
                    name=row["name"],
                    token_type=DeceptionTokenType(row["token_type"]),
                    asset=row["asset"],
                    created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
                    expires_at_utc=datetime.fromisoformat(row["expires_at_utc"]),
                    active=bool(row["active"]),
                    hit_count=int(row["hit_count"] or 0),
                    last_hit_at_utc=(
                        datetime.fromisoformat(row["last_hit_at_utc"])
                        if row["last_hit_at_utc"]
                        else None
                    ),
                )
            )
        return output

    def revoke_token(self, tenant_id: str, token_id: str) -> bool:
        revoked = self._store.revoke_deception_token(tenant_id, token_id)
        self._store.append_audit(
            tenant_id,
            "deception.token.revoke",
            token_id,
            "success" if revoked else "not_found",
            {},
        )
        return revoked

    def resolve_hit(self, request: DeceptionHitRequest) -> ResolvedDeceptionHit | None:
        token_hash = hashlib.sha256(request.token.encode("utf-8")).hexdigest()
        row = self._store.resolve_deception_token(token_hash)
        if row is None:
            return None

        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(row["expires_at_utc"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            self._store.revoke_deception_token(row["tenant_id"], row["token_id"])
            return None

        fingerprint_payload = {
            "token_id": row["token_id"],
            "source_ip": request.source_ip,
            "source_host": request.source_host,
            "username": request.username,
            "process_name": request.process_name,
            "destination": request.destination,
            "context": request.context,
        }
        fingerprint = hashlib.sha256(
            json.dumps(fingerprint_payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()
        duplicate = self._store.recent_deception_hit_exists(
            row["token_id"],
            fingerprint,
            now - timedelta(seconds=self._duplicate_window),
        )
        if duplicate:
            return ResolvedDeceptionHit(
                tenant_id=row["tenant_id"],
                token_id=row["token_id"],
                duplicate=True,
                incident=None,
            )

        incident_id = f"deception-{row['token_id']}-{uuid.uuid4().hex[:10]}"
        metadata: dict[str, Any] = json.loads(row["metadata_json"] or "{}")
        hit = {
            "token_id": row["token_id"],
            "token_type": row["token_type"],
            "name": row["name"],
            "asset": row["asset"],
            "source_ip": request.source_ip,
            "source_host": request.source_host,
            "username": request.username,
            "process_name": request.process_name,
            "destination": request.destination,
            "timestamp_utc": request.timestamp_utc.isoformat(),
            "context": request.context,
            "metadata": metadata,
        }
        incident = IncidentInput(
            incident_id=incident_id,
            title=f"Deception tripwire: {row['name']}",
            rule_id="DECEPTION_TOKEN_HIT",
            severity="Critical",
            description=(
                f"A {row['token_type']} deception token associated with {row['asset'] or 'an asset'} "
                "was accessed. Validate immediately and preserve evidence."
            ),
            source_ip=request.source_ip,
            source_host=request.source_host,
            username=request.username,
            process_name=request.process_name,
            destination_host=request.destination or row["asset"],
            deception_hits=[hit],
            raw_evidence=[
                {
                    "ref_id": f"deception-context:{row['token_id']}",
                    "kind": "deception_context",
                    "summary": "Context supplied by the deception sensor",
                    "timestamp": request.timestamp_utc.isoformat(),
                    **request.context,
                }
            ] if request.context else [],
            first_seen=request.timestamp_utc,
            last_seen=request.timestamp_utc,
        )
        self._store.record_deception_hit(
            token_id=row["token_id"],
            tenant_id=row["tenant_id"],
            timestamp_utc=request.timestamp_utc,
            source_ip=request.source_ip,
            fingerprint=fingerprint,
            payload=hit,
            incident_id=incident_id,
        )
        self._store.append_audit(
            row["tenant_id"],
            "deception.hit",
            row["token_id"],
            "success",
            {"incident_id": incident_id, "source_ip": request.source_ip},
            actor="deception-sensor",
        )
        return ResolvedDeceptionHit(
            tenant_id=row["tenant_id"],
            token_id=row["token_id"],
            duplicate=False,
            incident=incident,
        )
