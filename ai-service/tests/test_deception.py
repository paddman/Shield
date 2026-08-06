from __future__ import annotations

from app.deception import DeceptionService
from app.models import DeceptionHitRequest, DeceptionTokenRequest, DeceptionTokenType


def test_deception_token_is_returned_once_and_hit_creates_incident(store):
    service = DeceptionService(store, duplicate_window_seconds=300)
    token = service.create_token(
        "tenant-a",
        DeceptionTokenRequest(
            name="Finance backup credential",
            token_type=DeceptionTokenType.CANARY_CREDENTIAL,
            asset="backup-vault",
            ttl_days=30,
        ),
    )

    summaries = service.list_tokens("tenant-a")
    assert len(summaries) == 1
    assert summaries[0].token_id == token.token_id
    assert not hasattr(summaries[0], "token")

    hit = service.resolve_hit(
        DeceptionHitRequest(
            token=token.token,
            source_ip="10.9.0.7",
            source_host="unknown-host",
            process_name="powershell.exe",
            destination="backup-vault",
        )
    )
    assert hit is not None
    assert hit.tenant_id == "tenant-a"
    assert hit.duplicate is False
    assert hit.incident is not None
    assert hit.incident.severity == "Critical"
    assert hit.incident.deception_hits

    duplicate = service.resolve_hit(
        DeceptionHitRequest(
            token=token.token,
            source_ip="10.9.0.7",
            source_host="unknown-host",
            process_name="powershell.exe",
            destination="backup-vault",
        )
    )
    assert duplicate is not None
    assert duplicate.duplicate is True
    assert duplicate.incident is None


def test_invalid_deception_token_is_not_resolved(store):
    service = DeceptionService(store)
    assert service.resolve_hit(DeceptionHitRequest(token="x" * 24)) is None
