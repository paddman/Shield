from __future__ import annotations

import hashlib

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.security import TenantRegistry


def test_tenant_key_and_hash_authentication(tmp_path):
    hashed = hashlib.sha256(b"secret-b").hexdigest()
    settings = Settings(
        environment="test",
        data_dir=tmp_path,
        database_path=tmp_path / "auth.db",
        allow_dev_tenant=False,
        tenants_json=(
            '[{"tenant_id":"a","api_key":"secret-a"},'
            f'{{"tenant_id":"b","api_key_sha256":"{hashed}"}}]'
        ),
        llm_enabled=False,
    )
    registry = TenantRegistry(settings)

    assert registry.authenticate("a", "secret-a").tenant_id == "a"
    assert registry.authenticate("b", "secret-b").tenant_id == "b"

    with pytest.raises(HTTPException):
        registry.authenticate("a", "wrong")
    with pytest.raises(HTTPException):
        registry.authenticate("missing", "whatever")
