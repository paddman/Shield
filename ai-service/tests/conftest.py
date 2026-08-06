from __future__ import annotations

from pathlib import Path

import pytest

from app.analyst import SentinelBrain
from app.anomaly import HybridAnomalyEngine
from app.audit import AuditStore
from app.config import Settings
from app.llm import OpenAICompatibleLlm
from app.playbooks import PlaybookRetriever


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        data_dir=tmp_path,
        database_path=tmp_path / "brain.db",
        playbook_dir=Path(__file__).resolve().parents[1] / "playbooks",
        llm_enabled=False,
        allow_dev_tenant=True,
        anomaly_min_samples=12,
        anomaly_max_samples=100,
        analysis_mode="multi_agent",
    )


@pytest.fixture
def store(settings: Settings) -> AuditStore:
    return AuditStore(settings.database_path)


@pytest.fixture
def brain(settings: Settings, store: AuditStore) -> SentinelBrain:
    anomaly = HybridAnomalyEngine(store, settings)
    return SentinelBrain(
        settings=settings,
        store=store,
        anomaly_engine=anomaly,
        llm=OpenAICompatibleLlm(settings),
        playbooks=PlaybookRetriever(settings.playbook_dir),
    )
