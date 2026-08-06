from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NT Shield Brain"
    environment: Literal["development", "test", "production"] = "development"
    host: str = "0.0.0.0"
    port: int = 8088
    log_level: str = "INFO"

    data_dir: Path = Path("./data")
    database_path: Path = Path("./data/ntshield-brain.db")
    playbook_dir: Path = Path("./playbooks")

    tenants_json: str = "[]"
    allow_dev_tenant: bool = True
    dev_tenant_id: str = "demo"
    dev_api_key: str = "dev-change-me"

    llm_enabled: bool = True
    llm_base_url: str = "http://127.0.0.1:8000/v1"
    llm_api_key: str = "local"
    llm_model: str = "qwen3.5-9b"
    llm_timeout_seconds: float = 45.0
    llm_temperature: float = 0.1
    llm_max_tokens: int = 2200
    llm_json_response_format: bool = True
    llm_enable_thinking: bool = False

    analysis_mode: Literal["single", "multi_agent"] = "multi_agent"
    specialist_parallelism: int = 3
    max_evidence_items: int = 250
    max_evidence_chars: int = 80_000
    max_payload_bytes: int = 3_000_000

    code_scan_max_llm_findings: int = Field(default=80, ge=1, le=500)
    code_scan_max_llm_chars: int = Field(default=60_000, ge=5_000, le=500_000)
    code_scan_llm_max_tokens: int = Field(default=2800, ge=256, le=16_384)

    anomaly_min_samples: int = 20
    anomaly_max_samples: int = 500
    anomaly_contamination: float = 0.05

    central_connect_timeout_seconds: float = 8.0
    central_read_timeout_seconds: float = 30.0

    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    def prepare_paths(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_paths()
    return settings
