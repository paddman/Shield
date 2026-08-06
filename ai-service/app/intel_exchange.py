from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .models import ApiModel


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    SHA256 = "sha256"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_BLOCKED_DOMAIN_SUFFIXES = (".local", ".lan", ".internal", ".localhost", ".invalid")


def canonicalize_indicator(indicator_type: IndicatorType | str, value: str) -> str:
    kind = IndicatorType(str(indicator_type))
    raw = value.strip()
    if not raw:
        raise ValueError("indicator is empty")

    if kind == IndicatorType.IP:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise ValueError("only public/global IP indicators may be shared across tenants")
        return address.compressed.lower()

    if kind == IndicatorType.DOMAIN:
        domain = raw.rstrip(".").lower()
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid internationalized domain") from exc
        if not _DOMAIN_RE.fullmatch(domain):
            raise ValueError("invalid domain indicator")
        if domain.endswith(_BLOCKED_DOMAIN_SUFFIXES):
            raise ValueError("internal domain suffix may not be shared")
        return domain

    if kind == IndicatorType.SHA256:
        if not _SHA256_RE.fullmatch(raw):
            raise ValueError("sha256 indicator must contain exactly 64 hexadecimal characters")
        return raw.lower()

    raise ValueError("unsupported indicator type")


class IntelPublishRequest(ApiModel):
    indicator_type: IndicatorType
    indicator: str = Field(min_length=1, max_length=512)
    incident_id: str = Field(min_length=1, max_length=200)
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: Literal["true_positive"] = "true_positive"
    approved: bool = False
    approved_by: str = Field(default="", max_length=200)
    first_seen_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list, max_length=30)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("indicator")
    @classmethod
    def strip_indicator(cls, value: str) -> str:
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(str(value).strip().lower()[:80] for value in values if str(value).strip()))

    @model_validator(mode="after")
    def validate_approval_and_time(self) -> "IntelPublishRequest":
        if not self.approved:
            raise ValueError("cross-tenant publication requires explicit analyst approval")
        if not self.approved_by.strip():
            raise ValueError("approved_by is required")
        if self.last_seen_utc < self.first_seen_utc:
            raise ValueError("last_seen_utc must be on or after first_seen_utc")
        self.indicator = canonicalize_indicator(self.indicator_type, self.indicator)
        return self


class IntelPublishResponse(ApiModel):
    accepted: bool
    indicator_type: IndicatorType
    indicator: str
    incident_id: str
    shared_fields: list[str]


class IntelReputation(ApiModel):
    indicator_type: IndicatorType
    indicator: str
    found: bool
    observation_count: int = 0
    tenant_count: int = 0
    seen_by_other_tenants: int = 0
    first_seen_utc: datetime | None = None
    last_seen_utc: datetime | None = None
    max_risk_score: int = 0
    average_confidence: float = 0.0
    tags: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    privacy_note: str = "Tenant identities and customer telemetry are never returned."


class IntelExchangeStore:
    """Approval-gated IOC exchange that exposes aggregates, never tenant identities."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._database_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ioc_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    verdict TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    first_seen_utc TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    UNIQUE(tenant_id, indicator_type, indicator, incident_id)
                );
                CREATE INDEX IF NOT EXISTS idx_ioc_lookup
                    ON ioc_observations(indicator_type, indicator, last_seen_utc DESC);
                CREATE INDEX IF NOT EXISTS idx_ioc_tenant_time
                    ON ioc_observations(tenant_id, last_seen_utc DESC);
                """
            )

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)

    def publish(self, tenant_id: str, request: IntelPublishRequest) -> IntelPublishResponse:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ioc_observations (
                    tenant_id, indicator_type, indicator, incident_id,
                    risk_score, confidence, verdict, approved_by,
                    first_seen_utc, last_seen_utc, tags_json,
                    evidence_refs_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, indicator_type, indicator, incident_id) DO UPDATE SET
                    risk_score=excluded.risk_score,
                    confidence=excluded.confidence,
                    verdict=excluded.verdict,
                    approved_by=excluded.approved_by,
                    first_seen_utc=MIN(ioc_observations.first_seen_utc, excluded.first_seen_utc),
                    last_seen_utc=MAX(ioc_observations.last_seen_utc, excluded.last_seen_utc),
                    tags_json=excluded.tags_json,
                    evidence_refs_json=excluded.evidence_refs_json,
                    created_at_utc=excluded.created_at_utc
                """,
                (
                    tenant_id,
                    request.indicator_type.value,
                    request.indicator,
                    request.incident_id,
                    request.risk_score,
                    request.confidence,
                    request.verdict,
                    request.approved_by,
                    request.first_seen_utc.isoformat(),
                    request.last_seen_utc.isoformat(),
                    self._json(request.tags),
                    self._json(request.evidence_refs),
                    now,
                ),
            )
        return IntelPublishResponse(
            accepted=True,
            indicator_type=request.indicator_type,
            indicator=request.indicator,
            incident_id=request.incident_id,
            shared_fields=[
                "indicator_type",
                "indicator",
                "risk_score",
                "confidence",
                "first_seen_utc",
                "last_seen_utc",
                "tags",
            ],
        )

    def lookup(
        self,
        requester_tenant_id: str,
        indicator_type: IndicatorType | str,
        indicator: str,
    ) -> IntelReputation:
        kind = IndicatorType(str(indicator_type))
        canonical = canonicalize_indicator(kind, indicator)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tenant_id, risk_score, confidence, first_seen_utc,
                       last_seen_utc, tags_json, evidence_refs_json
                FROM ioc_observations
                WHERE indicator_type=? AND indicator=?
                ORDER BY last_seen_utc DESC
                """,
                (kind.value, canonical),
            ).fetchall()

        if not rows:
            return IntelReputation(indicator_type=kind, indicator=canonical, found=False)

        tenants = {str(row["tenant_id"]) for row in rows}
        tags: list[str] = []
        evidence_count = 0
        for row in rows:
            try:
                tags.extend(str(item) for item in json.loads(row["tags_json"] or "[]"))
            except json.JSONDecodeError:
                pass
            try:
                evidence_count += len(json.loads(row["evidence_refs_json"] or "[]"))
            except (json.JSONDecodeError, TypeError):
                pass

        first_seen = min(datetime.fromisoformat(row["first_seen_utc"]) for row in rows)
        last_seen = max(datetime.fromisoformat(row["last_seen_utc"]) for row in rows)
        average_confidence = sum(float(row["confidence"]) for row in rows) / len(rows)
        own_present = requester_tenant_id in tenants
        return IntelReputation(
            indicator_type=kind,
            indicator=canonical,
            found=True,
            observation_count=len(rows),
            tenant_count=len(tenants),
            seen_by_other_tenants=max(0, len(tenants) - (1 if own_present else 0)),
            first_seen_utc=first_seen,
            last_seen_utc=last_seen,
            max_risk_score=max(int(row["risk_score"]) for row in rows),
            average_confidence=round(average_confidence, 4),
            tags=sorted(set(tags))[:30],
            evidence_count=evidence_count,
        )

    def purge_expired(self, retention_days: int = 365) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(30, retention_days))
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM ioc_observations WHERE last_seen_utc < ?",
                (cutoff.isoformat(),),
            )
            return int(cursor.rowcount or 0)
