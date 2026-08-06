from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AnalystDecision, FeedbackRequest, UsageSummary


class AuditStore:
    """Small durable store for analyses, audit events, feedback and ML baselines."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._database_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    tenant_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    analysis_id TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    model TEXT NOT NULL,
                    analysis_mode TEXT NOT NULL,
                    deterministic_fallback INTEGER NOT NULL,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    llm_calls INTEGER NOT NULL DEFAULT 0,
                    request_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, incident_id)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_analysis_id
                    ON analyses(tenant_id, analysis_id);
                CREATE INDEX IF NOT EXISTS idx_analyses_created
                    ON analyses(tenant_id, created_at_utc DESC);

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    outcome TEXT NOT NULL,
                    detail_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
                    ON audit_log(tenant_id, timestamp_utc DESC);

                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    analysis_id TEXT,
                    verdict TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    approved_actions_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_feedback_tenant_incident
                    ON feedback(tenant_id, incident_id, created_at_utc DESC);

                CREATE TABLE IF NOT EXISTS anomaly_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    features_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_anomaly_asset_time
                    ON anomaly_observations(tenant_id, asset_id, timestamp_utc DESC);

                CREATE TABLE IF NOT EXISTS deception_tokens (
                    token_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_deception_tokens_tenant
                    ON deception_tokens(tenant_id, active, created_at_utc DESC);

                CREATE TABLE IF NOT EXISTS deception_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    source_ip TEXT,
                    fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    incident_id TEXT,
                    FOREIGN KEY(token_id) REFERENCES deception_tokens(token_id)
                );
                CREATE INDEX IF NOT EXISTS idx_deception_hits_token_time
                    ON deception_hits(token_id, timestamp_utc DESC);
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()}
            if "llm_calls" not in columns:
                conn.execute("ALTER TABLE analyses ADD COLUMN llm_calls INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)

    def append_audit(
        self,
        tenant_id: str,
        action: str,
        target: str | None,
        outcome: str,
        detail: dict[str, Any] | None = None,
        actor: str = "api",
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (tenant_id, timestamp_utc, actor, action, target, outcome, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                    action,
                    target,
                    outcome,
                    self._json(detail or {}),
                ),
            )

    def save_analysis(
        self,
        tenant_id: str,
        request_payload: dict[str, Any],
        analysis: AnalystDecision,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analyses (
                    tenant_id, incident_id, analysis_id, created_at_utc,
                    model, analysis_mode, deterministic_fallback,
                    prompt_tokens, completion_tokens, llm_calls, request_json, analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, incident_id) DO UPDATE SET
                    analysis_id=excluded.analysis_id,
                    created_at_utc=excluded.created_at_utc,
                    model=excluded.model,
                    analysis_mode=excluded.analysis_mode,
                    deterministic_fallback=excluded.deterministic_fallback,
                    prompt_tokens=excluded.prompt_tokens,
                    completion_tokens=excluded.completion_tokens,
                    llm_calls=excluded.llm_calls,
                    request_json=excluded.request_json,
                    analysis_json=excluded.analysis_json
                """,
                (
                    tenant_id,
                    analysis.incident_id,
                    analysis.analysis_id,
                    analysis.created_at_utc.isoformat(),
                    analysis.model,
                    analysis.analysis_mode,
                    1 if analysis.deterministic_fallback else 0,
                    analysis.prompt_tokens,
                    analysis.completion_tokens,
                    analysis.llm_calls,
                    self._json(request_payload),
                    analysis.model_dump_json(by_alias=True),
                ),
            )

    def get_analysis(self, tenant_id: str, incident_id: str) -> AnalystDecision | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM analyses WHERE tenant_id=? AND incident_id=?",
                (tenant_id, incident_id),
            ).fetchone()
        if row is None:
            return None
        return AnalystDecision.model_validate_json(row["analysis_json"])

    def list_analyses(self, tenant_id: str, limit: int = 50) -> list[AnalystDecision]:
        safe_limit = max(1, min(limit, 500))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT analysis_json FROM analyses
                WHERE tenant_id=?
                ORDER BY created_at_utc DESC
                LIMIT ?
                """,
                (tenant_id, safe_limit),
            ).fetchall()
        return [AnalystDecision.model_validate_json(row["analysis_json"]) for row in rows]

    def save_feedback(self, tenant_id: str, feedback: FeedbackRequest) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO feedback (
                    tenant_id, incident_id, analysis_id, verdict, notes,
                    approved_actions_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    feedback.incident_id,
                    feedback.analysis_id,
                    feedback.verdict,
                    feedback.notes,
                    self._json([action.value for action in feedback.approved_actions]),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def add_observation(
        self,
        tenant_id: str,
        asset_id: str,
        timestamp_utc: datetime,
        features: dict[str, float],
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_observations
                    (tenant_id, asset_id, timestamp_utc, features_json)
                VALUES (?, ?, ?, ?)
                """,
                (tenant_id, asset_id, timestamp_utc.isoformat(), self._json(features)),
            )

    def load_observations(
        self,
        tenant_id: str,
        asset_id: str,
        limit: int,
    ) -> list[dict[str, float]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT features_json FROM anomaly_observations
                WHERE tenant_id=? AND asset_id=?
                ORDER BY timestamp_utc DESC
                LIMIT ?
                """,
                (tenant_id, asset_id, max(1, limit)),
            ).fetchall()
        result: list[dict[str, float]] = []
        for row in reversed(rows):
            raw = json.loads(row["features_json"])
            result.append({str(k): float(v) for k, v in raw.items()})
        return result


    def create_deception_token(
        self,
        *,
        token_id: str,
        tenant_id: str,
        token_hash: str,
        name: str,
        token_type: str,
        asset: str,
        metadata: dict[str, Any],
        created_at_utc: datetime,
        expires_at_utc: datetime,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO deception_tokens (
                    token_id, tenant_id, token_hash, name, token_type, asset,
                    metadata_json, created_at_utc, expires_at_utc, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    token_id,
                    tenant_id,
                    token_hash,
                    name,
                    token_type,
                    asset,
                    self._json(metadata),
                    created_at_utc.isoformat(),
                    expires_at_utc.isoformat(),
                ),
            )

    def list_deception_tokens(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT t.*,
                       COUNT(h.id) AS hit_count,
                       MAX(h.timestamp_utc) AS last_hit_at_utc
                FROM deception_tokens t
                LEFT JOIN deception_hits h ON h.token_id=t.token_id
                WHERE t.tenant_id=?
                GROUP BY t.token_id
                ORDER BY t.created_at_utc DESC
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def resolve_deception_token(self, token_hash: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM deception_tokens
                WHERE token_hash=? AND active=1
                """,
                (token_hash,),
            ).fetchone()
        return dict(row) if row is not None else None

    def revoke_deception_token(self, tenant_id: str, token_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE deception_tokens SET active=0 WHERE tenant_id=? AND token_id=?",
                (tenant_id, token_id),
            )
            return cursor.rowcount > 0

    def recent_deception_hit_exists(self, token_id: str, fingerprint: str, since_utc: datetime) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM deception_hits
                WHERE token_id=? AND fingerprint=? AND timestamp_utc>=?
                LIMIT 1
                """,
                (token_id, fingerprint, since_utc.isoformat()),
            ).fetchone()
        return row is not None

    def record_deception_hit(
        self,
        *,
        token_id: str,
        tenant_id: str,
        timestamp_utc: datetime,
        source_ip: str | None,
        fingerprint: str,
        payload: dict[str, Any],
        incident_id: str,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO deception_hits (
                    token_id, tenant_id, timestamp_utc, source_ip,
                    fingerprint, payload_json, incident_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    tenant_id,
                    timestamp_utc.isoformat(),
                    source_ip,
                    fingerprint,
                    self._json(payload),
                    incident_id,
                ),
            )

    def usage_summary(self, tenant_id: str, month: str) -> UsageSummary:
        prefix = f"{month}-"
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS analyses,
                    COALESCE(SUM(llm_calls), 0) AS llm_calls,
                    COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens,
                    COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                    SUM(CASE WHEN deterministic_fallback=1 THEN 1 ELSE 0 END) AS fallback_analyses
                FROM analyses
                WHERE tenant_id=? AND created_at_utc LIKE ?
                """,
                (tenant_id, f"{prefix}%"),
            ).fetchone()

        return UsageSummary(
            tenant_id=tenant_id,
            month=month,
            analyses=int(row["analyses"] or 0),
            llm_calls=int(row["llm_calls"] or 0),
            prompt_tokens=int(row["prompt_tokens"] or 0),
            completion_tokens=int(row["completion_tokens"] or 0),
            fallback_analyses=int(row["fallback_analyses"] or 0),
        )
