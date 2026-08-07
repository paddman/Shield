from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .code_scan_models import CodeScanAnalysis, CodeScanListItem, CodeScanRequest

class _ClosingConnection(sqlite3.Connection):
    """Commit/rollback like sqlite's context manager, then release the FD."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


_CREDENTIAL_KEY = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|private[_-]?token|db[_-]?password|"
    r"database[_-]?password|connection[_-]?string)"
)
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            rf"((?<![A-Za-z0-9_])[\"']?{_CREDENTIAL_KEY}[\"']?"
            r"\s*[:=]\s*[\"'])[^\"']+([\"'])",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(
            rf"((?<![A-Za-z0-9_])[\"']?{_CREDENTIAL_KEY}[\"']?"
            r"\s*[:=]\s*)[A-Za-z0-9_./+~=-]{8,}",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.IGNORECASE), "[REDACTED_SLACK_TOKEN]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(
            r"(Authorization\s*[:=]\s*[\"']?(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@", re.IGNORECASE),
        r"\1[REDACTED]@",
    ),
)


def clean_text(value: Any, limit: int) -> str:
    text = str(value or "").replace("\x00", "")
    text = "".join(ch for ch in text if ch in "\n\r\t" or ord(ch) >= 0x20)
    text = re.sub(r"<\|[^>]{0,200}\|>", "[CONTROL_TOKEN]", text)
    if "PRIVATE KEY-----" in text.upper():
        return "[REDACTED_PRIVATE_KEY_MATERIAL]"
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]


def sanitize_code_scan(payload: CodeScanRequest) -> CodeScanRequest:
    raw = payload.model_dump(mode="json", by_alias=False)
    for key, limit in {"name": 300, "repository": 1000, "branch": 300, "commit": 160}.items():
        raw["project"][key] = clean_text(raw["project"].get(key), limit)
    for key, limit in {"name": 120, "version": 80, "host": 255, "platform": 80}.items():
        raw["scanner"][key] = clean_text(raw["scanner"].get(key), limit)
    for finding in raw.get("findings", []):
        for key, limit in {"title": 500, "snippet": 2000, "evidence": 1200, "cwe": 80, "owasp": 160}.items():
            finding[key] = clean_text(finding.get(key), limit)
    raw["errors"] = [clean_text(item, 500) for item in raw.get("errors", [])[:100]]
    return CodeScanRequest.model_validate(raw)


class CodeScanStore:
    """Tenant-scoped durable storage using NTShield Brain's SQLite database."""

    def __init__(self, database_path: Path) -> None:
        self._path = database_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS code_scan_analyses (
                    tenant_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    analysis_id TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    model TEXT NOT NULL,
                    llm_used INTEGER NOT NULL,
                    input_findings INTEGER NOT NULL,
                    request_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, scan_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_code_scan_analysis_id
                    ON code_scan_analyses(tenant_id, analysis_id);
                CREATE INDEX IF NOT EXISTS idx_code_scan_created
                    ON code_scan_analyses(tenant_id, created_at_utc DESC);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._path,
            timeout=30,
            check_same_thread=False,
            factory=_ClosingConnection,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def save(self, tenant_id: str, request: CodeScanRequest, analysis: CodeScanAnalysis) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO code_scan_analyses (
                    tenant_id, scan_id, analysis_id, project_name, created_at_utc,
                    verdict, risk_score, model, llm_used, input_findings,
                    request_json, analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, scan_id) DO UPDATE SET
                    analysis_id=excluded.analysis_id,
                    project_name=excluded.project_name,
                    created_at_utc=excluded.created_at_utc,
                    verdict=excluded.verdict,
                    risk_score=excluded.risk_score,
                    model=excluded.model,
                    llm_used=excluded.llm_used,
                    input_findings=excluded.input_findings,
                    request_json=excluded.request_json,
                    analysis_json=excluded.analysis_json
                """,
                (
                    tenant_id,
                    analysis.scan_id,
                    analysis.analysis_id,
                    request.project.name,
                    analysis.created_at_utc.isoformat(),
                    analysis.verdict.value,
                    analysis.risk_score,
                    analysis.model,
                    int(analysis.llm_used),
                    analysis.input_findings,
                    request.model_dump_json(by_alias=True),
                    analysis.model_dump_json(by_alias=True),
                ),
            )

    def get(self, tenant_id: str, scan_id: str) -> CodeScanAnalysis | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM code_scan_analyses WHERE tenant_id=? AND scan_id=?",
                (tenant_id, scan_id),
            ).fetchone()
        return None if row is None else CodeScanAnalysis.model_validate_json(row["analysis_json"])

    def list(self, tenant_id: str, limit: int = 50) -> list[CodeScanListItem]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, analysis_id, project_name, created_at_utc, verdict,
                       risk_score, model, llm_used, input_findings
                FROM code_scan_analyses
                WHERE tenant_id=?
                ORDER BY created_at_utc DESC
                LIMIT ?
                """,
                (tenant_id, max(1, min(limit, 500))),
            ).fetchall()
        return [
            CodeScanListItem(
                scan_id=row["scan_id"],
                analysis_id=row["analysis_id"],
                project_name=row["project_name"],
                created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
                verdict=row["verdict"],
                risk_score=row["risk_score"],
                model=row["model"],
                llm_used=bool(row["llm_used"]),
                input_findings=row["input_findings"],
            )
            for row in rows
        ]
