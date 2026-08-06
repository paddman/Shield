from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class CodeApiModel(BaseModel):
    """Strict model for machine-generated source scan payloads."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class CodeSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CodeAssessmentVerdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    FALSE_POSITIVE = "false_positive"
    NEEDS_CONTEXT = "needs_context"


class CodeScanVerdict(StrEnum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NEEDS_REVIEW = "needs_review"


class CodeScannerIdentity(CodeApiModel):
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(default="", max_length=80)
    host: str = Field(default="", max_length=255)
    platform: str = Field(default="unknown", max_length=80)


class CodeScanProject(CodeApiModel):
    name: str = Field(min_length=1, max_length=300)
    repository: str = Field(default="", max_length=1000)
    branch: str = Field(default="", max_length=300)
    commit: str = Field(default="", max_length=160)


class CodeScanSummary(CodeApiModel):
    files_scanned: int = Field(default=0, ge=0, le=10_000_000)
    files_skipped: int = Field(default=0, ge=0, le=10_000_000)
    finding_count: int = Field(default=0, ge=0, le=10_000)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    languages: dict[str, int] = Field(default_factory=dict)

    @field_validator("severity_counts")
    @classmethod
    def valid_severity_counts(cls, value: dict[str, int]) -> dict[str, int]:
        allowed = {item.value for item in CodeSeverity}
        clean: dict[str, int] = {}
        for key, raw in value.items():
            normalized = str(key).lower()[:32]
            if normalized not in allowed:
                continue
            clean[normalized] = max(0, min(int(raw), 10_000))
        return clean

    @field_validator("languages")
    @classmethod
    def valid_language_counts(cls, value: dict[str, int]) -> dict[str, int]:
        clean: dict[str, int] = {}
        for key, raw in list(value.items())[:100]:
            normalized = re.sub(r"[^a-z0-9_+.#-]", "", str(key).lower())[:60]
            if normalized:
                clean[normalized] = max(0, min(int(raw), 10_000_000))
        return clean


class CodeScanFinding(CodeApiModel):
    finding_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    rule_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    severity: CodeSeverity
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    cwe: str = Field(default="", max_length=80)
    owasp: str = Field(default="", max_length=160)
    language: str = Field(default="unknown", max_length=80)
    path: str = Field(min_length=1, max_length=700)
    line: int = Field(default=0, ge=0, le=100_000_000)
    column: int = Field(default=0, ge=0, le=10_000_000)
    snippet: str = Field(default="", max_length=2000)
    evidence: str = Field(default="", max_length=1200)
    tags: list[str] = Field(default_factory=list, max_length=30)
    fingerprint: str = Field(default="", max_length=160)

    @field_validator("path")
    @classmethod
    def relative_safe_path(cls, value: str) -> str:
        path = value.replace("\\", "/").strip()
        if not path or path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
            raise ValueError("finding path must be relative")
        if any(part == ".." for part in path.split("/")):
            raise ValueError("finding path must not contain parent traversal")
        if any(ord(ch) < 0x20 for ch in path):
            raise ValueError("finding path contains control characters")
        return path

    @field_validator("tags")
    @classmethod
    def valid_tags(cls, value: list[str]) -> list[str]:
        result: list[str] = []
        for item in value[:30]:
            tag = re.sub(r"[^a-zA-Z0-9_+.#:/-]", "", str(item))[:80]
            if tag and tag not in result:
                result.append(tag)
        return result


class CodeScanRequest(CodeApiModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    scanner: CodeScannerIdentity
    started_at_utc: datetime
    finished_at_utc: datetime
    privacy_mode: Literal["snippets", "metadata"] = "snippets"
    project: CodeScanProject
    summary: CodeScanSummary
    findings: list[CodeScanFinding] = Field(default_factory=list, max_length=500)
    errors: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("errors")
    @classmethod
    def bounded_errors(cls, value: list[str]) -> list[str]:
        return [str(item)[:500] for item in value[:100]]

    @model_validator(mode="after")
    def valid_report(self) -> CodeScanRequest:
        if self.finished_at_utc < self.started_at_utc:
            raise ValueError("finishedAtUtc must not be before startedAtUtc")
        finding_ids = [item.finding_id for item in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("findingId values must be unique")
        if self.summary.finding_count != len(self.findings):
            raise ValueError("summary.findingCount must equal findings length")
        return self


class CodeFindingAssessment(CodeApiModel):
    finding_id: str = Field(min_length=1, max_length=160)
    verdict: CodeAssessmentVerdict
    adjusted_severity: CodeSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_th: str = Field(min_length=1, max_length=1600)
    remediation: str = Field(default="", max_length=1600)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class CodeDerivedFinding(CodeApiModel):
    derived_id: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=500)
    severity: CodeSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_th: str = Field(min_length=1, max_length=1600)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class CodeScanAnalysis(CodeApiModel):
    accepted: bool = True
    scan_id: str
    analysis_id: str
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verdict: CodeScanVerdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary_th: str = Field(min_length=1, max_length=3000)
    model: str
    llm_used: bool = False
    deterministic_fallback: bool = True
    assessments: list[CodeFindingAssessment] = Field(default_factory=list, max_length=500)
    derived_findings: list[CodeDerivedFinding] = Field(default_factory=list, max_length=50)
    attack_surface: list[str] = Field(default_factory=list, max_length=50)
    priority_actions: list[str] = Field(default_factory=list, max_length=30)
    warnings: list[str] = Field(default_factory=list, max_length=50)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0, le=10)
    input_findings: int = Field(default=0, ge=0, le=10_000)
    analyzed_by_llm: int = Field(default=0, ge=0, le=10_000)


class CodeScanListItem(CodeApiModel):
    scan_id: str
    analysis_id: str
    project_name: str
    created_at_utc: datetime
    verdict: CodeScanVerdict
    risk_score: int = Field(ge=0, le=100)
    model: str
    llm_used: bool
    input_findings: int = Field(ge=0)


class CodeLlmAssessment(CodeApiModel):
    finding_id: str = Field(min_length=1, max_length=160)
    verdict: CodeAssessmentVerdict
    adjusted_severity: CodeSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_th: str = Field(min_length=1, max_length=1600)
    remediation: str = Field(default="", max_length=1600)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class CodeLlmDerivedFinding(CodeApiModel):
    title: str = Field(min_length=1, max_length=500)
    severity: CodeSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_th: str = Field(min_length=1, max_length=1600)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class CodeLlmOutput(CodeApiModel):
    verdict: CodeScanVerdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary_th: str = Field(min_length=1, max_length=3000)
    assessments: list[CodeLlmAssessment] = Field(default_factory=list, max_length=200)
    derived_findings: list[CodeLlmDerivedFinding] = Field(default_factory=list, max_length=30)
    attack_surface: list[str] = Field(default_factory=list, max_length=50)
    priority_actions: list[str] = Field(default_factory=list, max_length=30)
    warnings: list[str] = Field(default_factory=list, max_length=50)
