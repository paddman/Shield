from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class ApiModel(BaseModel):
    """Base model that accepts both snake_case and camelCase payloads."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        str_strip_whitespace=True,
    )


class EvidenceSource(StrEnum):
    INCIDENT = "incident"
    WINDOWS_EVENT = "windows_event"
    ENDPOINT = "endpoint"
    SURICATA = "suricata"
    ZEEK = "zeek"
    ASM = "asm"
    THREAT_INTEL = "threat_intel"
    DECEPTION = "deception"
    TEMPORAL_CHAIN = "temporal_chain"
    RAW = "raw"


class ResponseActionType(StrEnum):
    CAPTURE_PCAP = "CapturePcap"
    REPLAY_PCAP = "ReplayPcap"
    ENRICH_THREAT_INTEL = "EnrichThreatIntel"
    COLLECT_DIAGNOSTICS = "CollectDiagnostics"
    EXPORT_EVIDENCE = "ExportEvidence"
    OPEN_TICKET = "OpenTicket"
    NOTIFY_ADMIN = "NotifyAdmin"
    BLOCK_SOURCE_IP = "BlockSourceIp"
    RATE_LIMIT_SOURCE_IP = "RateLimitSourceIp"
    ISOLATE_HOST = "IsolateHost"
    QUARANTINE_HOST = "QuarantineHost"
    STOP_SERVICE = "StopService"
    TERMINATE_PROCESS = "TerminateProcess"
    LOCK_ACCOUNT = "LockAccount"
    REVOKE_SESSIONS = "RevokeSessions"
    SNAPSHOT_FORENSICS = "SnapshotForensics"


NON_DESTRUCTIVE_ACTIONS: frozenset[ResponseActionType] = frozenset(
    {
        ResponseActionType.CAPTURE_PCAP,
        ResponseActionType.REPLAY_PCAP,
        ResponseActionType.ENRICH_THREAT_INTEL,
        ResponseActionType.COLLECT_DIAGNOSTICS,
        ResponseActionType.EXPORT_EVIDENCE,
        ResponseActionType.OPEN_TICKET,
        ResponseActionType.NOTIFY_ADMIN,
        ResponseActionType.SNAPSHOT_FORENSICS,
    }
)


class DeceptionTokenType(StrEnum):
    CANARY_CREDENTIAL = "canary_credential"
    HONEY_FILE = "honey_file"
    DECOY_API_KEY = "decoy_api_key"
    DECOY_URL = "decoy_url"
    DECOY_SHARE = "decoy_share"


class DeceptionTokenRequest(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    token_type: DeceptionTokenType
    asset: str = Field(default="", max_length=500)
    ttl_days: int = Field(default=365, ge=1, le=3650)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeceptionTokenResponse(ApiModel):
    token_id: str
    token: str
    name: str
    token_type: DeceptionTokenType
    asset: str
    created_at_utc: datetime
    expires_at_utc: datetime


class DeceptionTokenSummary(ApiModel):
    token_id: str
    name: str
    token_type: DeceptionTokenType
    asset: str
    created_at_utc: datetime
    expires_at_utc: datetime
    active: bool
    hit_count: int = 0
    last_hit_at_utc: datetime | None = None


class DeceptionHitRequest(ApiModel):
    token: str = Field(min_length=16, max_length=500)
    source_ip: str | None = None
    source_host: str | None = None
    username: str | None = None
    process_name: str | None = None
    destination: str | None = None
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict[str, Any] = Field(default_factory=dict)


class DeceptionHitResponse(ApiModel):
    accepted: bool
    duplicate: bool = False
    incident_id: str | None = None


class EvidenceItem(ApiModel):
    ref_id: str = Field(min_length=1, max_length=160)
    source: EvidenceSource
    kind: str = Field(default="event", max_length=80)
    timestamp_utc: datetime | None = None
    summary: str = Field(max_length=1200)
    attributes: dict[str, Any] = Field(default_factory=dict)


class EvidenceCitation(ApiModel):
    ref_id: str
    reason: str = Field(max_length=500)


class RiskSignal(ApiModel):
    name: str
    score_delta: float
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)


class AnomalyObservationRequest(ApiModel):
    asset_id: str = Field(min_length=1, max_length=200)
    features: dict[str, float] = Field(min_length=1)
    learn: bool = True
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("features")
    @classmethod
    def finite_features(cls, value: dict[str, float]) -> dict[str, float]:
        clean: dict[str, float] = {}
        for key, raw in value.items():
            number = float(raw)
            if number != number or number in (float("inf"), float("-inf")):
                raise ValueError(f"feature {key!r} must be finite")
            clean[str(key)[:120]] = number
        return clean


class AnomalyResult(ApiModel):
    asset_id: str
    state: Literal["learning", "ready"]
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    baseline_samples: int = Field(ge=0)
    model: str
    contributors: list[RiskSignal] = Field(default_factory=list)


class IncidentInput(ApiModel):
    """Unified input accepted from NT Shield Central, Suricata, Zeek and ASM."""

    incident_id: str = Field(min_length=1, max_length=200)
    title: str = Field(default="Security incident", max_length=500)
    rule_id: str = Field(default="", max_length=200)
    severity: str | int = "Medium"
    description: str = Field(default="", max_length=4000)
    status: str = Field(default="Open", max_length=80)
    incident_score: int | None = Field(default=None, ge=0, le=100)
    detection_stage: str | None = Field(default=None, max_length=500)

    source_ip: str | None = None
    source_host: str | None = None
    source_agent_id: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)

    destination_ip: str | None = None
    destination_host: str | None = None
    destination_agent_id: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    username: str | None = None
    domain: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    process_path: str | None = None
    process_command_line: str | None = None
    executable_sha256: str | None = None
    services: list[str] = Field(default_factory=list)
    service_account: str | None = None

    failed_attempts: int = Field(default=0, ge=0)
    distinct_usernames: int = Field(default=0, ge=0)
    successful_login_detected: bool = False
    privileged_logon: bool = False

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence_events: list[dict[str, Any]] = Field(default_factory=list)
    evidence_json: Any = None

    suricata_alerts: list[dict[str, Any]] = Field(default_factory=list)
    zeek_events: list[dict[str, Any]] = Field(default_factory=list)
    asm_findings: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel: list[dict[str, Any]] = Field(default_factory=list)
    deception_hits: list[dict[str, Any]] = Field(default_factory=list)
    # Preferred Central v2 contract: bounded facts with stable citation ids.
    # This is distinct from raw_evidence, which remains a compatibility input.
    structured_evidence: list[EvidenceItem] = Field(default_factory=list, max_length=250)
    raw_evidence: list[dict[str, Any]] = Field(default_factory=list)

    features: dict[str, float] = Field(default_factory=dict)
    asset_id: str | None = None
    observe_baseline: bool = False
    privacy_mode: Literal["full", "masked"] = "full"
    context: dict[str, Any] = Field(default_factory=dict)


class RecommendedAction(ApiModel):
    action: ResponseActionType
    target: str | None = None
    reason: str = Field(max_length=700)
    evidence_refs: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)


class SpecialistFinding(ApiModel):
    specialist: Literal["network", "endpoint", "exposure", "commander"]
    summary_th: str
    hypotheses: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    risk_adjustment: int = Field(default=0, ge=-20, le=20)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)


class GraphNode(ApiModel):
    node_id: str
    node_type: str
    label: str
    risk: int = Field(default=0, ge=0, le=100)
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(ApiModel):
    edge_id: str
    source: str
    target: str
    relation: str
    evidence_refs: list[str] = Field(default_factory=list)
    timestamp_utc: datetime | None = None


class ThreatGraph(ApiModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class AnalystDecision(ApiModel):
    analysis_id: str
    tenant_id: str
    incident_id: str
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    classification: str
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary_th: str
    summary_en: str = ""
    attack_chain: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    risk_signals: list[RiskSignal] = Field(default_factory=list)
    anomaly: AnomalyResult | None = None
    specialists: list[SpecialistFinding] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    analyst_questions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    playbooks: list[str] = Field(default_factory=list)
    threat_graph: ThreatGraph = Field(default_factory=ThreatGraph)

    model: str
    analysis_mode: str
    deterministic_fallback: bool = False
    latency_ms: int = Field(default=0, ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)


class FeedbackRequest(ApiModel):
    incident_id: str
    analysis_id: str | None = None
    verdict: Literal["true_positive", "false_positive", "benign", "needs_more_data"]
    notes: str = Field(default="", max_length=4000)
    approved_actions: list[ResponseActionType] = Field(default_factory=list)


class MonthlyReportRequest(ApiModel):
    month: str = Field(pattern=r"^\d{4}-\d{2}$")
    organization_name: str = Field(max_length=300)
    metrics: dict[str, Any] = Field(default_factory=dict)
    top_incidents: list[dict[str, Any]] = Field(default_factory=list)
    response_actions: list[dict[str, Any]] = Field(default_factory=list)
    asm_findings: list[dict[str, Any]] = Field(default_factory=list)
    compliance_frameworks: list[str] = Field(
        default_factory=lambda: ["ISO27001", "NIST-CSF", "SOC2"]
    )


class MonthlyReportResponse(ApiModel):
    month: str
    organization_name: str
    executive_summary_th: str
    technical_summary_th: str
    key_risks: list[str] = Field(default_factory=list)
    achievements: list[str] = Field(default_factory=list)
    next_month_priorities: list[str] = Field(default_factory=list)
    compliance_evidence: list[dict[str, Any]] = Field(default_factory=list)
    model: str
    deterministic_fallback: bool = False


class ThreatHuntRequest(ApiModel):
    query: str = Field(min_length=3, max_length=2000)
    available_sources: list[str] = Field(
        default_factory=lambda: ["endpoint", "suricata", "zeek", "asm", "threat_intel"]
    )
    time_range: str = Field(default="24h", max_length=80)
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatHuntPlan(ApiModel):
    hypothesis: str
    data_sources: list[str]
    safe_queries: list[dict[str, Any]]
    expected_signals: list[str]
    stop_conditions: list[str]
    requires_approval: bool = False
    model: str
    deterministic_fallback: bool = False


class UsageSummary(ApiModel):
    tenant_id: str
    month: str
    analyses: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    fallback_analyses: int = 0
