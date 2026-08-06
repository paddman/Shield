from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from .models import EvidenceItem, EvidenceSource, IncidentInput

_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]{1,80})\\([A-Za-z0-9_.-]{1,80})\b")


def safe_text(value: Any, limit: int = 1200) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    else:
        text = str(value)
    text = _CONTROL_RE.sub(" ", text).replace("\r", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def mask_text(value: str) -> str:
    value = _EMAIL_RE.sub(lambda m: f"{m.group(1)[:2]}***@{m.group(2)}", value)
    value = _DOMAIN_USER_RE.sub(lambda m: f"{m.group(1)}\\{m.group(2)[:2]}***", value)
    return value


def _stable_ref(prefix: str, payload: Any, index: int) -> str:
    digest = hashlib.sha256(safe_text(payload, 8000).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{index}:{digest}"


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _first(data: dict[str, Any], *keys: str) -> Any:
    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def _public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


class EvidenceNormalizer:
    def __init__(self, max_items: int = 250, max_chars: int = 80_000) -> None:
        self._max_items = max(10, max_items)
        self._max_chars = max(10_000, max_chars)

    def normalize(self, incident: IncidentInput) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        total_chars = 0

        def add(item: EvidenceItem) -> None:
            nonlocal total_chars
            if len(items) >= self._max_items:
                return
            if incident.privacy_mode == "masked":
                item.summary = mask_text(item.summary)
                item.attributes = {
                    key: mask_text(safe_text(value, 1000)) if isinstance(value, str) else value
                    for key, value in item.attributes.items()
                }
            size = len(item.summary) + len(safe_text(item.attributes, 6000))
            if total_chars + size > self._max_chars:
                return
            total_chars += size
            items.append(item)

        core_attributes = {
            "rule_id": incident.rule_id,
            "severity": incident.severity,
            "source_ip": incident.source_ip,
            "source_host": incident.source_host,
            "source_port": incident.source_port,
            "destination_ip": incident.destination_ip,
            "destination_host": incident.destination_host,
            "destination_port": incident.destination_port,
            "username": incident.username,
            "domain": incident.domain,
            "process_name": incident.process_name,
            "process_id": incident.process_id,
            "process_path": incident.process_path,
            "process_command_line": incident.process_command_line,
            "services": incident.services,
            "failed_attempts": incident.failed_attempts,
            "distinct_usernames": incident.distinct_usernames,
            "successful_login_detected": incident.successful_login_detected,
            "privileged_logon": incident.privileged_logon,
            "status": incident.status,
        }
        compact_core = {key: value for key, value in core_attributes.items() if value not in (None, "", [], 0, False)}
        add(
            EvidenceItem(
                ref_id=f"incident:{incident.incident_id}",
                source=EvidenceSource.INCIDENT,
                kind="incident_summary",
                timestamp_utc=incident.last_seen or incident.first_seen,
                summary=safe_text(
                    incident.description
                    or f"{incident.title}: {incident.source_ip or incident.source_host or '?'} -> "
                    f"{incident.destination_ip or incident.destination_host or '?'}"
                ),
                attributes=compact_core,
            )
        )

        for idx, event in enumerate(incident.evidence_events):
            event_id = _first(event, "eventId", "event_id")
            record_id = _first(event, "eventRecordId", "event_record_id")
            user = _first(event, "username", "user")
            source_ip = _first(event, "sourceIp", "source_ip", "src_ip")
            status = _first(event, "status", "subStatus", "sub_status")
            summary = f"Windows event {event_id or '?'} user={user or '-'} source={source_ip or '-'} status={status or '-'}"
            ref = f"win:{record_id}" if record_id not in (None, "", 0) else _stable_ref("win", event, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.WINDOWS_EVENT,
                    kind=f"event_{event_id or 'unknown'}",
                    timestamp_utc=_timestamp(_first(event, "timestampUtc", "timestamp_utc", "timestamp")),
                    summary=safe_text(summary),
                    attributes={str(k): v for k, v in event.items()},
                )
            )

        self._append_evidence_json(incident.evidence_json, add)

        for idx, alert in enumerate(incident.suricata_alerts):
            signature = _first(alert, "signature", "alert.signature", "name", "message")
            signature_id = _first(alert, "signature_id", "signatureId", "sid")
            src = _first(alert, "src_ip", "srcIp", "source_ip", "sourceIp")
            dst = _first(alert, "dest_ip", "dst_ip", "destination_ip", "destinationIp")
            severity = _first(alert, "severity", "alert.severity")
            category = _first(alert, "category", "alert.category")
            ref = f"suricata:{signature_id}:{idx}" if signature_id else _stable_ref("suricata", alert, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.SURICATA,
                    kind="ids_alert",
                    timestamp_utc=_timestamp(_first(alert, "timestamp", "timestampUtc", "@timestamp")),
                    summary=safe_text(
                        f"Suricata {signature or 'alert'} {src or '?'} -> {dst or '?'} "
                        f"severity={severity or '?'} category={category or '-'}"
                    ),
                    attributes={str(k): v for k, v in alert.items()},
                )
            )

        for idx, event in enumerate(incident.zeek_events):
            log_type = _first(event, "log", "log_type", "_path", "type") or "event"
            uid = _first(event, "uid", "id")
            src = _first(event, "id.orig_h", "src_ip", "source_ip")
            dst = _first(event, "id.resp_h", "dst_ip", "destination_ip")
            finding = _first(event, "finding", "name", "note", "weird_name", "query", "host", "server_name")
            ref = f"zeek:{uid}:{idx}" if uid else _stable_ref("zeek", event, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.ZEEK,
                    kind=safe_text(log_type, 80),
                    timestamp_utc=_timestamp(_first(event, "ts", "timestamp", "timestampUtc")),
                    summary=safe_text(f"Zeek {log_type}: {src or '?'} -> {dst or '?'} {finding or ''}"),
                    attributes={str(k): v for k, v in event.items()},
                )
            )

        for idx, finding in enumerate(incident.asm_findings):
            tool = _first(finding, "tool", "scanner", "source") or "asm"
            target = _first(finding, "target", "host", "url", "asset")
            name = _first(finding, "name", "finding", "template", "title", "service")
            severity = _first(finding, "severity", "risk")
            ref = _stable_ref(f"asm:{safe_text(tool, 30)}", finding, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.ASM,
                    kind=safe_text(tool, 80),
                    timestamp_utc=_timestamp(_first(finding, "timestamp", "timestampUtc", "scanned_at")),
                    summary=safe_text(f"ASM {tool}: {target or '?'} {name or ''} severity={severity or '-'}"),
                    attributes={str(k): v for k, v in finding.items()},
                )
            )

        for idx, intel in enumerate(incident.threat_intel):
            indicator = _first(intel, "indicator", "ioc", "ip", "domain", "value")
            verdict = _first(intel, "verdict", "classification", "reputation", "risk")
            source = _first(intel, "source", "feed") or "threat-intel"
            ref = _stable_ref("intel", intel, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.THREAT_INTEL,
                    kind="ioc",
                    timestamp_utc=_timestamp(_first(intel, "timestamp", "last_seen", "timestampUtc")),
                    summary=safe_text(f"Threat intel {source}: {indicator or '?'} verdict={verdict or 'unknown'}"),
                    attributes={str(k): v for k, v in intel.items()},
                )
            )

        for idx, hit in enumerate(incident.deception_hits):
            token = _first(hit, "token_id", "tokenId", "canary_id", "id")
            source = _first(hit, "source_ip", "sourceIp", "src_ip")
            asset = _first(hit, "asset", "host", "path", "resource")
            ref = f"deception:{token}" if token else _stable_ref("deception", hit, idx)
            add(
                EvidenceItem(
                    ref_id=ref,
                    source=EvidenceSource.DECEPTION,
                    kind="deception_hit",
                    timestamp_utc=_timestamp(_first(hit, "timestamp", "timestampUtc")),
                    summary=safe_text(f"Deception token touched from {source or '?'} on {asset or '?'}"),
                    attributes={str(k): v for k, v in hit.items()},
                )
            )

        for idx, raw in enumerate(incident.raw_evidence):
            ref = str(raw.get("ref_id") or raw.get("refId") or _stable_ref("raw", raw, idx))
            add(
                EvidenceItem(
                    ref_id=safe_text(ref, 160),
                    source=EvidenceSource.RAW,
                    kind=safe_text(raw.get("kind", "raw"), 80),
                    timestamp_utc=_timestamp(raw.get("timestamp") or raw.get("timestampUtc")),
                    summary=safe_text(raw.get("summary") or raw),
                    attributes={str(k): v for k, v in raw.items()},
                )
            )

        return self._deduplicate(items)

    @staticmethod
    def _append_evidence_json(value: Any, add: Any) -> None:
        if value in (None, "", "[]", "{}"):
            return
        parsed = value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                parsed = [{"summary": value}]
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, Iterable) or isinstance(parsed, (str, bytes)):
            parsed = [{"value": parsed}]

        for idx, entry in enumerate(parsed):
            if not isinstance(entry, dict):
                entry = {"value": entry}
            add(
                EvidenceItem(
                    ref_id=_stable_ref("endpoint", entry, idx),
                    source=EvidenceSource.ENDPOINT,
                    kind=safe_text(_first(entry, "kind", "type", "source") or "endpoint_context", 80),
                    timestamp_utc=_timestamp(_first(entry, "timestamp", "timestampUtc", "timestamp_utc")),
                    summary=safe_text(_first(entry, "summary", "message", "description") or entry),
                    attributes={str(k): v for k, v in entry.items()},
                )
            )

    @staticmethod
    def _deduplicate(items: list[EvidenceItem]) -> list[EvidenceItem]:
        seen: set[str] = set()
        output: list[EvidenceItem] = []
        for item in items:
            if item.ref_id in seen:
                continue
            seen.add(item.ref_id)
            output.append(item)
        return output


def extract_domains(items: list[EvidenceItem]) -> set[str]:
    domains: set[str] = set()
    pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
    for item in items:
        for match in pattern.findall(item.summary):
            domains.add(match.lower())
        for key in ("domain", "query", "host", "hostname", "server_name", "sni"):
            value = item.attributes.get(key)
            if isinstance(value, str) and pattern.fullmatch(value.strip()):
                domains.add(value.strip().lower())
    return domains


def public_ips(items: list[EvidenceItem]) -> set[str]:
    result: set[str] = set()
    pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for item in items:
        for candidate in pattern.findall(item.summary):
            if _public_ip(candidate):
                result.add(candidate)
        for value in item.attributes.values():
            if isinstance(value, str) and _public_ip(value):
                result.add(value)
    return result
