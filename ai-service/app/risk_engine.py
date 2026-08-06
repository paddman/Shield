from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from .models import EvidenceItem, EvidenceSource, IncidentInput, RiskSignal


@dataclass(slots=True)
class RiskAssessment:
    score: int
    confidence: float
    classification: str
    attack_chain: list[str]
    mitre_techniques: list[str]
    signals: list[RiskSignal]


class HybridRiskEngine:
    """Explainable rules that anchor the LLM and constrain hallucinated risk."""

    _SUSPICIOUS_PROCESS_TOKENS = (
        "powershell",
        "pwsh",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "certutil",
        "wmic",
        "psexec",
        "mimikatz",
        "cobalt",
        "nc.exe",
        "ncat",
        "w3wp",
    )
    _REMOTE_ACCESS_TOKENS = (
        "anydesk",
        "teamviewer",
        "rustdesk",
        "screenconnect",
        "cloudflare tunnel",
        "trycloudflare",
        "ngrok",
        "tailscale",
    )
    _MALICIOUS_VERDICTS = ("malicious", "high risk", "known bad", "botnet", "c2", "tor exit")

    @staticmethod
    def _severity_score(value: str | int) -> tuple[int, str]:
        if isinstance(value, int):
            mapping = {
                0: (10, "Informational"),
                1: (20, "Low"),
                2: (40, "Medium"),
                3: (60, "High"),
                4: (78, "Critical"),
            }
            return mapping.get(value, (40, "Medium"))
        normalized = str(value).strip().lower()
        if normalized in {"critical", "crit", "4"}:
            return 78, "Critical"
        if normalized in {"high", "3"}:
            return 60, "High"
        if normalized in {"medium", "moderate", "2"}:
            return 40, "Medium"
        if normalized in {"low", "1"}:
            return 20, "Low"
        return 10, "Informational"

    def assess(
        self,
        incident: IncidentInput,
        evidence: list[EvidenceItem],
        anomaly_score: float | None = None,
    ) -> RiskAssessment:
        score, severity_label = self._severity_score(incident.severity)
        signals: list[RiskSignal] = [
            RiskSignal(
                name="source_severity",
                score_delta=score,
                reason=f"Base score from source severity {severity_label}",
                evidence_refs=[f"incident:{incident.incident_id}"],
            )
        ]
        attack_chain: list[str] = []
        techniques: list[str] = []
        text = " ".join(
            [
                incident.title,
                incident.rule_id,
                incident.description,
                incident.process_name or "",
                incident.process_path or "",
                incident.process_command_line or "",
                " ".join(item.summary for item in evidence),
            ]
        ).lower()

        def add(name: str, delta: float, reason: str, refs: list[str] | None = None) -> None:
            nonlocal score
            score += int(round(delta))
            signals.append(
                RiskSignal(
                    name=name,
                    score_delta=delta,
                    reason=reason,
                    evidence_refs=refs or [f"incident:{incident.incident_id}"],
                )
            )

        if incident.failed_attempts >= 5:
            delta = 5 if incident.failed_attempts < 20 else 12 if incident.failed_attempts < 100 else 18
            add("failed_authentication_burst", delta, f"{incident.failed_attempts} failed authentication attempts")
            self._append_unique(attack_chain, "Credential Access")
            self._append_unique(techniques, "T1110")

        if incident.distinct_usernames >= 5:
            add(
                "password_spray_pattern",
                min(15, 5 + incident.distinct_usernames / 3),
                f"Authentication attempts span {incident.distinct_usernames} usernames",
            )
            self._append_unique(attack_chain, "Credential Access")
            self._append_unique(techniques, "T1110.003")

        if incident.successful_login_detected and incident.failed_attempts > 0:
            add("success_after_failures", 18, "Successful login followed failed authentication activity")
            self._append_unique(attack_chain, "Initial Access")
            self._append_unique(attack_chain, "Lateral Movement")
            self._append_unique(techniques, "T1078")

        if incident.privileged_logon:
            add("privileged_logon", 14, "Privileged logon observed in the incident window")
            self._append_unique(attack_chain, "Privilege Escalation")
            self._append_unique(techniques, "T1078.002")

        process_ref = next(
            (item.ref_id for item in evidence if item.source in {EvidenceSource.ENDPOINT, EvidenceSource.WINDOWS_EVENT}),
            f"incident:{incident.incident_id}",
        )
        suspicious_processes = [token for token in self._SUSPICIOUS_PROCESS_TOKENS if token in text]
        if suspicious_processes:
            add(
                "suspicious_process_context",
                min(16, 7 + len(suspicious_processes) * 2),
                f"Suspicious execution context: {', '.join(suspicious_processes[:5])}",
                [process_ref],
            )
            self._append_unique(attack_chain, "Execution")
            self._append_unique(techniques, "T1059")

        remote_apps = [token for token in self._REMOTE_ACCESS_TOKENS if token in text]
        if remote_apps:
            add(
                "remote_access_or_tunnel",
                min(15, 8 + len(remote_apps) * 2),
                f"Remote access or tunneling technology observed: {', '.join(remote_apps[:4])}",
                self._refs_for_text(evidence, remote_apps),
            )
            self._append_unique(attack_chain, "Command and Control")
            self._append_unique(techniques, "T1219")

        suricata = [item for item in evidence if item.source == EvidenceSource.SURICATA]
        if suricata:
            high_count = sum(1 for item in suricata if self._numeric_severity(item.attributes) >= 2)
            add(
                "network_ids_alerts",
                min(18, 4 + len(suricata) + high_count * 2),
                f"{len(suricata)} Suricata alert(s), {high_count} elevated",
                [item.ref_id for item in suricata[:8]],
            )

        zeek_weird = [
            item
            for item in evidence
            if item.source == EvidenceSource.ZEEK
            and ("weird" in item.kind.lower() or "weird" in item.summary.lower())
        ]
        if zeek_weird:
            add(
                "zeek_protocol_anomalies",
                min(12, 3 + len(zeek_weird)),
                f"{len(zeek_weird)} Zeek protocol anomaly event(s)",
                [item.ref_id for item in zeek_weird[:8]],
            )

        port_scan_evidence = [
            item
            for item in evidence
            if any(token in item.summary.lower() for token in ("port scan", "probing multiple ports", "unique dst ports"))
        ]
        if port_scan_evidence or re.search(r"\b(scan|recon|probing)\b", text):
            add(
                "reconnaissance_pattern",
                10,
                "Port scanning or broad reconnaissance pattern detected",
                [item.ref_id for item in port_scan_evidence[:8]],
            )
            self._append_unique(attack_chain, "Reconnaissance")
            self._append_unique(attack_chain, "Discovery")
            self._append_unique(techniques, "T1046")

        critical_asm = [
            item
            for item in evidence
            if item.source == EvidenceSource.ASM
            and any(token in item.summary.lower() for token in ("critical", "high", "vulnerab", "exposed"))
        ]
        if critical_asm:
            add(
                "attack_surface_exposure",
                min(15, 5 + len(critical_asm) * 2),
                f"{len(critical_asm)} elevated attack-surface finding(s)",
                [item.ref_id for item in critical_asm[:8]],
            )
            self._append_unique(attack_chain, "Initial Access")

        malicious_intel = [
            item
            for item in evidence
            if item.source == EvidenceSource.THREAT_INTEL
            and any(token in item.summary.lower() for token in self._MALICIOUS_VERDICTS)
        ]
        if malicious_intel:
            add(
                "known_malicious_indicator",
                min(20, 12 + len(malicious_intel) * 2),
                f"{len(malicious_intel)} indicator(s) have malicious reputation",
                [item.ref_id for item in malicious_intel[:8]],
            )

        deception = [item for item in evidence if item.source == EvidenceSource.DECEPTION]
        if deception:
            add(
                "deception_hit",
                30,
                "A deception token or decoy asset was accessed; benign explanations are uncommon",
                [item.ref_id for item in deception[:8]],
            )
            score = max(score, 92)
            self._append_unique(attack_chain, "Credential Access")
            self._append_unique(attack_chain, "Discovery")

        if anomaly_score is not None:
            anomaly_score = max(0.0, min(1.0, anomaly_score))
            delta = max(0, round((anomaly_score - 0.55) * 35))
            if delta > 0:
                add(
                    "behavioral_anomaly",
                    delta,
                    f"Tenant/asset baseline anomaly score is {anomaly_score:.2f}",
                )

        score = max(0, min(100, score))
        classification = self._classify(incident, text, attack_chain, deception)
        confidence = self._confidence(evidence, signals, incident)
        return RiskAssessment(
            score=score,
            confidence=confidence,
            classification=classification,
            attack_chain=attack_chain or ["Detection"],
            mitre_techniques=techniques,
            signals=signals,
        )

    @staticmethod
    def _numeric_severity(attributes: dict[str, Any]) -> int:
        value = attributes.get("severity")
        if value is None and isinstance(attributes.get("alert"), dict):
            value = attributes["alert"].get("severity")
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            text = str(value).lower()
            return 3 if "critical" in text else 2 if "high" in text else 1 if "medium" in text else 0

    @staticmethod
    def _append_unique(target: list[str], value: str) -> None:
        if value not in target:
            target.append(value)

    @staticmethod
    def _refs_for_text(evidence: list[EvidenceItem], tokens: list[str]) -> list[str]:
        refs = [
            item.ref_id
            for item in evidence
            if any(token in (item.summary + " " + str(item.attributes)).lower() for token in tokens)
        ]
        return refs[:8]

    @staticmethod
    def _confidence(
        evidence: list[EvidenceItem],
        signals: list[RiskSignal],
        incident: IncidentInput,
    ) -> float:
        source_diversity = len({item.source for item in evidence})
        evidence_factor = min(0.25, math.log2(max(1, len(evidence))) * 0.04)
        diversity_factor = min(0.2, source_diversity * 0.04)
        signal_factor = min(0.2, max(0, len(signals) - 1) * 0.025)
        endpoint_factor = 0.1 if incident.process_name or incident.source_agent_id else 0.0
        return round(min(0.98, 0.35 + evidence_factor + diversity_factor + signal_factor + endpoint_factor), 2)

    @staticmethod
    def _classify(
        incident: IncidentInput,
        text: str,
        attack_chain: list[str],
        deception: list[EvidenceItem],
    ) -> str:
        if deception:
            return "High-confidence deception tripwire"
        if "webshell" in text or ("w3wp" in text and any(token in text for token in ("powershell", "cmd.exe"))):
            return "Suspected web compromise / webshell"
        if incident.successful_login_detected and incident.failed_attempts > 0:
            return "Credential attack with possible account compromise"
        if "Lateral Movement" in attack_chain:
            return "Suspected lateral movement"
        if "port scan" in text or "Reconnaissance" in attack_chain:
            return "Network reconnaissance / port scan"
        if "Command and Control" in attack_chain:
            return "Suspicious remote access or tunneling"
        if "attack_surface" in text or "vulnerab" in text:
            return "Attack-surface exposure"
        return incident.title or "Security anomaly"
