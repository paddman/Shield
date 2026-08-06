from __future__ import annotations

import hashlib
import re
from typing import Any

from .evidence import extract_domains, public_ips
from .models import EvidenceItem, EvidenceSource, GraphEdge, GraphNode, IncidentInput, ThreatGraph


class ThreatGraphBuilder:
    def build(
        self,
        incident: IncidentInput,
        evidence: list[EvidenceItem],
        risk_score: int,
    ) -> ThreatGraph:
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        def node(node_type: str, value: str | int | None, risk: int = 0, **attrs: Any) -> str | None:
            if value in (None, ""):
                return None
            label = str(value)
            node_id = f"{node_type}:{hashlib.sha256(label.lower().encode()).hexdigest()[:14]}"
            existing = nodes.get(node_id)
            if existing is None:
                nodes[node_id] = GraphNode(
                    node_id=node_id,
                    node_type=node_type,
                    label=label,
                    risk=max(0, min(100, risk)),
                    attributes={key: val for key, val in attrs.items() if val not in (None, "")},
                )
            else:
                existing.risk = max(existing.risk, max(0, min(100, risk)))
                existing.attributes.update({key: val for key, val in attrs.items() if val not in (None, "")})
            return node_id

        def edge(
            source: str | None,
            target: str | None,
            relation: str,
            refs: list[str] | None = None,
            timestamp: Any = None,
        ) -> None:
            if not source or not target or source == target:
                return
            key = f"{source}|{target}|{relation}"
            edge_id = f"edge:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            if edge_id not in edges:
                edges[edge_id] = GraphEdge(
                    edge_id=edge_id,
                    source=source,
                    target=target,
                    relation=relation,
                    evidence_refs=list(dict.fromkeys(refs or []))[:20],
                    timestamp_utc=timestamp,
                )
            else:
                edges[edge_id].evidence_refs = list(
                    dict.fromkeys(edges[edge_id].evidence_refs + (refs or []))
                )[:20]

        incident_ref = f"incident:{incident.incident_id}"
        src_ip = node("ip", incident.source_ip, risk_score)
        src_host = node("host", incident.source_host, risk_score, agent_id=incident.source_agent_id)
        dst_ip = node("ip", incident.destination_ip, max(20, risk_score - 10))
        dst_host = node("host", incident.destination_host, max(20, risk_score - 10), agent_id=incident.destination_agent_id)
        user = node("user", incident.username, max(10, risk_score - 15), domain=incident.domain)
        process = node(
            "process",
            incident.process_name or incident.process_path,
            max(15, risk_score - 5),
            pid=incident.process_id,
            path=incident.process_path,
            command_line=incident.process_command_line,
            sha256=incident.executable_sha256,
        )

        edge(src_host, src_ip, "has_address", [incident_ref])
        edge(dst_host, dst_ip, "has_address", [incident_ref])
        edge(user, src_host or dst_host, "authenticated_on", [incident_ref], incident.last_seen)
        edge(process, src_host, "executed_on", [incident_ref], incident.last_seen)
        edge(src_ip or src_host, dst_ip or dst_host, "connected_to", [incident_ref], incident.last_seen)
        edge(process, dst_ip or dst_host, "opened_connection_to", [incident_ref], incident.last_seen)

        for service_name in incident.services:
            service = node("service", service_name, max(10, risk_score - 10), account=incident.service_account)
            edge(service, process, "hosted_by", [incident_ref])
            edge(service, src_host, "runs_on", [incident_ref])

        for item in evidence:
            refs = [item.ref_id]
            attrs = item.attributes
            if item.source == EvidenceSource.SURICATA:
                src = self._first(attrs, "src_ip", "srcIp", "source_ip", "sourceIp")
                dst = self._first(attrs, "dest_ip", "dst_ip", "destination_ip", "destinationIp")
                alert = self._first(attrs, "signature", "name", "message") or item.summary
                alert_node = node("alert", alert, min(100, risk_score + 5), sensor="suricata")
                src_node = node("ip", src, risk_score)
                dst_node = node("ip", dst, max(10, risk_score - 10))
                edge(src_node, dst_node, "triggered_network_alert", refs, item.timestamp_utc)
                edge(alert_node, src_node, "observed_source", refs, item.timestamp_utc)
                edge(alert_node, dst_node, "observed_target", refs, item.timestamp_utc)

            elif item.source == EvidenceSource.ZEEK:
                src = self._first(attrs, "id.orig_h", "src_ip", "source_ip")
                dst = self._first(attrs, "id.resp_h", "dst_ip", "destination_ip")
                src_node = node("ip", src, risk_score)
                dst_node = node("ip", dst, max(10, risk_score - 10))
                edge(src_node, dst_node, f"zeek_{item.kind}", refs, item.timestamp_utc)

            elif item.source == EvidenceSource.ASM:
                target = self._first(attrs, "target", "host", "url", "asset")
                finding = self._first(attrs, "name", "finding", "template", "title", "service") or item.summary
                asset = node("asset", target, max(10, risk_score - 20))
                finding_node = node("exposure", finding, min(100, risk_score + 5))
                edge(asset, finding_node, "has_exposure", refs, item.timestamp_utc)

            elif item.source == EvidenceSource.DECEPTION:
                token = self._first(attrs, "token_id", "tokenId", "canary_id", "id") or item.ref_id
                token_node = node("deception", token, 100)
                source = self._first(attrs, "source_ip", "sourceIp", "src_ip")
                edge(node("ip", source, 100), token_node, "touched_decoy", refs, item.timestamp_utc)

            elif item.source == EvidenceSource.THREAT_INTEL:
                indicator = self._first(attrs, "indicator", "ioc", "ip", "domain", "value")
                verdict = self._first(attrs, "verdict", "classification", "reputation", "risk")
                indicator_node = node("indicator", indicator, min(100, risk_score + 10), verdict=verdict)
                edge(indicator_node, src_ip or dst_ip, "enriches", refs, item.timestamp_utc)

        for domain in extract_domains(evidence):
            domain_node = node("domain", domain, max(10, risk_score - 5))
            edge(process or src_host or src_ip, domain_node, "resolved_or_contacted", self._refs_for(evidence, domain))

        for ip in public_ips(evidence):
            ip_node = node("ip", ip, max(10, risk_score - 5))
            if ip_node not in {src_ip, dst_ip}:
                edge(src_ip or src_host or process, ip_node, "observed_external_peer", self._refs_for(evidence, ip))

        cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
        for item in evidence:
            for cve in cve_pattern.findall(item.summary + " " + str(item.attributes)):
                cve_node = node("vulnerability", cve.upper(), min(100, risk_score + 10))
                edge(dst_host or dst_ip, cve_node, "potentially_exposed_to", [item.ref_id])

        return ThreatGraph(nodes=list(nodes.values()), edges=list(edges.values()))

    @staticmethod
    def _first(data: dict[str, Any], *keys: str) -> Any:
        lowered = {str(key).lower(): value for key, value in data.items()}
        for key in keys:
            if key.lower() in lowered:
                return lowered[key.lower()]
        return None

    @staticmethod
    def _refs_for(evidence: list[EvidenceItem], value: str) -> list[str]:
        value = value.lower()
        return [
            item.ref_id
            for item in evidence
            if value in (item.summary + " " + str(item.attributes)).lower()
        ][:12]
