from __future__ import annotations

from app.evidence import EvidenceNormalizer
from app.models import IncidentInput
from app.threat_graph import ThreatGraphBuilder


def test_graph_links_process_host_and_network_alert():
    incident = IncidentInput(
        incident_id="graph-1",
        title="Potential port scan",
        severity="High",
        source_ip="10.0.0.5",
        source_host="srv-a",
        destination_ip="203.0.113.50",
        process_name="powershell.exe",
        process_id=900,
        services=["UpdaterService"],
        suricata_alerts=[
            {
                "signature_id": 2001219,
                "signature": "ET SCAN Potential SSH Scan",
                "src_ip": "10.0.0.5",
                "dest_ip": "203.0.113.50",
                "severity": 2,
            }
        ],
    )
    evidence = EvidenceNormalizer().normalize(incident)
    graph = ThreatGraphBuilder().build(incident, evidence, 86)

    assert any(node.node_type == "process" and node.label == "powershell.exe" for node in graph.nodes)
    assert any(node.node_type == "alert" for node in graph.nodes)
    assert any(edge.relation == "opened_connection_to" for edge in graph.edges)
