from app.models import IncidentInput
from app.risk_engine import HybridRiskEngine


def test_endpoint_score_is_a_floor_for_ai_correlation():
    incident = IncidentInput(
        incident_id="av-floor-1",
        title="Antivirus threat detected",
        rule_id="DEFENDER_THREAT",
        severity="Medium",
        incident_score=96,
        detection_stage="signature -> heuristic -> defender",
        features={"defender_threat": 1.0, "entropy": 7.8},
    )

    result = HybridRiskEngine().assess(incident, evidence=[])

    assert result.score >= 96
    assert any(signal.name == "endpoint_protection_score" for signal in result.signals)
