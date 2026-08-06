from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.intel_exchange import IndicatorType, IntelExchangeStore, IntelPublishRequest
from app.investigation import InvestigationOrchestrator, InvestigationRequest
from app.llm import OpenAICompatibleLlm
from app.models import IncidentInput
from app.playbooks import PlaybookRetriever
from app.security import TenantContext


class FakeCentral:
    async def list_incidents(self, tenant, take=100):
        del tenant, take
        return [
            IncidentInput(
                incident_id="central-related-1",
                title="Prior scan activity",
                rule_id="PORT_SCAN",
                severity="High",
                source_ip="8.8.8.8",
                destination_ip="10.0.0.20",
                first_seen=datetime(2026, 8, 1, tzinfo=timezone.utc),
                last_seen=datetime(2026, 8, 1, 0, 2, tzinfo=timezone.utc),
            )
        ]


@pytest.mark.asyncio
async def test_investigation_calls_only_bounded_read_only_tools(settings, store, brain):
    intel = IntelExchangeStore(settings.database_path)
    intel.publish(
        "tenant-b",
        IntelPublishRequest(
            indicator_type=IndicatorType.IP,
            indicator="8.8.8.8",
            incident_id="tenant-b-hit",
            risk_score=91,
            confidence=0.93,
            approved=True,
            approved_by="soc-b",
            tags=["scanner"],
        ),
    )

    await brain.analyze(
        "tenant-a",
        IncidentInput(
            incident_id="prior-a",
            title="Earlier scan from 8.8.8.8",
            rule_id="PORT_SCAN",
            severity="Medium",
            source_ip="8.8.8.8",
            destination_ip="10.0.0.9",
        ),
    )

    orchestrator = InvestigationOrchestrator(
        brain=brain,
        store=store,
        intel=intel,
        central=FakeCentral(),
        llm=OpenAICompatibleLlm(settings),
        playbooks=PlaybookRetriever(settings.playbook_dir),
    )
    tenant = TenantContext(
        tenant_id="tenant-a",
        name="Tenant A",
        central_url="https://central.invalid:7443",
        central_api_key="operator-key",
        central_verify_tls=False,
        metadata={},
    )
    result = await orchestrator.run(
        tenant,
        InvestigationRequest(
            incident=IncidentInput(
                incident_id="current-a",
                title="Potential port scan from 8.8.8.8",
                rule_id="PORT_SCAN",
                severity="High",
                source_ip="8.8.8.8",
                destination_ip="10.0.0.10",
                suricata_alerts=[
                    {
                        "signature_id": 2001219,
                        "signature": "ET SCAN Potential SSH Scan",
                        "src_ip": "8.8.8.8",
                        "dest_ip": "10.0.0.10",
                        "severity": 2,
                    }
                ],
            ),
            max_steps=4,
            max_runtime_seconds=30,
        ),
    )

    allowed = {"ioc_lookup", "analysis_history", "central_related", "playbook_search", "ntshield_brain_analysis"}
    assert result.read_only is True
    assert result.bounded is True
    assert len(result.trace) <= 5
    assert {item.tool for item in result.trace}.issubset(allowed)
    assert result.related_incident_count == 1
    assert result.prior_analysis_count >= 1
    assert result.intel_reputation[0].seen_by_other_tenants == 1
    assert result.decision.evidence
    serialized = result.model_dump_json()
    assert "tenant-b" not in serialized
