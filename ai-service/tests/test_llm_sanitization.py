from __future__ import annotations

import pytest

from app.analyst import SentinelBrain
from app.anomaly import HybridAnomalyEngine
from app.llm import LlmResult
from app.models import IncidentInput, ResponseActionType
from app.playbooks import PlaybookRetriever


class FakeLlm:
    configured = True

    async def json_chat(self, system_prompt, user_payload, *, max_tokens=None):
        del system_prompt, user_payload, max_tokens
        return LlmResult(
            data={
                "classification": "AI invented dramatic title",
                "risk_score": 100,
                "confidence": 0.99,
                "summary_th": "วิเคราะห์จากหลักฐานที่ให้มา",
                "attack_chain": ["Reconnaissance", "Invented Tactic"],
                "mitre_techniques": ["T1046", "NOT-A-TECHNIQUE"],
                "evidence": [
                    {"ref_id": "incident:sanitize-1", "reason": "real"},
                    {"ref_id": "invented:999", "reason": "hallucinated"},
                ],
                "recommended_actions": [
                    {
                        "action": "BlockSourceIp",
                        "target": "10.0.0.9",
                        "reason": "contain",
                        "evidence_refs": ["incident:sanitize-1", "invented:999"],
                        "requires_human_approval": False,
                    },
                    {"action": "RunArbitraryShell", "reason": "bad idea"},
                ],
            },
            model="fake-qwen",
            prompt_tokens=10,
            completion_tokens=20,
            latency_ms=1,
        )


@pytest.mark.asyncio
async def test_llm_cannot_invent_evidence_or_auto_approve_destructive_action(settings, store):
    settings.analysis_mode = "single"
    brain = SentinelBrain(
        settings=settings,
        store=store,
        anomaly_engine=HybridAnomalyEngine(store, settings),
        llm=FakeLlm(),
        playbooks=PlaybookRetriever(settings.playbook_dir),
    )
    decision = await brain.analyze(
        "tenant-a",
        IncidentInput(
            incident_id="sanitize-1",
            title="Potential port scan",
            severity="Medium",
            source_ip="10.0.0.9",
            destination_ip="10.0.0.10",
        ),
    )

    assert {citation.ref_id for citation in decision.evidence} == {"incident:sanitize-1"}
    assert decision.risk_score < 100  # bounded around deterministic score
    assert decision.attack_chain == ["Reconnaissance"]
    assert decision.mitre_techniques == ["T1046"]
    assert len(decision.recommended_actions) == 1
    action = decision.recommended_actions[0]
    assert action.action == ResponseActionType.BLOCK_SOURCE_IP
    assert action.requires_human_approval is True
    assert action.evidence_refs == ["incident:sanitize-1"]
