from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from app.analyst import SentinelBrain
from app.anomaly import HybridAnomalyEngine
from app.audit import AuditStore
from app.config import Settings
from app.evidence import EvidenceNormalizer
from app.llm import OpenAICompatibleLlm
from app.models import NON_DESTRUCTIVE_ACTIONS, IncidentInput
from app.playbooks import PlaybookRetriever


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percent
    lower = int(rank)
    upper = min(len(ordered) - 1, lower + 1)
    fraction = rank - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the NT SHIELD controlled acceptance suite")
    parser.add_argument(
        "--suite",
        default=str(Path(__file__).resolve().parents[1] / "evaluation" / "acceptance-suite.json"),
    )
    parser.add_argument("--out", default="", help="Optional JSON report path")
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Use the configured local Qwen endpoint; default is deterministic fallback for reproducibility",
    )
    return parser.parse_args()


async def run_suite(args: argparse.Namespace) -> dict[str, Any]:
    suite_path = Path(args.suite)
    cases = json.loads(suite_path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("acceptance suite must be a non-empty JSON list")

    with tempfile.TemporaryDirectory(prefix="ntshield-eval-") as temp_dir:
        root = Path(temp_dir)
        settings = Settings(
            environment="test",
            data_dir=root,
            database_path=root / "evaluation.db",
            playbook_dir=Path(__file__).resolve().parents[1] / "playbooks",
            llm_enabled=bool(args.use_llm),
            allow_dev_tenant=True,
            analysis_mode="single" if args.use_llm else "multi_agent",
        )
        store = AuditStore(settings.database_path)
        brain = SentinelBrain(
            settings=settings,
            store=store,
            anomaly_engine=HybridAnomalyEngine(store, settings),
            llm=OpenAICompatibleLlm(settings),
            playbooks=PlaybookRetriever(settings.playbook_dir),
        )
        normalizer = EvidenceNormalizer(settings.max_evidence_items, settings.max_evidence_chars)

        scenario_results: list[dict[str, Any]] = []
        latencies: list[float] = []
        total_returned_refs = 0
        valid_returned_refs = 0
        destructive_without_approval = 0

        for case in cases:
            scenario_id = str(case["scenario_id"])
            incident = IncidentInput.model_validate(case["incident"])
            expected = dict(case.get("expect") or {})
            valid_refs = {item.ref_id for item in normalizer.normalize(incident)}

            started = time.perf_counter()
            decision = await brain.analyze("evaluation", incident)
            latency_ms = (time.perf_counter() - started) * 1000
            latencies.append(latency_ms)

            checks: list[dict[str, Any]] = []

            def check(name: str, passed: bool, actual: Any, requirement: Any) -> None:
                checks.append(
                    {
                        "name": name,
                        "passed": bool(passed),
                        "actual": actual,
                        "requirement": requirement,
                    }
                )

            risk_min = int(expected.get("risk_min", 0))
            risk_max = int(expected.get("risk_max", 100))
            check("risk_range", risk_min <= decision.risk_score <= risk_max, decision.risk_score, [risk_min, risk_max])

            classification_terms = [str(item).lower() for item in expected.get("classification_contains", [])]
            if classification_terms:
                actual = decision.classification.lower()
                check(
                    "classification_contains",
                    all(term in actual for term in classification_terms),
                    decision.classification,
                    classification_terms,
                )

            attack_stages = [str(item) for item in expected.get("attack_chain_contains", [])]
            if attack_stages:
                check(
                    "attack_chain_contains",
                    all(stage in decision.attack_chain for stage in attack_stages),
                    decision.attack_chain,
                    attack_stages,
                )

            forbidden_actions = {str(item) for item in expected.get("forbidden_actions", [])}
            actual_actions = [item.action.value for item in decision.recommended_actions]
            if forbidden_actions:
                check(
                    "forbidden_actions_absent",
                    forbidden_actions.isdisjoint(actual_actions),
                    actual_actions,
                    sorted(forbidden_actions),
                )

            invalid_refs = [item.ref_id for item in decision.evidence if item.ref_id not in valid_refs]
            total_returned_refs += len(decision.evidence)
            valid_returned_refs += len(decision.evidence) - len(invalid_refs)
            check("citation_validity", not invalid_refs, invalid_refs, "all refs must exist in normalized evidence")

            unsafe = [
                item.action.value
                for item in decision.recommended_actions
                if item.action not in NON_DESTRUCTIVE_ACTIONS and not item.requires_human_approval
            ]
            destructive_without_approval += len(unsafe)
            check("human_approval", not unsafe, unsafe, "all destructive actions require approval")

            scenario_results.append(
                {
                    "scenario_id": scenario_id,
                    "description": case.get("description", ""),
                    "passed": all(item["passed"] for item in checks),
                    "latency_ms": round(latency_ms, 2),
                    "risk_score": decision.risk_score,
                    "classification": decision.classification,
                    "attack_chain": decision.attack_chain,
                    "actions": actual_actions,
                    "citation_count": len(decision.evidence),
                    "checks": checks,
                }
            )

        citation_validity = (
            valid_returned_refs / total_returned_refs if total_returned_refs else 1.0
        )
        passed = sum(1 for item in scenario_results if item["passed"])
        report = {
            "suite": str(suite_path),
            "mode": "local_qwen" if args.use_llm else "deterministic_fallback",
            "scenario_count": len(scenario_results),
            "passed": passed,
            "failed": len(scenario_results) - passed,
            "pass_rate": round(passed / len(scenario_results), 4),
            "latency_ms": {
                "mean": round(statistics.fmean(latencies), 2),
                "p50": round(percentile(latencies, 0.50), 2),
                "p95": round(percentile(latencies, 0.95), 2),
                "max": round(max(latencies), 2),
            },
            "citation_validity": round(citation_validity, 4),
            "unsupported_citation_count": total_returned_refs - valid_returned_refs,
            "destructive_without_approval": destructive_without_approval,
            "scenarios": scenario_results,
        }
        return report


async def main() -> int:
    args = parse_args()
    report = await run_suite(args)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
