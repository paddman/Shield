"""Poll NT Shield Central and run Brain analysis for each new incident."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from urllib.parse import quote

import httpx


logging.basicConfig(
    level=os.getenv("NTSHIELD_POLLER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s ntshield.brain.poller %(message)s",
)
logger = logging.getLogger("ntshield.brain.poller")


def _tenant() -> dict[str, object]:
    raw = os.environ.get("NTSHIELD_TENANTS_JSON", "[]")
    value = json.loads(raw)
    if isinstance(value, dict):
        value = value.get("tenants", [])
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        raise RuntimeError("NTSHIELD_TENANTS_JSON must contain one tenant object")
    tenant = value[0]
    if not tenant.get("tenant_id") or not tenant.get("api_key"):
        raise RuntimeError("poller requires tenant_id and api_key")
    return tenant


def _state_path() -> Path:
    return Path(
        os.getenv(
            "NTSHIELD_POLLER_STATE_PATH",
            "/var/lib/ntshield/ai/central-poller-state.json",
        )
    )


def _load_state(path: Path) -> set[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    return {str(item) for item in value.get("analyzed_incidents", [])} if isinstance(value, dict) else set()


def _save_state(path: Path, analyzed: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps({"analyzed_incidents": sorted(analyzed)}, separators=(",", ":")),
        encoding="utf-8",
    )
    temporary.replace(path)


async def _poll() -> None:
    tenant = _tenant()
    tenant_id = str(tenant["tenant_id"])
    api_key = str(tenant["api_key"])
    headers = {
        "X-NTShield-Tenant": tenant_id,
        "X-NTShield-Api-Key": api_key,
    }
    base_url = os.getenv("NTSHIELD_BRAIN_URL", "http://127.0.0.1:8088").rstrip("/")
    interval = max(10, int(os.getenv("NTSHIELD_POLLER_INTERVAL_SECONDS", "30")))
    state_path = _state_path()
    analyzed = _load_state(state_path)

    timeout = httpx.Timeout(connect=10.0, read=240.0, write=30.0, pool=10.0)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        while True:
            try:
                # Reconcile with Brain's durable audit DB so a state-file loss
                # does not cause duplicate LLM analyses.
                prior = await client.get(f"{base_url}/v1/analyses?limit=500", headers=headers)
                prior.raise_for_status()
                analyzed.update(
                    str(item.get("incidentId") or item.get("incident_id"))
                    for item in prior.json()
                    if item.get("incidentId") or item.get("incident_id")
                )

                response = await client.get(
                    f"{base_url}/v1/central/incidents?take=500",
                    headers=headers,
                )
                response.raise_for_status()
                incidents = response.json()
                for incident in incidents:
                    incident_id = str(incident.get("incidentId") or incident.get("incident_id") or "")
                    if not incident_id or incident_id in analyzed:
                        continue
                    encoded_id = quote(incident_id, safe="")
                    result = await client.post(
                        f"{base_url}/v1/central/incidents/{encoded_id}/analyze",
                        headers=headers,
                    )
                    if result.is_success:
                        analyzed.add(incident_id)
                        _save_state(state_path, analyzed)
                        logger.info("analyzed incident=%s model=%s", incident_id, result.json().get("model"))
                    else:
                        logger.warning(
                            "analysis failed incident=%s status=%s body=%s",
                            incident_id,
                            result.status_code,
                            result.text[:200],
                        )
                _save_state(state_path, analyzed)
            except Exception as exc:  # keep monitoring after transient failures
                logger.warning("poll cycle failed: %s", str(exc)[:300])
            await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(_poll())
