from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType


def _load_script(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


central_poller = _load_script("central_poller")
run_brain = _load_script("run_brain")


def test_poller_state_path_has_no_developer_home_dependency(monkeypatch) -> None:
    monkeypatch.delenv("NTSHIELD_POLLER_STATE_PATH", raising=False)
    assert central_poller._state_path() == Path("/var/lib/ntshield/ai/central-poller-state.json")


def test_poller_state_path_can_be_overridden(monkeypatch, tmp_path: Path) -> None:
    configured = tmp_path / "poller-state.json"
    monkeypatch.setenv("NTSHIELD_POLLER_STATE_PATH", str(configured))
    assert central_poller._state_path() == configured


def test_dotenv_loader_allows_missing_file_and_parses_values(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing.env"
    run_brain.load_dotenv(missing)

    dotenv = tmp_path / ".env"
    dotenv.write_text('NTSHIELD_TEST_VALUE="safe value"\n', encoding="utf-8")
    monkeypatch.delenv("NTSHIELD_TEST_VALUE", raising=False)
    run_brain.load_dotenv(dotenv)

    assert os.environ["NTSHIELD_TEST_VALUE"] == "safe value"
