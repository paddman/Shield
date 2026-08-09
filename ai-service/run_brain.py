"""Run the Brain with dotenv-compatible parsing and a stable process boundary."""

from __future__ import annotations

import ast
import os
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            try:
                value = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                pass
        # Values supplied by systemd/containers are the deployment authority.
        # The local dotenv file only fills settings that the process does not
        # already have.
        os.environ.setdefault(key.strip(), value)


def main() -> None:
    root = Path(__file__).resolve().parent
    load_dotenv(root / ".env")
    uvicorn = root / ".venv" / "bin" / "uvicorn"
    os.execvpe(
        str(uvicorn),
        ["uvicorn", "app.main_v2:app", "--host", "127.0.0.1", "--port", "8088"],
        os.environ,
    )


if __name__ == "__main__":
    main()
